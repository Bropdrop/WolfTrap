"""GeoTrace v2 offline advisory contract. No dispatch, transport or credential interface."""
from collections import defaultdict
from datetime import date
import hashlib
import json

from . import _geotrace_v1 as v1

INPUT = "wolftrap.geotrace-input/v2"
POLICY = "wolftrap.geotrace-policy/v2"
REPORT = "wolftrap.geotrace-report/v2"
DIMENSIONS = {"provider_origin", "network_egress", "destination_hop", "execution_region",
              "processing_jurisdiction", "intermediary"}
CONTEXT = {"execution_region", "processing_jurisdiction", "intermediary"}


def require(value):
    if not value:
        raise ValueError("unsupported GeoTrace input")


def fields(obj, names):
    require(isinstance(obj, dict) and set(obj) == set(names))


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parse(raw):
    def pairs(items):
        obj = dict(items)
        require(len(obj) == len(items))
        return obj

    def invalid(_):
        raise ValueError("invalid JSON constant")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)


def country(value):
    require(isinstance(value, str) and value.isascii() and len(value) == 2)
    return v1.valid_country(value.upper(), "country")


def day(value):
    return date.fromisoformat(v1.valid_date(value, "date"))


def observation(codes, basis):
    unique = sorted(set(codes))
    return {"state": "CONFLICTING" if len(unique) > 1 else "CLAIMED" if unique else "UNKNOWN",
            "countries": unique, "basis": basis}


def evaluate(source, policy, as_of):
    now = day(as_of)
    fields(policy, ("schema", "task", "workload", "allowed", "max_age_days", "valid_from", "valid_until"))
    require(policy["schema"] == POLICY and day(policy["valid_from"]) <= now <= day(policy["valid_until"]))
    v1.valid_id(policy["task"], "task")
    v1.valid_id(policy["workload"], "workload")
    age = policy["max_age_days"]
    require(type(age) is int and 0 <= age <= 366)
    allow = policy["allowed"]
    require(isinstance(allow, dict) and allow and set(allow) <= DIMENSIONS)
    allowed = {}
    for dimension, values in allow.items():
        require(isinstance(values, list) and 0 < len(values) <= 249)
        allowed[dimension] = {country(v) for v in values}
        require(len(values) == len(allowed[dimension]))

    if source.get("schema") == v1.INPUT_SCHEMA:
        capture, context = source, []
        require(policy["task"] == "v1-import" and policy["workload"] == "unknown")
    else:
        fields(source, ("schema", "task", "workload", "capture", "observations"))
        require(source["schema"] == INPUT and source["task"] == policy["task"]
                and source["workload"] == policy["workload"])
        capture, context = source["capture"], source["observations"]
    require(isinstance(capture, dict) and day(capture["snapshot_date"]) == now)
    require(isinstance(context, list) and len(context) <= 512)
    # Validate the legacy schema. Its embedded policy is candidate data and never controls v2.
    require(isinstance(capture.get("providers"), list) and
            sum(len(p["domains"]) for p in capture["providers"]) <= 512)
    legacy = v1.analyze(capture)
    events = {e["id"]: digest(v1.canonical(e)) for e in capture["events"]}
    claims = defaultdict(list)
    seen = set()
    references = defaultdict(list)
    for index, item in enumerate(context):
        fields(item, ("event", "event_sha256", "kind", "hop", "country", "source", "observed_on", "valid_until"))
        kind, hop = item["kind"], item["hop"]
        require(kind in CONTEXT and item["event"] in events and events[item["event"]] == item["event_sha256"])
        require(type(hop) is int and (1 <= hop <= 32 if kind == "intermediary" else hop == 0))
        origin = v1.valid_id(item["source"], "source")
        key = (item["event"], kind, hop)
        require((*key, origin) not in seen)
        seen.add((*key, origin))
        start, end = day(item["observed_on"]), day(item["valid_until"])
        require(start <= end)
        value = country(item["country"])
        # Keep even a stale hop present as UNKNOWN.
        current = claims[key]
        usable = start <= now <= end and (now - start).days <= age
        references[key].append({"observation_index":index, "current":usable})
        if usable:
            current.append(value)

    rows = []
    for index, event in enumerate(legacy["events"]):
        event_id = event["event_id"]
        geo = {}
        for dim, old in (("provider_origin","provider_origin"), ("network_egress","source_egress"),
                         ("destination_hop","destination_hop")):
            point = event[old]
            fresh = point["country"] and (now - day(point["verified_on"])).days <= age
            geo[dim] = observation([point["country"]] if fresh else [], point["basis"])
            geo[dim]["observed_on"] = point["verified_on"]
        for dim in ("execution_region", "processing_jurisdiction"):
            key = (event_id, dim, 0)
            geo[dim] = observation(claims.get(key, []), "EXPLICIT_CAPTURE_CLAIM")
            geo[dim]["sources"] = references.get(key, [])
        hops = [{"hop": hop, "sources": references[(eid, kind, hop)], **observation(values, "EXPLICIT_CAPTURE_CLAIM")}
                for (eid, kind, hop), values in sorted(claims.items())
                if eid == event_id and kind == "intermediary"]
        results = {}
        for dim, accepted in allowed.items():
            points = hops if dim == "intermediary" else [geo[dim]]
            gaps = dim == "intermediary" and [p["hop"] for p in hops] != list(range(1, len(hops) + 1))
            if gaps or not points or any(p["state"] != "CLAIMED" for p in points):
                results[dim] = "INCONCLUSIVE"
            elif any(p["countries"][0] not in accepted for p in points):
                results[dim] = "REVIEW_REQUIRED"
            else:
                results[dim] = "NO_PATTERN_MATCH"
        rows.append({"event_index": index, "geography": geo, "intermediaries": hops,
                     "route_completeness":"UNVERIFIED", "source_role":event["source_role"], "destination_role":event["destination_role"],
                     "policy_results": results})
    outcomes = {v for row in rows for v in row["policy_results"].values()}
    status = ("INCONCLUSIVE" if not rows or "INCONCLUSIVE" in outcomes else
              "REVIEW_REQUIRED" if "REVIEW_REQUIRED" in outcomes else "NO_PATTERN_MATCH")
    return {"schema": REPORT, "as_of": as_of, "events":rows, "outcome":status,
            "confidence":"STATIC_REVIEW_SIGNAL", "operator_identity":"UNVERIFIED",
            "workload_identity":"UNVERIFIED", "action_authorization":"NOT_EVALUATED",
            "protected_effects_committed":0}

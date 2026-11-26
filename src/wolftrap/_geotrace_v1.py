# In-memory analysis from the preserved R01 source; legacy filesystem entry points excluded.
"""WolfTrap API GeoTrace v1: read-only, offline country attribution for API metadata.

Does not query remote services, sniff packets or infer geography from domain TLDs.
Provider nationality, source-egress IP geography, and destination-hop IP geography
are separate fields. No field alone establishes a malicious API call.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import date
from typing import Any

INPUT_SCHEMA = "wolftrap.api-geotrace-input/v1"
OUTPUT_SCHEMA = "wolftrap.api-geotrace-report/v1"
MAX_SOURCE_BYTES = 262_144
MAX_EVENTS = 256
MAX_RANGES = 4096
MAX_PROVIDERS = 256
EVENT_KEYS = frozenset({
    "id", "source_ip", "destination_ip", "tls_sni", "http_host", "dns_qname",
    "destination_role", "source_role",
})
PROVIDER_KEYS = frozenset({"id", "name", "origin_country", "domains", "evidence_ref", "verified_on"})
RANGE_KEYS = frozenset({"network", "country", "evidence_ref", "verified_on", "valid_until"})
POLICY_KEYS = frozenset({"allowed_provider_countries", "allowed_source_countries", "allowed_destination_countries", "review_unknowns"})
TOP_KEYS = frozenset({"schema", "snapshot_date", "synthetic", "providers", "geo_ranges", "events", "policy"})
SOURCE_ROLES = frozenset({"client_egress", "server_egress", "vpn_egress", "proxy_egress", "unknown"})
DEST_ROLES = frozenset({"api_endpoint", "proxy_hop", "gateway_hop", "unknown"})
ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,63}$")
COUNTRY_RE = re.compile(r"^[A-Z]{2}$")
# Snapshot of ISO 3166-1 alpha-2 codes; no network / runtime country library.
ISO_COUNTRIES = frozenset(
    """AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW""".split()
)
HOST_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")


class GeoTraceError(ValueError):
    """Fail closed on malformed or ambiguous input, never silently assert a country."""


def require(condition: bool, explanation: str) -> None:
    if not condition:
        raise GeoTraceError(explanation)


def keys(value: Any, expected: frozenset[str], required: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label}: expected object")
    unexpected = set(value) - expected
    require(not unexpected, f"{label}: unsupported fields {sorted(unexpected)} (no headers, bodies or credentials accepted)")
    require(required <= set(value), f"{label}: missing {sorted(required - set(value))}")
    return value


def valid_date(value: Any, label: str) -> str:
    require(isinstance(value, str), f"{label}: expected YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise GeoTraceError(f"{label}: invalid YYYY-MM-DD") from exc
    require(parsed.isoformat() == value, f"{label}: noncanonical date")
    return value


def valid_country(value: Any, label: str) -> str:
    require(isinstance(value, str) and COUNTRY_RE.fullmatch(value) is not None,
            f"{label}: expected ISO 3166-1 alpha-2 uppercase country code")
    require(value in ISO_COUNTRIES, f"{label}: unrecognized country code")
    return value


def valid_id(value: Any, label: str) -> str:
    require(isinstance(value, str) and ID_RE.fullmatch(value) is not None, f"{label}: bad ID")
    return value


def valid_ref(value: Any, label: str) -> str:
    # Evidence reference is an offline catalogue handle, not a URL to be fetched.
    require(isinstance(value, str) and 3 <= len(value) <= 200 and "\n" not in value and "\r" not in value,
            f"{label}: evidence reference must be a short printable string")
    return value


def hostname(value: Any, label: str) -> str | None:
    if value is None:
        return None
    require(isinstance(value, str), f"{label}: expected hostname or null")
    normalized = value.lower().removesuffix(".")
    require(len(normalized) <= 253 and HOST_RE.fullmatch(normalized) is not None,
            f"{label}: invalid hostname (URLs, paths and userinfo not accepted)")
    return normalized


def ip_addr(value: Any, label: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    require(isinstance(value, str) and len(value) <= 45, f"{label}: expected IP address")
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:
        raise GeoTraceError(f"{label}: invalid IP address") from exc


def alias(raw: str) -> str:
    # A stable, unsalted digest identifies an event's IP for evidence correlation,
    # but should not be mistaken for anonymization of a low-entropy address.
    return "sha256:" + hashlib.sha256(raw.encode("ascii")).hexdigest()


def canonical(document: Any) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode()


def country_evidence(code: str | None, method: str, evidence: str | None = None,
                     verified_on: str | None = None) -> dict[str, Any]:
    return {"country": code, "basis": method, "evidence_ref": evidence, "verified_on": verified_on}


def domain_match(host: str, registered: str) -> bool:
    """Label-bound suffixes only: foo.example.test.evil.test must not match example.test."""
    return host == registered or host.endswith("." + registered)


def _country_rule(country: Any, policy: dict[str, Any], field: str) -> bool:
    choices = policy.get(field)
    return country is not None and choices is not None and country not in choices


def _validate(document: Any) -> tuple[dict[str, Any], list[dict[str, Any]],
                                     list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    data = keys(document, TOP_KEYS, {"schema", "snapshot_date", "synthetic", "providers", "geo_ranges", "events"}, "input")
    require(data["schema"] == INPUT_SCHEMA, "unrecognized input schema")
    snapshot = valid_date(data["snapshot_date"], "snapshot_date")
    require(type(data["synthetic"]) is bool, "synthetic: expected boolean")

    providers = data["providers"]
    require(isinstance(providers, list) and len(providers) <= MAX_PROVIDERS, "providers: invalid list or size")
    occupied: set[str] = set()
    provider_ids: set[str] = set()
    normalized_providers = []
    for i, raw in enumerate(providers):
        p = keys(raw, PROVIDER_KEYS, set(PROVIDER_KEYS), f"providers[{i}]")
        pid = valid_id(p["id"], f"providers[{i}].id")
        require(pid not in provider_ids, "duplicate provider ID")
        provider_ids.add(pid)
        require(isinstance(p["name"], str) and 1 <= len(p["name"]) <= 120,
                f"providers[{i}].name must be short")
        origin = valid_country(p["origin_country"], f"providers[{i}].origin_country")
        ref = valid_ref(p["evidence_ref"], f"providers[{i}].evidence_ref")
        verified = valid_date(p["verified_on"], f"providers[{i}].verified_on")
        require(verified <= snapshot, "provider evidence is newer than snapshot")
        require(isinstance(p["domains"], list) and 1 <= len(p["domains"]) <= 50,
                f"providers[{i}].domains invalid")
        doms = []
        for dom in p["domains"]:
            d = hostname(dom, f"providers[{i}].domains")
            require(d is not None and d not in occupied, f"ambiguous or duplicate provider domain: {d}")
            occupied.add(d)
            doms.append(d)
        normalized_providers.append({"id": pid, "name": p["name"], "origin_country": origin,
                                     "domains": doms, "evidence_ref": ref, "verified_on": verified})
    # A subdomain from one provider that overlaps another must not silently pick one.
    for i, p in enumerate(normalized_providers):
        for other in normalized_providers[i + 1:]:
            for a in p["domains"]:
                for b in other["domains"]:
                    require(not (domain_match(a, b) or domain_match(b, a)),
                            "overlapping domain ownership across providers")

    raw_ranges = data["geo_ranges"]
    require(isinstance(raw_ranges, list) and len(raw_ranges) <= MAX_RANGES, "geo_ranges: invalid list or size")
    seen_networks: set[str] = set()
    ranges = []
    for i, raw in enumerate(raw_ranges):
        g = keys(raw, RANGE_KEYS, {"network", "country", "evidence_ref", "verified_on"}, f"geo_ranges[{i}]")
        require(isinstance(g["network"], str) and len(g["network"]) <= 50,
                "geo_ranges.network must be CIDR")
        try:
            net = ipaddress.ip_network(g["network"], strict=True)
        except ValueError as exc:
            raise GeoTraceError(f"geo_ranges[{i}]: invalid canonical CIDR") from exc
        require(str(net) not in seen_networks, "duplicate CIDR across geo records")
        seen_networks.add(str(net))
        country = valid_country(g["country"], f"geo_ranges[{i}].country")
        ref = valid_ref(g["evidence_ref"], f"geo_ranges[{i}].evidence_ref")
        verified = valid_date(g["verified_on"], f"geo_ranges[{i}].verified_on")
        until = valid_date(g["valid_until"], f"geo_ranges[{i}].valid_until") if g.get("valid_until") is not None else None
        require(verified <= snapshot, "geo evidence is newer than snapshot")
        require(until is None or verified <= until, "geo validity ends before verification")
        ranges.append({"net": net, "country": country, "evidence_ref": ref,
                       "verified_on": verified, "valid_until": until})

    events = data["events"]
    require(isinstance(events, list) and len(events) <= MAX_EVENTS, "events: invalid list or size")
    ids: set[str] = set()
    normalized_events = []
    for i, raw in enumerate(events):
        e = keys(raw, EVENT_KEYS, {"id", "source_ip", "destination_ip"}, f"events[{i}]")
        event_id = valid_id(e["id"], f"events[{i}].id")
        require(event_id not in ids, "duplicate event ID")
        ids.add(event_id)
        src, dst = ip_addr(e["source_ip"], f"events[{i}].source_ip"), ip_addr(e["destination_ip"], f"events[{i}].destination_ip")
        role_s = e.get("source_role", "unknown")
        role_d = e.get("destination_role", "unknown")
        require(role_s in SOURCE_ROLES, f"events[{i}].source_role unknown")
        require(role_d in DEST_ROLES, f"events[{i}].destination_role unknown")
        normalized_events.append({"id": event_id, "src": src, "dst": dst,
                                  "tls_sni": hostname(e.get("tls_sni"), f"events[{i}].tls_sni"),
                                  "http_host": hostname(e.get("http_host"), f"events[{i}].http_host"),
                                  "dns_qname": hostname(e.get("dns_qname"), f"events[{i}].dns_qname"),
                                  "source_role": role_s, "destination_role": role_d})

    policy = keys(data.get("policy", {}), POLICY_KEYS, set(), "policy")
    normalized_policy = {}
    for k in ("allowed_provider_countries", "allowed_source_countries", "allowed_destination_countries"):
        if k not in policy:
            normalized_policy[k] = None
        else:
            v = policy[k]
            require(isinstance(v, list) and bool(v), f"policy.{k}: expected nonempty list")
            countries = [valid_country(c, f"policy.{k}") for c in v]
            require(len(countries) == len(set(countries)), f"policy.{k}: duplicate country")
            normalized_policy[k] = countries
    require(type(policy.get("review_unknowns", True)) is bool, "policy.review_unknowns must be boolean")
    normalized_policy["review_unknowns"] = policy.get("review_unknowns", True)
    return data, normalized_providers, ranges, normalized_events, normalized_policy


def _match_geo(ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
               ranges: list[dict[str, Any]], as_of: str, synthetic: bool) -> dict[str, Any]:
    if not synthetic and not ip.is_global:
        return country_evidence(None, "NON_GLOBAL_ADDRESS_NOT_GEOLOCATABLE")
    applicable = [r for r in ranges if ip in r["net"] and (r["valid_until"] is None or r["valid_until"] >= as_of)]
    if not applicable:
        return country_evidence(None, "NO_CURRENT_GEO_EVIDENCE")
    best = max(applicable, key=lambda r: r["net"].prefixlen)
    return country_evidence(best["country"], "OFFLINE_IP_GEO_ESTIMATE",
                            best["evidence_ref"], best["verified_on"])


def _match_provider(host: str | None, providers: list[dict[str, Any]]) -> dict[str, Any] | None:
    if host is None:
        return None
    for p in providers:
        if any(domain_match(host, d) for d in p["domains"]):
            return p
    return None


def analyze(document: Any) -> dict[str, Any]:
    data, providers, ranges, events, policy = _validate(document)
    findings = []
    reviews = 0
    attributed = 0
    for event in events:
        flags = []
        sni, host, dns = event["tls_sni"], event["http_host"], event["dns_qname"]
        if sni and host and sni != host:
            flags.append("HOST_SNI_CONFLICT")
            candidate = None
            observation = "CONFLICTING_NETWORK_HOSTS"
        elif sni or host:
            candidate = sni or host
            observation = "OBSERVED_TLS_SNI_OR_HTTP_HOST"
        else:
            candidate = None
            observation = "DNS_HINT_ONLY" if dns else "NO_HOST_OBSERVATION"
            flags.append(observation)
        match = _match_provider(candidate, providers)
        if match is None and candidate is not None:
            flags.append("UNATTRIBUTED_PROVIDER")
        if match is not None:
            attributed += 1
        provider_country = country_evidence(
            match["origin_country"] if match else None,
            "PROVIDER_REGISTRY_CLAIM" if match else "UNKNOWN_PROVIDER",
            match["evidence_ref"] if match else None,
            match["verified_on"] if match else None,
        )
        src_geo = _match_geo(event["src"], ranges, data["snapshot_date"], data["synthetic"])
        dst_geo = _match_geo(event["dst"], ranges, data["snapshot_date"], data["synthetic"])
        if src_geo["country"] is None:
            flags.append("UNKNOWN_SOURCE_EGRESS_COUNTRY")
        if dst_geo["country"] is None:
            flags.append("UNKNOWN_DESTINATION_HOP_COUNTRY")
        if event["source_role"] in ("vpn_egress", "proxy_egress"):
            flags.append("SOURCE_IS_INTERMEDIARY_NOT_CLIENT_ORIGIN")
        if event["destination_role"] in ("proxy_hop", "gateway_hop"):
            flags.append("DESTINATION_IS_INTERMEDIARY_NOT_FINAL_API_REGION")
        if event["destination_role"] == "unknown":
            flags.append("DESTINATION_ROLE_UNVERIFIED")
        if event["source_role"] == "unknown":
            flags.append("SOURCE_ROLE_UNVERIFIED")
        if _country_rule(provider_country["country"], policy, "allowed_provider_countries"):
            flags.append("PROVIDER_COUNTRY_OUTSIDE_POLICY")
        if _country_rule(src_geo["country"], policy, "allowed_source_countries"):
            flags.append("SOURCE_EGRESS_COUNTRY_OUTSIDE_POLICY")
        if _country_rule(dst_geo["country"], policy, "allowed_destination_countries"):
            flags.append("DESTINATION_HOP_COUNTRY_OUTSIDE_POLICY")
        # Missing evidence must never be treated as an allowlisted pass.
        unknown = any(x in flags for x in (
            "UNKNOWN_SOURCE_EGRESS_COUNTRY", "UNKNOWN_DESTINATION_HOP_COUNTRY",
            "UNATTRIBUTED_PROVIDER", "DNS_HINT_ONLY", "NO_HOST_OBSERVATION", "HOST_SNI_CONFLICT"))
        review = (any(x.endswith("_OUTSIDE_POLICY") for x in flags)
                  or (policy["review_unknowns"] and unknown))
        reviews += int(review)
        findings.append({
            "event_id": event["id"],
            "source_ip_digest": alias(str(event["src"])),
            "destination_ip_digest": alias(str(event["dst"])),
            "hostname_digest": alias(candidate) if candidate is not None else None,
            "host_observation": observation,
            "provider_id": match["id"] if match else None,
            "provider_name": match["name"] if match else None,
            "provider_origin": provider_country,
            "source_egress": src_geo,
            "destination_hop": dst_geo,
            "source_role": event["source_role"],
            "destination_role": event["destination_role"],
            "processing_country": country_evidence(None, "NOT_OBSERVED"),
            "network_path_countries": None,
            "flags": sorted(set(flags)),
            "policy_status": "REVIEW_REQUIRED" if review else "ADVISORY_ONLY",
            "malicious_attribution": False,
        })
    return {
        "schema": OUTPUT_SCHEMA,
        "source_sha256": "sha256:" + hashlib.sha256(canonical(document)).hexdigest(),
        "snapshot_date": data["snapshot_date"],
        "synthetic_input": data["synthetic"],
        "network_contacted": False,
        "scope": "OFFLINE_METADATA_ONLY",
        "qualification": "NOT_A_SECURITY_CERTIFICATION",
        "summary": {"events": len(findings), "provider_attributed": attributed,
                    "review_required": reviews, "unknown_providers": len(findings) - attributed},
        "events": findings,
    }

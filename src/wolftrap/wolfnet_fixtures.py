"""Public, reproducible test publishers. Their signing seeds are intentionally public."""

from __future__ import annotations

import ctypes
import hashlib
import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from .cursorial_corpus import fixture as schedule
from .cursorial_lab import execute
from .wolfprint_challenge import trace_fixture
from .wolfprint_fixtures import anchor_trace, fixture as workload
from .wolfprint_reference import frame as wp_hash, operation
from .wolfnet_crypto import sodium

ROLES = {1: "distributor", 2: "publisher", 3: "reviewer", 4: "reviewer", 5: "observer", 6: "publisher", 7: "reviewer"}
ORIGIN = datetime(2030, 1, 1, tzinfo=timezone.utc)


def stamp(tick):
    return (ORIGIN + timedelta(seconds=tick)).strftime("%Y-%m-%dT%H:%M:%SZ")


def wire(label, obj):
    return ("wolftrap.wolfnet/v1\x00" + label + "\x00" + json.dumps(obj, sort_keys=True, ensure_ascii=True,
            separators=(",", ":"), allow_nan=False)).encode("ascii")


def ref_hash(label, obj):
    return hashlib.sha256(wire(label, obj)).hexdigest()


@lru_cache(maxsize=32)
def _fictional_pair(signer, revision):
    if signer not in ROLES or revision not in (1, 2):
        raise ValueError("unknown public fixture key")
    seed = hashlib.sha256(f"PUBLIC WOLFNET FICTIONAL TEST SEED {signer}/{revision}".encode("ascii")).digest()
    pk, sk = ctypes.create_string_buffer(32), ctypes.create_string_buffer(64)
    if sodium().crypto_sign_ed25519_seed_keypair(pk, sk, seed) != 0:
        raise ValueError("fixture key generation failed")
    return pk.raw, sk.raw


def sign(role, signer, body, revision=1):
    message = wire("signature/" + role, {"body": body, "alg": "Ed25519", "key_revision": revision, "signer": signer})
    signature = ctypes.create_string_buffer(64)
    if sodium().crypto_sign_ed25519_detached(signature, None, message, len(message), _fictional_pair(signer, revision)[1]) != 0:
        raise ValueError("fixture signing failed")
    return {"signer": signer, "key_revision": revision, "alg": "Ed25519", "signature": signature.raw.hex()}


def public_key(signer, revision=1):
    return {"signer": signer, "org": signer, "role": ROLES[signer], "revision": revision, "predecessor": revision - 1,
            "public_key": _fictional_pair(signer, revision)[0].hex(), "since": stamp(0 if revision == 1 else 25),
            "expires": stamp(600), "revoked_at": None}


def publication(record, reviewers=(3, 4), signer=None, revision=1):
    author = record["publisher"] if signer is None else signer
    return {"record": deepcopy(record), "author": sign(ROLES[author], author, record, revision),
            "approvals": [sign("reviewer", reviewer, record) for reviewer in reviewers]}


def append_frame(data, entries, tick, key=1):
    history = data["feed"]["history"]
    scope = data["trust"]["subscription"]
    previous = ref_hash("frame", history[-1]) if history else ref_hash("genesis", scope)
    body = {"schema": "wolftrap.wolfnet-snapshot/v1", "subscription": scope, "sequence": len(history) + 1,
            "previous": previous, "published_at": stamp(tick), "expires_at": stamp(tick + 100), "entries": entries}
    history.append({"body": body, "seal": sign("distributor", 1, body, key)})


def checkpoint(data, sequence, at):
    frames = data["feed"]["history"]
    old = data["checkpoint"]
    return {**old, "sequence": sequence, "head": ref_hash("frame", frames[sequence - 1]) if sequence else old["head"],
            "trust_sha256": ref_hash("subscriber-trust", data["trust"]), "accepted_at": stamp(at)}


def update(data, status, *, reviewers=(3, 4), signer=None, key=1, **changes):
    history = data["feed"]["history"]
    old = history[-1]["body"]["entries"][0]["record"]
    tick = 31 + 2 * len(history)
    back = ref_hash("advisory", old)
    record = {**deepcopy(old), "revision": old["revision"] + 1, "status": status, "updated_at": stamp(tick),
              "supersedes": back if status != "WITHDRAWN" else None, "withdraws": back if status == "WITHDRAWN" else None,
              **changes}
    append_frame(data, [publication(record, reviewers, signer, key)], tick + 1)


def basic(profile=1, kind="high"):
    manifest, request, reg, _ = workload(profile)
    if kind == "high":
        incident_registry = deepcopy(reg)
        incident_registry["grants"] = []
        chain = execute(schedule(profile, "unregistered"), "effect-on-deny")
        trace = anchor_trace(chain, request["claim"], incident_registry)
    else:
        _, _, incident_registry, trace = trace_fixture(profile, "revocation-observed-denial" if kind == "moderate" else "complete")
    s = request["claim"]
    coords = {k: s[k] for k in ("issuer", "trust_domain", "tenant")}
    subscription = {**coords, "realm": 71, "stream": 1}
    principal = wp_hash("principal", {**coords, "principal": s["principal"]})
    subject = {**coords, "principal_id": principal, "instance_id": wp_hash("instance", s),
               "architecture_sha256": s["architecture_sha256"], "key_revision": s["key_revision"]}
    category, level, classification = ("unauthorized-effect", 3, "SYNTHETICALLY VERIFIED")
    if kind == "moderate":
        category, level = "rejected-request", 2
    elif kind == "static":
        category, level, classification = "metadata-indicator", 1, "STATIC REVIEW SIGNAL"
    op = operation(request["operation"])
    anchor = incident_registry["bindings"][-1]
    # The blocked-attempt fixture intentionally leaves a larger time window between gates.
    issued = max(30, anchor["at"] + 1)
    witness = {"schema": "wolftrap.wolfnet-observation/v1", "subscription": subscription,
               "incident_ref": ref_hash("fictional-incident", [profile, 1]), "provenance_ref": ref_hash("fixture-source", [profile]),
               "subject": subject, "category": category, "operation_sha256": op, "resource_scope": request["operation"]["resource"],
               "observed_at": stamp(anchor["at"]), "expires_at": stamp(120), "classification": classification,
               "trace_sha256": None if kind == "static" else anchor["trace_sha256"], "binding": None if kind == "static" else anchor["binding"]}
    record = {"schema": "wolftrap.wolfnet-advisory/v1", "subscription": subscription, "publisher": 2, "serial": 1,
              "advisory_id": "WN-" + ref_hash("advisory-id", [subscription, 2, 1]), "revision": 1,
              "created_at": stamp(issued), "updated_at": stamp(issued), "expires_at": stamp(115),
              "status": "ACTIVE", "supersedes": None, "withdraws": None, "subject": deepcopy(subject), "severity": level,
              "confidence": "HIGH", "identity_assurance": "DECLARED" if kind == "static" else "FIXTURE_ISSUER_BOUND",
              "evidence_class": classification, "evidence_sha256": ref_hash("observation", witness),
              "recommendation": "DENY" if level == 3 else ("READ_ONLY" if level == 2 else "MONITOR"),
              "distribution": "FICTIONAL_REDACTED", "sharing_consent": True, "review_ref": 7, "appeal_ref": 11}
    for k in ("incident_ref", "provenance_ref", "category", "operation_sha256", "resource_scope"):
        record[k] = witness[k]
    trust = {"schema": "wolftrap.wolfnet-trust/v1", "subscription": subscription, "revision": 1, "since": stamp(0),
             "expires": stamp(600), "clock_origin": stamp(0), "keys": [public_key(i) for i in ROLES]}
    local = {"schema": "wolftrap.wolfnet-policy/v1", "subscription": subscription, "revision": 1,
             "since": stamp(0), "expires": stamp(125), "publishers": [2, 6], "min_severity": 2,
             "min_confidence": "MEDIUM", "min_reviewers": 2, "actions": ["ALLOW", "MONITOR", "READ_ONLY", "DENY", "DENY"],
             "appeal_holds": []}
    data = {"trust": trust, "checkpoint": {"schema": "wolftrap.wolfnet-checkpoint/v1", "subscription": subscription,
            "trust_revision": 1, "sequence": 0, "head": ref_hash("genesis", subscription), "accepted_at": stamp(0)},
            "feed": {"schema": "wolftrap.wolfnet-feed/v1", "history": []}, "at": stamp(60), "accepted": False,
            "witnesses": {"schema": "wolftrap.wolfnet-witnesses/v1", "witnesses": [{"body": witness, "seal": sign("observer", 5, witness)}]},
            "traces": [] if kind == "static" else [trace], "witness_registry": None if kind == "static" else incident_registry,
            "manifest": manifest, "request": request, "registry": reg, "policy": local}
    append_frame(data, [publication(record)], issued + 1)
    return data

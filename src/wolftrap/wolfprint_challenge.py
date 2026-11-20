"""Reproducible, finite differential tests against authored expectations."""

from __future__ import annotations

import json
from collections import Counter
from copy import deepcopy

from . import wolfprint_reference as ref
from .cursorial_corpus import fixture as cursorial_fixture, vary
from .cursorial_lab import execute
from .cursorial_trace import Gap, decode_json
from .wolfprint import fingerprint
from .wolfprint_fixtures import anchor_trace, fixture
from .wolfprint_identity import inspect
from .wolfprint_trace import inspect_chain


def _outcome(result):
    p = result["policy_proposal"]
    return (result["identity"]["status"], tuple(result["classification"]), p["action"], p["current_scoped_grant"])


def _mutate(control, original, inputs):
    """Deliberately defective alternates. Only the fictional qualification calls these."""
    manifest, request, registry, at = deepcopy(inputs)
    status, labels, action, grant = _outcome(original)
    claim = request["claim"]
    if control == "always-allow":
        return status, labels, "ALLOW", True
    if control == "always-deny":
        return status, labels, "DENY", False
    if control == "trust-claim" and claim:
        return ref.OK, labels, action, grant
    if control == "build-is-subject" and registry and registry["baseline"]:
        if ref.architecture(manifest) == registry["baseline"]["architecture_sha256"]:
            return ref.OK, ref.KNOWN, action, grant
    if control == "rotation-is-substitution" and "VERIFIED_KEY_ROTATION" in labels:
        return ref.FAKE, (ref.FAKE,), "REAUTHENTICATE", False
    if control == "all-changes-quarantine" and "CHANGED_ARCHITECTURE" in labels:
        return status, labels, "QUARANTINE", grant
    if control == "trust-sign-in-as-grant" and status == ref.OK:
        return status, labels, "ALLOW", True
    if registry is None or claim is None:
        return _outcome(original)
    if control == "accept-replayed-presentations" and registry["used_nonces"]:
        registry["used_nonces"] = []
    elif control == "ignore-revocation" and any(g["revoked_at"] is not None for g in registry["grants"]):
        for g in registry["grants"]:
            g["revoked_at"] = None
    elif control == "ignore-issuer" and claim["issuer"] != registry["issuer"]:
        claim["issuer"] = registry["issuer"]
    elif control == "architecture-wide-restriction" and status == ref.OK and registry["restrictions"]:
        for rule in registry["restrictions"]:
            rule["principal"] = claim["principal"]
    else:
        return _outcome(original)
    return _outcome(inspect(manifest, request, registry, at))


MUTANTS = ("always-allow", "always-deny", "trust-claim", "build-is-subject", "rotation-is-substitution",
           "all-changes-quarantine", "trust-sign-in-as-grant", "accept-replayed-presentations",
           "ignore-revocation", "ignore-issuer", "architecture-wide-restriction")

TRACE_EXPECT = {
    "complete": ("SYNTHETICALLY VERIFIED", "issuer-host-and-ledger-witnesses-agree", 1),
    "missing-witness": ("INCONCLUSIVE", "missing-extra-or-contradictory-identity-witness", None),
    "duplicate-witness": ("INCONCLUSIVE", "missing-extra-or-contradictory-identity-witness", None),
    "detached-proposal": ("INCONCLUSIVE", "spliced-or-substituted-identity-witness", 1),
    "missing-ledger": ("INCONCLUSIVE", "incomplete-cursorial-host-or-effect-evidence", None),
    "missing-registry": ("INCONCLUSIVE", "missing-pinned-issuer-registry", None),
    "changed-instance-and-build": ("INCONCLUSIVE", "identity-changed-within-prepared-operation", 1),
    "revoked-before-effect": ("INCONCLUSIVE", "observed-effect-without-current-wolfprint-authority", 1),
    "revocation-observed-denial": ("SYNTHETICALLY VERIFIED", "issuer-host-and-ledger-witnesses-agree", 0),
}


def trace_fixture(profile, family):
    manifest, req, registry, _ = fixture(profile)
    plan = cursorial_fixture(profile)
    if family == "revocation-observed-denial":
        # Leave an unused tick after revocation for Cursorial's independent pursuit replay.
        for event in plan:
            event["at"] *= 2
        plan = vary(plan, "revoke-after-prepare")
        next(e for e in plan if e.get("state") == "revoked")["at"] -= 1
    trace = anchor_trace(execute(plan), req["claim"], registry)
    commit = registry["bindings"][-1]
    if family == "missing-witness":
        trace["identity_witnesses"].pop()
    elif family == "duplicate-witness":
        trace["identity_witnesses"].append(deepcopy(trace["identity_witnesses"][0]))
    elif family == "detached-proposal":
        commit["proposal"] += 1
    elif family == "missing-ledger":
        trace["chain"]["sources"]["ledger"]["events"].clear()
    elif family == "missing-registry":
        registry = None
    elif family == "changed-instance-and-build":
        _, req2, regs, _ = fixture(profile, "changed-build-authorized")
        claim = req2["claim"]
        registry["sessions"].append(regs["sessions"][-1])
        registry["grants"].append(regs["grants"][-1])
        trace["identity_witnesses"][-1]["claim"] = claim
        commit["statement_sha256"] = ref.frame("statement", claim)
    elif family in ("revoked-before-effect", "revocation-observed-denial"):
        registry["grants"][0]["revoked_at"] = commit["at"]
    return manifest, req, registry, trace


def input_controls():
    base = fixture(0)[0]
    valid = json.dumps(base, ensure_ascii=True).encode()
    raw = {"duplicate-decoded-key": valid.replace(b'"framework":', b'"fram\\u0065work":"x","framework":'),
           "malformed": valid[:-1], "oversize": b" " * 98305, "deep": b"[" * 13 + valid + b"]" * 13,
           "negative-zero": b'{"a":-0}', "float": b'{"a":1.5}', "invalid-utf8": b"\xff",
           "unknown-schema": json.dumps({**base, "schema": "wolftrap.architecture/v2"}).encode(),
           "confusable": json.dumps({**base, "framework": "fr\u0430mework"}).encode(),
           "extra-component": json.dumps({**base, "authority": True}).encode(),
           "copied-namespaced-tool": json.dumps({**base, "mcp_tools": base["mcp_tools"] * 2}).encode(),
           "repeated-capability": json.dumps({**base, "capabilities": ["read", "read"]}).encode()}
    errors = ("duplicate-json-key", "malformed-json", "input-byte-limit", "json-depth-limit", "noncanonical-negative-zero",
              "unsupported-number", "malformed-json", "invalid-architecture-shape", "invalid-architecture-shape",
              "invalid-architecture-shape", "ambiguous-namespaced-tool", "duplicate-capability")
    rows = []
    for (name, data), expected in zip(raw.items(), errors, strict=True):
        reason = "accepted"
        try:
            fingerprint(decode_json(data, canonical_numbers=True))
        except Gap as exc:
            reason = str(exc)
        rows.append({"id": name, "observed": reason, "expected": expected, "matched": reason == expected})
    return rows


def qualify():
    rows, chains = [], []
    defects = {k: {"control": k, "mismatches": 0, "first_counterexample": None} for k in MUTANTS}
    for profile in range(4):
        for family, expected in ref.EXPECT.items():
            data = fixture(profile, family)
            m, req, r, at = data
            named = f"WP-{profile + 1}-{family}"
            result = inspect(m, req, r, at)
            actual = _outcome(result)
            policy, ident = result["policy_proposal"], result["identity"]
            s = req["claim"]
            ids = (None, None) if expected[0] != ref.OK else (
                ref.frame("principal", {k: s[k] for k in ("trust_domain", "issuer", "tenant", "principal")}),
                ref.frame("instance", s))
            correct = (actual == expected and result["architecture_sha256"] == ref.architecture(m)
                       and ids == (ident["principal_id"], ident["instance_id"])
                       and policy["operation_sha256"] == ref.operation(req["operation"])
                       and policy["write_eligible_in_model"] == (expected[2] == "ALLOW" and expected[3]
                                                               and req["operation"]["verb"] != "read")
                       and policy["enforced"] is False and ident["cryptographically_authenticated"] is False)
            rows.append({"id": named, "classification": actual[1], "identity_status": actual[0],
                         "action": actual[2], "current_scoped_grant": actual[3], "expected": list(expected),
                         "architecture_sha256": result["architecture_sha256"], "principal_id": ident["principal_id"],
                         "instance_id": ident["instance_id"], "audit_sha256": policy["audit_sha256"], "matched": correct})
            for control, score in defects.items():
                if _mutate(control, result, data) != expected:
                    score["mismatches"] += 1
                    if score["first_counterexample"] is None:
                        score["first_counterexample"] = named
        for family, expectation in TRACE_EXPECT.items():
            _, _, r, trace = trace_fixture(profile, family)
            profile_result = inspect_chain(trace, r)["identity_profile"]
            attempts = profile_result["attempts"]
            count = attempts[0]["independently_observed_effects"] if attempts else None
            actual = (profile_result["status"], profile_result["reason"], count)
            changes = profile_result["changes"]
            transitioned = any("architecture_sha256" in row["changed"] and "instance_id" in row["changed"] for row in changes)
            chains.append({"id": f"WP-CIE-{profile + 1}-{family}", "expected": list(expectation), "observed": list(actual),
                           "trace_sha256": profile_result["trace_sha256"], "behavioral_sha256": profile_result["behavioral_sha256"],
                           "matched": actual == expectation and transitioned == (family == "changed-instance-and-build")})
    invalid = input_controls()
    failures = sum(not row["matched"] for row in rows + chains + invalid)
    caught = sum(d["mismatches"] > 0 for d in defects.values())
    return {"schema": "wolftrap.wolfprint-challenge/v1", "mode": "qualification",
            "status": "PASSED_BOUNDED" if not failures and caught == len(defects) else "CONTROL_GAP",
            "summary": {"cases": len(rows) + len(chains) + len(invalid), "identity_policy_cases": len(rows),
                        "trace_cases": len(chains), "invalid_input_cases": len(invalid), "mismatches": failures,
                        "defects_caught": caught, "defects": len(defects), "decisions": dict(Counter(r["action"] for r in rows))},
            "cases": rows, "traces": chains, "invalid_inputs": invalid, "defective_controls": list(defects.values())}

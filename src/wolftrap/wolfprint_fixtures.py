"""Fictional data factory. No issuer connectivity, credentials or signing material."""

from __future__ import annotations

from copy import deepcopy
from hashlib import sha256

from . import wolfprint_reference as ref


def artifact(label):
    return sha256(("fictional-artifact/" + label).encode("ascii")).hexdigest()


def manifest(profile):
    key = str(profile)
    return {"schema": "wolftrap.architecture/v1", "framework": "fixture-runner", "framework_version": "1.0",
            "model_provider": "fixture-lab", "model_family": "example-" + key,
            "model_revision": {"label": "r1", "evidence_sha256": artifact("model-card-" + key)},
            "build_sha256": artifact("build-" + key), "dependency_sha256": artifact("dependencies"),
            "sbom_sha256": artifact("sbom"), "sandbox_sha256": artifact("sandbox"),
            "permission_policy_sha256": artifact("permission-policy"), "protected_config_sha256": "UNKNOWN",
            "capabilities": ["label", "archive", "read", "append"],
            "mcp_tools": [{"server_sha256": artifact("server-" + n), "tool_sha256": artifact("tool"),
                           "schema_sha256": artifact("schema-" + n)} for n in ("a", "b")]}


def _key(revision=1, previous=0, since=0):
    return {"revision": revision, "previous": previous, "since": since, "expires": 180, "revoked_at": None}


def fixture(profile=1, family="authorized"):
    principal = profile + 1
    base = manifest(profile)
    if family == "benign-lookalike":
        base["framework"] = "quarantine-reviewer"
    candidate = deepcopy(base)
    op = {"server": 1, "tool": 1, "schema_rev": 1, "verb": ("append", "label", "archive", "append")[profile],
          "resource": principal, "value": 1}
    issued = {"issuer": 1, "trust_domain": 1, "tenant": principal, "principal": principal,
              "instance": 10 + principal, "nonce": 20 + principal, "audience": 2, "key_revision": 1, "issued": 2,
              "expires": 145, "architecture_sha256": ref.architecture(base), "policy_revision": 1,
              "delegation": list(range(1, principal + 1))}
    other = principal + 20
    components = sorted(k for k, v in base.items() if k != "schema" and v != "UNKNOWN")
    baseline = {k: issued[k] for k in ("principal", "architecture_sha256", "instance", "key_revision")}
    r = {"schema": "wolftrap.fixture-registry/v1", "issuer": 1, "trust_domain": 1, "tenant": principal,
         "audience": 2, "since": 0, "expires": 200, "epoch": 1, "policy_revision": 1, "baseline": baseline,
         "principals": [{"principal": p, "keys": [_key()]} for p in (principal, other)],
         "sessions": [{"statement": deepcopy(issued), "components": components.copy()}],
         "used_nonces": [], "revocations": [], "grants": [], "restrictions": [], "bindings": []}
    if family in ("changed-build-authorized", "changed-without-new-grant", "forged-build"):
        candidate["build_sha256"] = artifact("build-upgrade")
    if family in ("changed-schema-authorized", "forged-schema"):
        candidate["mcp_tools"][0]["schema_sha256"] = artifact("schema-upgrade")
    if family == "changed-policy-authorized":
        candidate["permission_policy_sha256"] = artifact("policy-upgrade")
    if family == "changed-capability-authorized":
        candidate["capabilities"].remove("archive")
    if family == "unknown-model":
        candidate["model_revision"] = "UNKNOWN"
    if family == "reordered-manifest":
        candidate = dict(reversed(candidate.items()))
        candidate["mcp_tools"].reverse()
        candidate["capabilities"].reverse()
    claim = deepcopy(issued)
    if family in ("restart", "concurrent", "rotation", "unknown-model") or family.startswith(("changed-", "other-principal-")) and family != "changed-statement":
        claim.update(instance=issued["instance"] + 10, nonce=issued["nonce"] + 10, issued=8,
                     architecture_sha256=ref.architecture(candidate))
        if family.startswith("other-principal-"):
            claim.update(principal=other, delegation=[other])
        if family == "rotation":
            r["principals"][0]["keys"].append(_key(2, 1, 7))
            claim["key_revision"] = 2
        r["sessions"].append({"statement": deepcopy(claim),
                              "components": [k for k in components if candidate[k] != "UNKNOWN"]})
    if family == "legitimate-read":
        op["verb"] = "read"
    grant = {"principal": claim["principal"], "architecture_sha256": claim["architecture_sha256"],
             "operation_sha256": ref.operation(op), "scope": op["resource"], "epoch": 1, "policy_revision": 1,
             "delegation": claim["delegation"].copy(), "since": 0, "expires": 150, "revoked_at": None}
    r["grants"].append(grant)
    at = 30
    if family == "changed-without-new-grant":
        grant["architecture_sha256"] = issued["architecture_sha256"]
    elif family == "other-principal-no-grant":
        grant.update(principal=principal, delegation=issued["delegation"])
    elif family == "cloned-subject":
        claim["principal"] = other
    elif family == "changed-statement":
        claim["nonce"] += 1
    elif family == "foreign-delegation":
        claim["delegation"] = [other, principal]
    elif family in ("wrong-domain", "wrong-issuer", "wrong-tenant", "wrong-audience"):
        field = family.removeprefix("wrong-")
        claim["trust_domain" if field == "domain" else field] += 1
    elif family == "expired-instance":
        at = claim["expires"]
    elif family == "not-issued":
        at = 1
    elif family == "retired-key":
        r["principals"][0]["keys"][0]["revoked_at"] = at
    elif family == "revoked-session":
        r["revocations"].append({"principal": principal, "instance": claim["instance"], "at": at})
    elif family == "replay":
        r["used_nonces"].append({"principal": principal, "nonce": claim["nonce"], "at": at})
    elif family == "missing-claim":
        claim = None
    elif family == "missing-session":
        claim["instance"] += 8
    elif family == "stale-registry":
        at = r["expires"]
    elif family == "revoked-grant":
        grant["revoked_at"] = at
    elif family == "wrong-scope":
        grant["scope"] += 1
    elif family == "wrong-operation":
        op["value"] += 1
    elif family == "stale-authority-epoch":
        r["epoch"] += 1
    elif family == "stale-policy-revision":
        r["policy_revision"] += 1
    elif family == "unattested-component":
        r["sessions"][0]["components"].remove("model_revision")
    elif family == "future-revocation":
        grant["revoked_at"] = at + 1
    actions = {"read-only": "READ_ONLY", "reauth-policy": "REAUTHENTICATE", "human-policy": "REQUIRE_HUMAN_APPROVAL",
               "quarantined": "QUARANTINE", "denied": "DENY", "policy-appeal-lifted": "QUARANTINE",
               "other-principal-quarantined": "QUARANTINE", "other-principal-foreign-restriction": "QUARANTINE"}
    if family in actions:
        r["restrictions"].append({"principal": principal if family == "other-principal-foreign-restriction" else claim["principal"],
                                  "scope": op["resource"], "operation_sha256": ref.operation(op),
                                  "policy_revision": 1, "action": actions[family], "since": 2, "expires": 100,
                                  "revoked_at": at if family == "policy-appeal-lifted" else None, "review": 1})
    return candidate, {"schema": "wolftrap.instance-request/v1", "claim": claim, "operation": op}, (
        None if family == "self-declared" else r), at


def anchor_trace(chain, claim, registry):
    """Fixture issuer and host emit sidecar bindings before the candidate is inspected."""
    events = {e["id"]: e for e in chain["sources"]["host"]["events"]}
    witnesses = []
    for e in events.values():
        if e["kind"] != "gate_decision":
            continue
        bind = events[e["binding"]]
        witnesses.append({"schema": "wolftrap.identity-witness/v1", "binding": bind["id"],
                          "phase": e["phase"], "claim": deepcopy(claim)})
        registry["bindings"].append({"trace_sha256": ref.frame("cursorial-trace", chain),
                                     "chain": bind["chain"], "proposal": bind["proposal"], "binding": bind["id"],
                                     "phase": e["phase"], "at": e["at"], "statement_sha256": ref.frame("statement", claim),
                                     "operation_sha256": bind["digest"]})
    return {"schema": "wolftrap.cursorial-identity-chain/v2", "profile": "wolfprint-fixture/v1",
            "chain": chain, "identity_witnesses": witnesses}

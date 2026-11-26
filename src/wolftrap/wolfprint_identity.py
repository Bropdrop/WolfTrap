"""Offline fixture issuer and scoped policy simulation. No credential or enforcement API."""

from __future__ import annotations

from .canonical import sha256_json
from .cursorial_trace import need
from .wolfprint import OPTIONAL, UNKNOWN, definitions, domain_digest, session_id, subject, tenant_id, validate

ATTESTED = "FIXTURE_ATTESTED"
INVALID = "INVALID_OR_EXPIRED_IDENTITY_EVIDENCE"
SPOOF = "CLAIMED_IDENTITY_SPOOFING"
GAP = "INCONCLUSIVE_IDENTITY"
RANK = ("ALLOW", "READ_ONLY", "REQUIRE_HUMAN_APPROVAL", "REAUTHENTICATE", "QUARANTINE", "DENY")


def _unique(rows, key, reason):
    ids = [key(row) for row in rows]
    need(len(ids) == len(set(ids)), reason)


def _interval(row):
    return row["since"] < row["expires"]


def _active(row, at):
    return row["since"] <= at < row["expires"] and (row.get("revoked_at") is None or at < row["revoked_at"])


def registry_contract(registry: dict) -> None:
    validate(registry, "registry")
    need(_interval(registry), "invalid-registry-window")
    registrations = registry["principals"]
    _unique(registrations, lambda r: r["principal"], "ambiguous-registration")
    principals = {r["principal"]: r for r in registrations}
    for r in registrations:
        keys = {k["revision"]: k for k in r["keys"]}
        need(len(keys) == len(r["keys"]) and sum(k["previous"] == 0 for k in keys.values()) == 1,
             "ambiguous-key-lineage")
        for k in keys.values():
            parent = keys.get(k["previous"])
            need(_interval(k) and (not k["previous"] or (parent is not None and parent["since"] < k["since"])),
                 "unresolved-key-lineage")
    sessions = registry["sessions"]
    _unique(sessions, lambda s: (s["statement"]["principal"], s["statement"]["instance"]), "ambiguous-instance")
    _unique(sessions, lambda s: (s["statement"]["principal"], s["statement"]["nonce"]), "ambiguous-session-nonce")
    for entry in sessions:
        s = entry["statement"]
        capabilities = entry["capabilities"]
        need((capabilities != UNKNOWN) == ("capabilities" in entry["components"]) and
             (capabilities == UNKNOWN or len(capabilities) == len(set(capabilities))),
             "contradictory-capability-witness")
        need(all(s[k] == registry[k] for k in ("trust_domain", "issuer", "tenant", "audience"))
             and s["principal"] in principals and s["issued"] < s["expires"]
             and s["key_revision"] in {k["revision"] for k in principals[s["principal"]]["keys"]}
             and len(set(s["delegation"])) == len(s["delegation"]) and s["delegation"][-1] == s["principal"]
             and len(set(entry["components"])) == len(entry["components"]), "contradictory-issuer-record")
    prior = registry["baseline"]
    if prior is not None:
        need(any(all(entry["statement"][k] == v for k, v in prior.items()) for entry in sessions),
             "unwitnessed-baseline")
    _unique(registry["bindings"], lambda a: (a["trace_sha256"], a["binding"], a["phase"]), "ambiguous-host-witness")
    _unique(registry["restrictions"], lambda a: (a["principal"], a["operation_sha256"], a["scope"],
            a["policy_revision"], a["review"]), "ambiguous-policy-review")
    _unique(registry["grants"], lambda g: (g["principal"], g["architecture_sha256"], g["operation_sha256"],
            g["scope"], g["epoch"], g["policy_revision"], tuple(g["delegation"])), "ambiguous-current-authority")
    for g in registry["grants"] + registry["restrictions"]:
        need(_interval(g) and g["principal"] in principals, "contradictory-policy-record")
    for g in registry["grants"]:
        need(len(set(g["delegation"])) == len(g["delegation"]) and g["delegation"][-1] == g["principal"],
             "contradictory-grant-delegation")


def _unverified(status, reason):
    return {"status": status, "reason": reason, "principal_id": None, "instance_id": None,
            "attested_components": [], "attested_capabilities": UNKNOWN, "valid_until": None,
            "cryptographically_authenticated": False}


def authenticate(s: dict | None, architecture: str, r: dict | None, at: int | None) -> dict:
    if s is None or r is None or at is None:
        return _unverified(GAP, "independent-issuer-or-presentation-missing")
    if not _active(r, at):
        return _unverified(GAP, "registry-outside-observation-window")
    if any(s[k] != r[k] for k in ("issuer", "trust_domain", "tenant", "audience")):
        return _unverified(INVALID, "issuer-tenant-domain-or-audience-mismatch")
    records = [entry for entry in r["sessions"] if entry["statement"]["instance"] == s["instance"]]
    entry = next((entry for entry in records if entry["statement"]["principal"] == s["principal"]), None)
    if entry is None:
        if any(e["statement"]["nonce"] == s["nonce"] for e in records):
            return _unverified(SPOOF, "claimed-subject-conflicts-with-issuer-record")
        return _unverified(GAP, "issuer-session-witness-missing")
    if entry["statement"] != s or architecture != s["architecture_sha256"]:
        return _unverified(SPOOF, "presentation-conflicts-with-independent-binding")
    if not s["issued"] <= at < s["expires"]:
        return _unverified(INVALID, "instance-expired-or-not-yet-issued")
    reg = next(p for p in r["principals"] if p["principal"] == s["principal"])
    key = next(k for k in reg["keys"] if k["revision"] == s["key_revision"])
    if not _active(key, at) or not _active(key, s["issued"]):
        return _unverified(INVALID, "issuer-key-outside-effective-window")
    cutoffs = [r["expires"], key["expires"], s["expires"]]
    if key["revoked_at"] is not None:
        cutoffs.append(key["revoked_at"])
    for rows, field, reason in ((r["revocations"], "instance", "instance-revoked"),
                                (r["used_nonces"], "nonce", "presentation-nonce-already-used")):
        for row in rows:
            if row["principal"] == s["principal"] and row[field] == s[field]:
                if row["at"] <= at:
                    return _unverified(INVALID, reason)
                cutoffs.append(row["at"])
    return {"status": ATTESTED, "reason": "independently-pinned-fixture-issuer-record",
            "principal_id": subject(s), "instance_id": session_id(s), "attested_components": sorted(entry["components"]),
            "attested_capabilities": sorted(entry["capabilities"]) if entry["capabilities"] != UNKNOWN else UNKNOWN,
            "valid_until": min(cutoffs), "cryptographically_authenticated": False}


def classify(identity, s, digest, r, baseline_digest=None):
    if identity["status"] != ATTESTED:
        result = [identity["status"]]
        if baseline_digest is not None:
            result.append("KNOWN_ARCHITECTURE" if digest == baseline_digest else "CHANGED_ARCHITECTURE")
        return result
    prior = r["baseline"]
    if prior is None:
        return ["INCONCLUSIVE_BASELINE"]
    same = prior["architecture_sha256"] == digest
    result = ["KNOWN_ARCHITECTURE" if same else "CHANGED_ARCHITECTURE"]
    if prior["principal"] != s["principal"]:
        if same:
            result.append("SIMILAR_ARCHITECTURE_OTHER_PRINCIPAL")
        return result
    if s["instance"] != prior["instance"]:
        result.append("SAME_PRINCIPAL_NEW_INSTANCE")
    if s["key_revision"] != prior["key_revision"]:
        rows = next(p["keys"] for p in r["principals"] if p["principal"] == s["principal"])
        parents = {k["revision"]: k["previous"] for k in rows}
        revision = parents[s["key_revision"]]
        while revision and revision != prior["key_revision"]:
            revision = parents[revision]
        result.append("VERIFIED_KEY_ROTATION" if revision else "UNRESOLVED_KEY_TRANSITION")
    return result


def propose(identity: dict, claim, operation: dict, r, at, coverage: dict, labels: list) -> dict:
    digest = sha256_json(operation)
    verified = identity["status"] == ATTESTED
    action, reason, grant_ok = "REAUTHENTICATE", identity["reason"], False
    cutoffs = [identity["valid_until"]] if verified else []
    reviews = []
    if verified:
        match = {"principal": claim["principal"], "architecture_sha256": claim["architecture_sha256"],
                 "operation_sha256": digest, "scope": operation["resource"], "epoch": r["epoch"],
                 "policy_revision": r["policy_revision"], "delegation": claim["delegation"]}
        grants = [g for g in r["grants"] if all(g[k] == v for k, v in match.items())]
        cutoffs.extend(g["since"] for g in grants if g["since"] > at)
        grant = next((g for g in grants if _active(g, at)), None)
        grant_ok = grant is not None and claim["policy_revision"] == r["policy_revision"]
        if not grant_ok:
            action, reason = "DENY", "missing-current-scoped-authority"
        else:
            cutoffs.append(grant["expires"])
            if grant["revoked_at"] is not None:
                cutoffs.append(grant["revoked_at"])
            uncertain = any(v != "ATTESTED" for k, v in coverage.items() if k != OPTIONAL)
            if uncertain or "UNRESOLVED_KEY_TRANSITION" in labels:
                action, reason = "REQUIRE_HUMAN_APPROVAL", "incomplete-component-or-key-lineage"
            elif operation["verb"] not in identity["attested_capabilities"]:
                action, reason = "REQUIRE_HUMAN_APPROVAL", "operation-outside-attested-capabilities"
            else:
                action, reason = "ALLOW", "current-scoped-fixture-grant"
        for rule in r["restrictions"]:
            if any(rule[k] != match[k] for k in ("principal", "operation_sha256", "scope", "policy_revision")):
                continue
            if rule["since"] > at:
                cutoffs.append(rule["since"])
            if _active(rule, at):
                cutoffs.append(rule["expires"])
                if rule["revoked_at"] is not None:
                    cutoffs.append(rule["revoked_at"])
                reviews.append(domain_digest("review", [identity["principal_id"], rule["review"]]))
                if RANK.index(rule["action"]) > RANK.index(action):
                    action, reason = rule["action"], "active-scoped-review-policy"
    valid_until = min(cutoffs) if cutoffs else None
    audit = {"action": action, "reason": reason, "principal_id": identity["principal_id"],
             "instance_id": identity["instance_id"], "tenant_id": tenant_id(r) if r else None,
             "operation_sha256": digest, "scope_id": domain_digest("scope", [tenant_id(r), operation["resource"]]) if r else None,
             "architecture_sha256": claim["architecture_sha256"] if verified else None,
             "delegation_sha256": domain_digest("delegation", [identity["principal_id"], claim["delegation"]]) if verified else None,
             "policy_revision": r["policy_revision"] if r else None, "authority_epoch": r["epoch"] if r else None,
             "registry_sha256": domain_digest("registry", r) if r else None, "evaluated_at": at,
             "valid_until": valid_until, "current_scoped_grant": grant_ok,
             "write_eligible_in_model": grant_ok and action == "ALLOW" and operation["verb"] != "read",
             "enforced": False, "appeal": {"route": "tenant-policy-review", "review_ids": sorted(reviews)}}
    return {**audit, "audit_sha256": domain_digest("policy-audit", audit)}


def evaluate(architecture: dict, request: dict, registry, at, baseline_digest=None) -> dict:
    """Evaluate already schema-checked operator inputs. Public callers use inspect()."""
    s, digest = request["claim"], architecture["architecture_sha256"]
    identity = authenticate(s, digest, registry, at)
    if identity["status"] == ATTESTED and identity["attested_capabilities"] != UNKNOWN:
        if identity["attested_capabilities"] != architecture["capabilities"]:
            identity = _unverified(GAP, "issuer-capabilities-conflict-with-selected-manifest")
    labels = classify(identity, s, digest, registry, baseline_digest)
    coverage = {k: ("ATTESTED" if v != UNKNOWN and k in identity["attested_components"] else v)
                for k, v in architecture["components"].items()}
    decision = propose(identity, s, request["operation"], registry, at, coverage, labels)
    return {"architecture_sha256": digest, "coverage": coverage, "identity": identity, "classification": labels,
            "policy_proposal": decision, "behavioral_sha256": UNKNOWN}


def inspect(manifest: dict, request: dict | None, registry=None, at=None, baseline=None) -> dict:
    from .wolfprint import fingerprint

    arch = fingerprint(manifest)
    previous = fingerprint(baseline)["architecture_sha256"] if baseline is not None else None
    if registry is not None:
        registry_contract(registry)
        validate(at, "tick")
        if previous is not None:
            need(registry["baseline"] is not None and registry["baseline"]["architecture_sha256"] == previous,
                 "stale-or-substituted-baseline")
    if request is None:
        need(registry is None, "identity-request-required-with-registry")
        labels = [] if previous is None else ["KNOWN_ARCHITECTURE" if previous == arch["architecture_sha256"] else "CHANGED_ARCHITECTURE"]
        return {"architecture_sha256": arch["architecture_sha256"], "coverage": arch["components"],
                "identity": _unverified(GAP, "architecture-only"), "classification": labels, "policy_proposal": None,
                "behavioral_sha256": UNKNOWN}
    validate(request, "request")
    return evaluate(arch, request, registry, at, previous)


def witnessed_components(identity: dict) -> dict:
    names = definitions()["architecture"]["properties"].keys() - {"schema"}
    return {k: "ATTESTED" if k in identity["attested_components"] else UNKNOWN for k in sorted(names)}

"""One fictional operation, independently selected local policy, zero enforcement."""

from __future__ import annotations

from collections import defaultdict

from .cursorial_trace import need
from .wolfprint_identity import ATTESTED, inspect
from .wolfnet_format import ACTIONS, CONFIDENCE, GAP, LEVELS, STATIC, SYNTHETIC, advance, digest, interval, logical_time, validate


def _applicable(records, scope, identity, architecture, operation, resource, publishers, key_revision):
    selected = []
    for row in records:
        r, s = row["record"], row["record"]["subject"]
        if (r["publisher"] in publishers and all(s[k] == scope[k] for k in ("tenant", "trust_domain", "issuer"))
            and s["principal_id"] == identity["principal_id"] and s["architecture_sha256"] == architecture
            and s["instance_id"] in (None, identity["instance_id"]) and s["key_revision"] in (None, key_revision)
            and r["operation_sha256"] == operation and r["resource_scope"] == resource):
            selected.append(row)
    return selected


def _conflict(rows):
    incidents = defaultdict(list)
    for row in rows:
        incidents[row["record"]["incident_ref"]].append(row)
    for group in incidents.values():
        active = [entry["record"] for entry in group if entry["state"] == "ACTIVE"]
        if active and (any(r["state"] in ("CONTESTED", "WITHDRAWN") for r in group)
                       or len({(r["category"], r["severity"], r["confidence"]) for r in active}) > 1):
            return True
    return False


def evaluate(verified, bundle, policy, manifest, request, registry, at):
    validate(policy, "policy")
    need(isinstance(request, dict) and isinstance(registry, dict), "current-workload-presentation-and-registry-required")
    scope = bundle["subscription"]
    interval(policy["since"], policy["expires"])
    need(policy["subscription"] == scope and policy["since"] <= at < policy["expires"], "stale-or-foreign-local-policy")
    pubs = policy["publishers"]
    need(len(set(pubs)) == len(pubs) and set(pubs) <= {k["signer"] for k in bundle["keys"] if k["role"] == "publisher"},
         "unknown-local-publisher-selection")
    need(len(set(policy["appeal_holds"])) == len(policy["appeal_holds"]) and policy["actions"][0] == "ALLOW",
         "invalid-local-policy-map")
    tick = logical_time(bundle, at)
    wp = inspect(manifest, request, registry, tick)
    identity, host = wp["identity"], wp["policy_proposal"]
    operation = host["operation_sha256"]
    disputed = policy.get("disputed_instances", [])
    need(len(set(disputed)) == len(disputed), "ambiguous-local-custody-records")
    disputed_session = identity["instance_id"] in disputed
    subject_ok = identity["status"] == ATTESTED and not disputed_session and all(
        registry[k] == scope[k] for k in ("issuer", "trust_domain", "tenant"))
    target = identity["principal_id"] if subject_ok else None
    rows = _applicable(verified["advisories"], scope, identity, wp["architecture_sha256"], operation,
                       request["operation"]["resource"], pubs, request["claim"]["key_revision"]) if subject_ok else []
    active = [r for r in rows if r["state"] == "ACTIVE"]
    held = [r for r in rows if r["state"] in ("ACTIVE", "CONTESTED", "UNTRUSTED") and
            r["record"]["advisory_id"] in policy["appeal_holds"]]
    ambiguous = bool(held or _conflict(rows) or any(r["state"] in ("CONTESTED", "UNTRUSTED", "PENDING_REVIEW")
                                                     for r in rows) or any(r["effective_level"] is None for r in active))
    horizons = [verified["valid_until"], policy["expires"]]
    if host["valid_until"] is not None:
        horizons.append(advance(bundle["clock_origin"], host["valid_until"]))
    for row in active:
        horizons.append(row["record"]["expires_at"])
        if row["evidence_valid_until"]:
            horizons.append(row["evidence_valid_until"])
    advice, level, confidence, assurance = "ALLOW", 0, None, "UNKNOWN"
    classification, reason, code = "NO_ACTIVE_ADVERSE_IN_SCOPE", "no-active-applicable-advisory", 0
    if not subject_ok or ambiguous:
        advice, level, classification, code = None, None, GAP, 2
        reason = "missing-trusted-presentation" if not subject_ok else "disputed-held-or-incomplete-evidence"
        if disputed_session:
            reason = "operator-disputes-session-custody"
    elif active:
        level = max(r["effective_level"] for r in active)
        highest = [r for r in active if r["effective_level"] == level]
        confidence = min((r["confidence"] for r in highest), key=CONFIDENCE.index)
        classification = SYNTHETIC if all(r["classification"] == SYNTHETIC for r in highest) else STATIC
        if all(r["identity_assurance"] == "FIXTURE_ISSUER_BOUND" for r in highest):
            assurance = "FIXTURE_ISSUER_BOUND"
        advice, reason, code = "MONITOR", "scoped-advisory-only", 1
        if policy.get("mode", "advisory") == "fictional-simulation":
            for row in active:
                r = row["record"]
                if (row["classification"] != SYNTHETIC or row["identity_assurance"] != "FIXTURE_ISSUER_BOUND"
                    or row["observed_instance"] != identity["instance_id"] or row["effective_level"] < policy["min_severity"]
                    or CONFIDENCE.index(row["confidence"]) < CONFIDENCE.index(policy["min_confidence"])
                    or len(row["approval_orgs"]) < policy["min_reviewers"]):
                    continue
                action = min((policy["actions"][row["effective_level"]], r["recommendation"]), key=ACTIONS.index)
                if action in ("QUARANTINE", "DENY") and not (
                    row["effective_level"] >= 3 and row["confidence"] == "HIGH" and len(row["approval_orgs"]) >= 2
                    and row["observation"]["category"] == "unauthorized-effect"):
                    continue
                if action == "DENY" and not policy.get("permit_deny", False):
                    continue
                if ACTIONS.index(action) > ACTIONS.index(advice):
                    advice, reason = action, "explicit-local-fixture-rule-and-independent-evidence"
    # An unverified subscription or claim can never add permission or identify a ban subject.
    local = host["action"]
    proposed = local if advice is None else max((advice, local), key=ACTIONS.index)
    if not subject_ok:
        proposed = max((local, "REAUTHENTICATE"), key=ACTIONS.index)
    decision = {"classification": classification, "basis": reason, "effective_level": level,
                "severity_label": LEVELS[level] if level is not None else "UNKNOWN", "confidence": confidence,
                "subject_assurance": assurance, "presentation_assurance": identity["status"],
                "principal_id": target, "instance_id": identity["instance_id"] if subject_ok else None,
                "architecture_sha256": wp["architecture_sha256"], "subscription": scope,
                "operation_sha256": operation, "resource_scope": request["operation"]["resource"],
                "feed_head": verified["checkpoint"]["head"], "feed_sequence": verified["checkpoint"]["sequence"],
                "trust_revision": bundle["revision"], "publisher_trust_sha256": digest("subscriber-trust", bundle),
                "policy_revision": policy["revision"], "policy_sha256": digest("local-policy", policy),
                "host_authority_epoch": host["authority_epoch"], "host_policy_revision": host["policy_revision"],
                "host_authority_sha256": host["registry_sha256"], "host_audit_sha256": host["audit_sha256"],
                "current_scoped_grant": host["current_scoped_grant"] if subject_ok else False,
                "host_proposal": local, "registry_proposal": advice, "proposed_action": proposed,
                "valid_until": min(horizons), "at": at, "scope": "one-fictional-operation", "enforced": False,
                "advisories": [{"id": r["record"]["advisory_id"], "revision": r["record"]["revision"], "state": r["state"],
                                "effective_level": r["effective_level"], "confidence": r["confidence"],
                                "identity_assurance": r["identity_assurance"], "classification": r["classification"],
                                "evidence_sha256": r["record"]["evidence_sha256"], "appeal_ref": r["record"]["appeal_ref"]}
                               for r in rows]}
    return {"status": classification, "exit_code": code, "decision": {**decision, "audit_sha256": digest("decision", decision)}}

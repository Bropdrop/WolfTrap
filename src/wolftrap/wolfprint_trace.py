"""Opt-in Cursorial profile joining fictional issuer, host and effect witnesses."""

from __future__ import annotations

from .cursorial import UNKNOWN as INCONCLUSIVE, VERIFIED, inspect_capture
from .cursorial_trace import Gap, need
from .wolfprint import UNKNOWN, behavior, domain_digest, validate
from .wolfprint_identity import ATTESTED, authenticate, classify, propose, registry_contract, witnessed_components


def _lineage(binding, host, owner):
    parent = binding["delegation"]
    path = []
    while parent:
        entry = host[parent]
        path.append(entry["delegate"])
        parent = entry["parent"]
    return [owner, *reversed(path)]


def inspect_chain(envelope: dict, registry: dict | None) -> dict:
    validate(envelope, "trace")
    chain = envelope["chain"]
    report = inspect_capture(chain)
    trace_digest = domain_digest("cursorial-trace", chain)
    result = {"schema": "wolftrap.cursorial-identity-result/v1", "profile": envelope["profile"],
              "status": INCONCLUSIVE, "trace_sha256": trace_digest, "behavioral_sha256": UNKNOWN,
              "changes": [], "attempts": [], "reason": "incomplete-independent-evidence"}
    report["identity_profile"] = result
    report["schema"] = "wolftrap.cursorial-evidence/v2"
    report["pursuit_identity_coverage"] = "unattested-counterfactuals"
    try:
        need(registry is not None, "missing-pinned-issuer-registry")
        registry_contract(registry)
        need(report["status"] == VERIFIED, "incomplete-cursorial-host-or-effect-evidence")
        observed = report["capture"]["witnesses"]
        need(bool(observed), "missing-protected-effect-window")
        keys = {(row["binding"], phase) for row in observed for phase in ("prepare", "commit")}
        entries = {(w["binding"], w["phase"]): w["claim"] for w in envelope["identity_witnesses"]}
        need(len(entries) == len(envelope["identity_witnesses"]) and entries.keys() == keys,
             "missing-extra-or-contradictory-identity-witness")
        anchors = {(a["binding"], a["phase"]): a for a in registry["bindings"] if a["trace_sha256"] == trace_digest}
        need(anchors.keys() == keys, "incomplete-independent-host-identity-bindings")
        host = {e["id"]: e for e in chain["sources"]["host"]["events"]}
        root = next(e for e in host.values() if e["kind"] == "chain_opened")
        proposals = {e["id"]: e for e in chain["sources"]["agent"]["events"]}
        previous = None
        timeline = []
        gap = None
        for row in observed:
            binding = host[row["binding"]]
            proposal = proposals[binding["proposal"]]
            lineage = _lineage(binding, host, root["owner"])
            count = len(row["ledger_witness"]["records"])
            attempt = {"binding": binding["id"], "proposal": proposal["id"], "effect_event": row["ledger_witness"]["event"],
                       "independently_observed_effects": count, "operation_sha256": binding["digest"], "phases": {}}
            result["attempts"].append(attempt)
            for phase in ("prepare", "commit"):
                phase_key = (binding["id"], phase)
                claim = entries[phase_key]
                event = host[row["host_witness"][phase + "_event"]]
                expected = {"trace_sha256": trace_digest, "chain": binding["chain"], "proposal": proposal["id"],
                            "binding": binding["id"], "phase": phase, "at": event["at"],
                            "statement_sha256": domain_digest("statement", claim), "operation_sha256": binding["digest"]}
                need(anchors[phase_key] == expected, "spliced-or-substituted-identity-witness")
                need((claim["tenant"], claim["principal"], claim["delegation"]) ==
                     (binding["tenant"], binding["actor"], lineage), "identity-delegation-or-host-actor-conflict")
                identity = authenticate(claim, claim["architecture_sha256"], registry, event["at"])
                need(identity["status"] == ATTESTED, identity["reason"])
                if phase == "prepare":
                    initiator = authenticate(claim, claim["architecture_sha256"], registry, proposal["at"])
                    need(initiator["status"] == ATTESTED, "identity-not-current-at-proposal")
                    attempt["initiator"] = {"at": proposal["at"], "principal_id": initiator["principal_id"],
                                            "instance_id": initiator["instance_id"]}
                labels = classify(identity, claim, claim["architecture_sha256"], registry)
                decision = propose(identity, claim, proposal["operation"], registry, event["at"],
                                   witnessed_components(identity), labels)
                phase_row = {"principal_id": identity["principal_id"], "instance_id": identity["instance_id"],
                             "architecture_sha256": claim["architecture_sha256"], "at": event["at"],
                             "delegation_sha256": decision["delegation_sha256"], "host_delegation_event": binding["delegation"],
                             "host_grant": proposal["grant"], "host_gate": row["host_witness"][phase],
                             "policy_proposal": decision, "classification": labels}
                attempt["phases"][phase] = phase_row
                timeline.append((event["at"], binding["id"], phase, phase_row))
            start, end = (attempt["phases"][p] for p in ("prepare", "commit"))
            if start["instance_id"] != end["instance_id"]:
                gap = "identity-changed-within-prepared-operation"
            if count and not all(p["policy_proposal"]["write_eligible_in_model"] for p in (start, end)):
                gap = "observed-effect-without-current-wolfprint-authority"
        for _, binding_id, phase, row in sorted(timeline):
            if previous is not None:
                changed = [k for k in ("principal_id", "instance_id", "architecture_sha256", "delegation_sha256")
                           if row[k] != previous[k]]
                if changed:
                    result["changes"].append({"binding": binding_id, "phase": phase, "changed": changed})
            previous = row
        need(gap is None, gap or "identity-evidence-gap")
        result.update(status=VERIFIED, reason="issuer-host-and-ledger-witnesses-agree",
                      behavioral_sha256=behavior(chain, report["capture"], registry))
    except Gap as exc:
        result["reason"] = str(exc)
        report.update(status=INCONCLUSIVE, exit_code=2)
    return report

"""Corroborate fictional reports against separate observer, issuer, host and ledger records."""

from __future__ import annotations

from .cursorial import assess, confirm
from .cursorial_lab import execute, schedule
from .cursorial_trace import Gap, need, track
from .wolfprint import domain_digest, validate as wp_validate
from .wolfprint_identity import ATTESTED, authenticate, registry_contract
from .wolfprint_trace import _lineage, inspect_chain
from .wolfnet_feed import read_feed
from .wolfnet_format import GAP, RUNTIME, STATIC, SYNTHETIC, advance, digest, interval, validate


def _receipt(row, identity, binding, commit):
    s = identity["claim"]
    return {"subject": {**{k: s[k] for k in ("tenant", "issuer", "trust_domain", "key_revision")},
                        "principal_id": identity["principal_id"], "instance_id": identity["instance_id"],
                        "architecture_sha256": s["architecture_sha256"]}, "binding": binding["id"],
            "resource_scope": row["operation"]["resource"], "operation_sha256": binding["digest"], "tick": commit["at"]}


def _reproduced_boundary(envelope, registry, measured):
    """One allowlisted in-memory defect. Require exact trace and reference-oracle reproduction."""
    chain = envelope["chain"]
    need(len(measured["discrepancies"]) == len(measured["witnesses"]) == 1, "unresolved-boundary-evidence")
    w, = measured["witnesses"]
    ledger = w["ledger_witness"]["records"]
    need(w["oracle"]["commit"] == w["host_witness"]["commit"] == "deny" and not w["oracle"]["records"]
         and len(ledger) == 1, "unresolved-boundary-evidence")
    tracked = track(chain)
    plan = schedule(tracked)
    need(execute(plan, "effect-on-deny") == chain, "unreproduced-submitted-trace")
    signature = measured["discrepancies"][0]["fingerprint"]
    run = confirm(plan, lambda: "effect-on-deny", signature)
    need(run["classification"] == SYNTHETIC and run["original"]["witness"] == w, "unreproduced-cursorial-oracle")
    events = {e["id"]: e for e in tracked.events}
    host = {e["id"]: e for e in chain["sources"]["host"]["events"]}
    root = next(e for e in host.values() if e["kind"] == "chain_opened")
    binding = host[w["binding"]]
    proposal = events[binding["proposal"]]
    need(ledger[0]["operation"] == proposal["operation"] and ledger[0]["actor"] == binding["actor"]
         and ledger[0]["tenant"] == binding["tenant"], "effect-substitution")
    trace_hash = domain_digest("cursorial-trace", chain)
    phases = {v["phase"]: v for v in envelope["identity_witnesses"]}
    anchors = [a for a in registry["bindings"] if a["trace_sha256"] == trace_hash]
    need(len(phases) == len(anchors) == len(envelope["identity_witnesses"]) == 2
         and set(phases) == {a["phase"] for a in anchors} == {"prepare", "commit"}, "missing-identity-witness")
    need(phases["prepare"]["claim"] == phases["commit"]["claim"], "changed-session-during-operation")
    s = phases["prepare"]["claim"]
    need((s["principal"], s["tenant"], s["delegation"]) == (binding["actor"], binding["tenant"],
         _lineage(binding, host, root["owner"])), "identity-delegation-conflict")
    initial = authenticate(s, s["architecture_sha256"], registry, proposal["at"])
    need(initial["status"] == ATTESTED, "unverified-initiating-session")
    for anchor in anchors:
        phase = anchor["phase"]
        gate = host[w["host_witness"][phase + "_event"]]
        expected = {"trace_sha256": trace_hash, "chain": binding["chain"], "proposal": proposal["id"], "binding": binding["id"],
                    "phase": phase, "at": gate["at"], "operation_sha256": binding["digest"],
                    "statement_sha256": domain_digest("statement", s)}
        epochs = [e for e in host.values() if e["kind"] in ("chain_opened", "epoch_observed") and e["at"] <= gate["at"]]
        need(phases[phase]["binding"] == binding["id"] and anchor == expected and
             max(epochs, key=lambda e: e["at"])["epoch"] == registry["epoch"], "spliced-identity-or-authority-witness")
        need(authenticate(s, s["architecture_sha256"], registry, gate["at"])["status"] == ATTESTED, "stale-bound-session")
    commit = host[w["host_witness"]["commit_event"]]
    facts = _receipt(proposal, {**initial, "claim": s}, binding, commit)
    return [{**facts, "category": "unauthorized-effect", "effects": len(ledger), "host_commit": "deny",
             "reference_commit": "deny", "reproduction_sha256": signature, "behavioral_sha256": None}]


def trace_observations(envelopes, registry):
    need(len(envelopes) <= 4 and bool(envelopes) == (registry is not None), "trace-and-independent-registry-required")
    if registry is not None:
        registry_contract(registry)
    found = {}
    for envelope in envelopes:
        wp_validate(envelope, "trace")
        chain = envelope["chain"]
        trace_hash = domain_digest("cursorial-trace", chain)
        need(trace_hash not in found, "duplicate-selected-trace")
        measured = assess(chain)
        try:
            if measured["discrepancies"]:
                rows = _reproduced_boundary(envelope, registry, measured)
            else:
                profile = inspect_chain(envelope, registry)["identity_profile"]
                need(profile["status"] == SYNTHETIC, "incomplete-cursorial-identity-profile")
                host = {e["id"]: e for e in chain["sources"]["host"]["events"]}
                proposals = {e["id"]: e for e in chain["sources"]["agent"]["events"]}
                rows = []
                for attempt in profile["attempts"]:
                    binding = host[attempt["binding"]]
                    phase = attempt["phases"]["commit"]
                    s = next(v["claim"] for v in envelope["identity_witnesses"]
                             if v["phase"] == "commit" and v["binding"] == binding["id"])
                    facts = _receipt(proposals[binding["proposal"]], {**phase, "claim": s}, binding, phase)
                    effects = attempt["independently_observed_effects"]
                    category = "rejected-request" if phase["host_gate"] == "deny" and not effects else "authorized-operation"
                    rows.append({**facts, "category": category, "effects": effects, "host_commit": phase["host_gate"],
                                 "reference_commit": phase["host_gate"], "reproduction_sha256": None,
                                 "behavioral_sha256": profile["behavioral_sha256"]})
            found[trace_hash] = {r["binding"]: r for r in rows}
        except Gap:
            found[trace_hash] = {}
    return found


def corroborate(trust, records, witnesses, traces, registry):
    validate(witnesses, "evidence")
    observations = trace_observations(traces, registry)
    evidence = {}
    for envelope in witnesses["witnesses"]:
        b = envelope["body"]
        interval(b["observed_at"], b["expires_at"], 30)
        need(b["subscription"] == trust.scope and b["observed_at"] <= trust.now, "unscoped-or-future-observation")
        observer = trust.check(envelope["seal"], "observer", b, b["observed_at"])
        identifier = digest("observation", b)
        need(identifier not in evidence, "ambiguous-observation")
        evidence[identifier] = (b, observer)
    result = []
    for entry in records.values():
        r = entry["record"]
        row = {**entry, "classification": GAP, "effective_level": None, "confidence": r["confidence"],
               "identity_assurance": "UNKNOWN", "basis": "independent-observation-missing", "observed_instance": None,
               "observation": None, "observer": None, "evidence_valid_until": None}
        result.append(row)
        if entry["state"] != "ACTIVE":
            row["basis"] = "lifecycle-" + entry["state"].lower()
            continue
        if r["evidence_class"] == RUNTIME or r["severity"] == 4 or r["identity_assurance"] == "RUNTIME_AUTHENTICATED":
            row["basis"] = "qualified-runtime-witness-unavailable"
            continue
        if r["evidence_sha256"] not in evidence:
            continue
        b, observer = evidence[r["evidence_sha256"]]
        row["observer"] = {k: observer[k] for k in ("signer", "org", "revision")}
        if observer["org"] in (entry["publisher_org"], *entry["approval_orgs"]):
            row["basis"] = "observer-not-independent"
            continue
        if (b["expires_at"] <= trust.now or b["observed_at"] > r["updated_at"] or
            any(b[k] != r[k] for k in ("subscription", "incident_ref", "provenance_ref", "category",
                                       "operation_sha256", "resource_scope")) or b["classification"] != r["evidence_class"] or
            any(v is not None and b["subject"][k] != v for k, v in r["subject"].items())):
            row["basis"] = "stale-or-contradictory-observation"
            continue
        row["evidence_valid_until"] = b["expires_at"]
        if b["classification"] == STATIC and b["category"] == "metadata-indicator" and r["severity"] == 1:
            row.update(classification=STATIC, effective_level=1, basis="independent-static-indicator")
            continue
        obs = observations.get(b["trace_sha256"], {}).get(b["binding"])
        if not obs:
            row["basis"] = "independent-cursorial-replay-unavailable"
            continue
        if (b["classification"] != SYNTHETIC or r["identity_assurance"] != "FIXTURE_ISSUER_BOUND"
            or obs["subject"] != b["subject"] or obs["category"] != b["category"]
            or obs["operation_sha256"] != b["operation_sha256"] or obs["resource_scope"] != b["resource_scope"]
            or advance(trust.bundle["clock_origin"], obs["tick"]) != b["observed_at"]):
            row["basis"] = "independent-witness-contradicts-allegation"
            continue
        ceiling = 3 if obs["category"] == "unauthorized-effect" else 2
        if r["severity"] > ceiling:
            row["basis"] = "severity-exceeds-observed-effect"
            continue
        row.update(classification=SYNTHETIC, effective_level=r["severity"], identity_assurance="FIXTURE_ISSUER_BOUND",
                   basis="independent-fixture-replay", observed_instance=obs["subject"]["instance_id"], observation=obs)
    return sorted(result, key=lambda item: item["record"]["advisory_id"])


def inspect_feed(feed, trust, checkpoint, witnesses, traces, witness_registry, at, *, use_accepted=False):
    roots, records, result = read_feed(feed, trust, checkpoint, at, use_accepted=use_accepted)
    entries = corroborate(roots, records, witnesses, traces, witness_registry)
    gaps = sum(r["state"] == "UNTRUSTED" or (r["state"] == "ACTIVE" and r["effective_level"] is None) for r in entries)
    return {**result, "advisories": entries, "unresolved_active_records": gaps,
            "status": "SIGNED_FEED_WITH_GAPS" if gaps else "SIGNED_FEED_VERIFIED", "exit_code": 2 if gaps else 0}

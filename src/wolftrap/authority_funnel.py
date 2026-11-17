"""ARTEX-informed, entirely synthetic authority-funnel challenge.

This models a host-owned grant registry and a stream of untrusted agent
proposals. It does not parse live prompts, verify cryptographic signatures,
operate tools, authenticate to a tenant, or load Ground Truth private code.
The independently implemented reference model is in authority_reference.py.
"""

from __future__ import annotations

import os
import re
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any, Mapping, Sequence

from .agent_scan import _json, _open_directory, _publish, _read_file, _sha
from .canonical import operation_digest


SCHEMA = "wolftrap.synthetic-authority-funnel/v1"
MANIFEST_SCHEMA = "wolftrap.synthetic-authority-funnel-manifest/v1"
REPORT_NAME = "authority-funnel-challenge.json"
MARKDOWN_NAME = "authority-funnel-challenge.md"
MANIFEST_NAME = "authority-funnel-challenge.manifest.json"
MAX_PROPOSALS = 1024
MAX_GRANTS = 32
MAX_LOGICAL_TIME = 10_000
ALLOWED_ACTIONS = frozenset({"write", "assign_role", "add_credential", "transfer"})
TOOL_CLAIMS = frozenset({
    "NONE", "SYSTEM_OVERRIDE", "VENDOR_APPROVAL", "GRANT_ADMIN", "IGNORE_POLICY",
})
GRANT_FIELDS = frozenset({
    "grant_id", "principal_id", "delegate_id", "tenant", "origin", "slot",
    "scope", "operation_digest", "epoch", "issued_at", "expires_at",
    "revoked_at", "nonce", "seal_valid",
})
PROPOSAL_FIELDS = frozenset({
    "at", "agent_id", "principal_id", "grant_id", "tenant", "origin",
    "slot", "action", "resource", "arguments", "tool_claim",
})


def _alias(value: Any, prefix: str) -> bool:
    return type(value) is str and re.fullmatch(
        re.escape(prefix) + r"[a-z0-9_-]{1,40}", value,
    ) is not None


def _tick(value: Any) -> bool:
    return type(value) is int and 0 <= value <= MAX_LOGICAL_TIME


def _operation_digest(proposal: Mapping[str, Any]) -> str:
    return operation_digest(
        action=proposal["action"],
        resource=proposal["resource"],
        arguments=proposal["arguments"],
        protected=True,
    )


def validate_input(
    grants: Sequence[dict[str, Any]],
    proposals: Sequence[dict[str, Any]],
    *,
    current_epoch: int,
    security_state_known: bool,
) -> None:
    """Accept only bounded typed in-memory data; never arbitrary prompt text."""
    if not isinstance(grants, (tuple, list)) or len(grants) > MAX_GRANTS:
        raise ValueError("synthetic grants exceed count bound")
    if not isinstance(proposals, (tuple, list)) or not 1 <= len(proposals) <= MAX_PROPOSALS:
        raise ValueError("synthetic proposals exceed count bound")
    if not _tick(current_epoch) or type(security_state_known) is not bool:
        raise ValueError("invalid trusted host-state fixture")
    ids: set[str] = set()
    nonces: set[str] = set()
    for grant in grants:
        if type(grant) is not dict or set(grant) != GRANT_FIELDS:
            raise ValueError("unknown or missing synthetic grant field")
        for field, prefix in (
            ("grant_id", "synthetic-grant://"),
            ("principal_id", "synthetic-principal://"),
            ("delegate_id", "synthetic-agent://"),
            ("tenant", "synthetic-tenant://"),
            ("origin", "synthetic-origin://"),
            ("slot", "synthetic-slot://"),
            ("nonce", "synthetic-nonce://"),
        ):
            if not _alias(grant[field], prefix):
                raise ValueError("invalid synthetic grant alias")
        if (grant["grant_id"] in ids or grant["nonce"] in nonces):
            raise ValueError("host registry contains a duplicate grant or nonce")
        ids.add(grant["grant_id"])
        nonces.add(grant["nonce"])
        if (type(grant["scope"]) is not str or ":synthetic://" not in grant["scope"]
                or len(grant["scope"]) > 120):
            raise ValueError("invalid synthetic grant scope")
        action, resource = grant["scope"].split(":", 1)
        if action not in ALLOWED_ACTIONS or re.fullmatch(
            r"synthetic://[a-z0-9_-]{1,40}/[a-z0-9_-]{1,40}", resource,
        ) is None:
            raise ValueError("invalid synthetic grant scope resource")
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", str(grant["operation_digest"])):
            raise ValueError("invalid synthetic operation digest")
        if not all(_tick(grant[field]) for field in ("epoch", "issued_at", "expires_at")):
            raise ValueError("invalid synthetic grant logical time")
        if grant["issued_at"] >= grant["expires_at"]:
            raise ValueError("invalid synthetic grant lifetime")
        if grant["revoked_at"] is not None and not _tick(grant["revoked_at"]):
            raise ValueError("invalid synthetic grant revocation")
        if type(grant["seal_valid"]) is not bool:
            raise ValueError("invalid synthetic grant seal")

    previous = -1
    for proposal in proposals:
        if type(proposal) is not dict or set(proposal) != PROPOSAL_FIELDS:
            raise ValueError("unknown or missing synthetic proposal field")
        if not _tick(proposal["at"]) or proposal["at"] < previous:
            raise ValueError("synthetic proposal time must be ordered and bounded")
        previous = proposal["at"]
        for field, prefix in (
            ("agent_id", "synthetic-agent://"),
            ("principal_id", "synthetic-principal://"),
            ("grant_id", "synthetic-grant://"),
            ("tenant", "synthetic-tenant://"),
            ("origin", "synthetic-origin://"),
            ("slot", "synthetic-slot://"),
        ):
            if not _alias(proposal[field], prefix):
                raise ValueError("invalid synthetic proposal alias")
        if type(proposal["action"]) is not str or proposal["action"] not in ALLOWED_ACTIONS:
            raise ValueError("invalid synthetic action")
        if (type(proposal["resource"]) is not str or re.fullmatch(
            r"synthetic://[a-z0-9_-]{1,40}/[a-z0-9_-]{1,40}", proposal["resource"],
        ) is None):
            raise ValueError("non-synthetic effect resources are forbidden")
        args = proposal["arguments"]
        if type(args) is not dict or len(args) != 1:
            raise ValueError("only a single bounded synthetic argument is supported")
        field, value = next(iter(args.items()))
        expected_field = {
            "write": "value", "assign_role": "role", "add_credential": "credential",
            "transfer": "destination",
        }[proposal["action"]]
        if field != expected_field or type(value) is not str:
            raise ValueError("unsupported synthetic operation arguments")
        if field == "destination":
            if not _alias(value, "synthetic-sink://"):
                raise ValueError("real transfer destinations are prohibited")
        elif re.fullmatch(r"[a-z0-9_-]{1,40}", value) is None:
            raise ValueError("raw payloads and secrets are prohibited")
        if type(proposal["tool_claim"]) is not str or proposal["tool_claim"] not in TOOL_CLAIMS:
            raise ValueError("untrusted tool claim must be an enumerated marker")


def enforce_funnel(
    grants: Sequence[dict[str, Any]],
    proposals: Sequence[dict[str, Any]],
    *,
    current_epoch: int,
    security_state_known: bool,
) -> dict[str, Any]:
    """Gate proposals against host-owned grants; return synthetic effects only.

    A tool claim is deliberately ignored when making authorization decisions.
    One protected effect per host slot and one per grant nonce are permitted.
    """
    return _enforce_funnel(
        grants, proposals, current_epoch=current_epoch,
        security_state_known=security_state_known,
    )


def _enforce_funnel(
    grants: Sequence[dict[str, Any]],
    proposals: Sequence[dict[str, Any]],
    *,
    current_epoch: int,
    security_state_known: bool,
    record_effect: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Execute the bounded gate and optionally write to the observer's sink."""
    validate_input(grants, proposals, current_epoch=current_epoch,
                   security_state_known=security_state_known)
    registry = {item["grant_id"]: item for item in grants}
    used_slots: set[str] = set()
    used_nonces: set[str] = set()
    effects: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []
    for proposal in proposals:
        grant = registry.get(proposal["grant_id"])
        reason = "ACCEPTED"
        if not security_state_known:
            reason = "UNKNOWN_SECURITY_STATE"
        elif grant is None:
            reason = "UNKNOWN_GRANT"
        elif not grant["seal_valid"]:
            reason = "UNVERIFIED_GRANT"
        elif grant["epoch"] != current_epoch:
            reason = "STALE_EPOCH"
        elif grant["revoked_at"] is not None and proposal["at"] >= grant["revoked_at"]:
            reason = "REVOKED"
        elif proposal["at"] < grant["issued_at"] or proposal["at"] >= grant["expires_at"]:
            reason = "EXPIRED_OR_NOT_YET_VALID"
        elif proposal["principal_id"] != grant["principal_id"]:
            reason = "SUBJECT_MISMATCH"
        elif proposal["agent_id"] != grant["delegate_id"]:
            reason = "DELEGATE_MISMATCH"
        elif proposal["tenant"] != grant["tenant"]:
            reason = "TENANT_MISMATCH"
        elif proposal["origin"] != grant["origin"]:
            reason = "ORIGIN_MISMATCH"
        elif proposal["slot"] != grant["slot"]:
            reason = "SLOT_MISMATCH"
        elif grant["scope"] != proposal["action"] + ":" + proposal["resource"]:
            reason = "SCOPE_MISMATCH"
        elif grant["operation_digest"] != _operation_digest(proposal):
            reason = "OPERATION_MISMATCH"
        elif grant["nonce"] in used_nonces:
            reason = "REPLAY"
        elif proposal["slot"] in used_slots:
            reason = "SLOT_EXHAUSTED"
        else:
            used_nonces.add(grant["nonce"])
            used_slots.add(proposal["slot"])
            effect = {
                "at": proposal["at"],
                "agent_id": proposal["agent_id"],
                "grant_id": grant["grant_id"],
                "slot": proposal["slot"],
                "operation_digest": _operation_digest(proposal),
            }
            if record_effect is not None:
                record_effect(dict(effect))
            effects.append(effect)
        decisions.append({"agent_id": proposal["agent_id"], "reason": reason})
    return {"effects": effects, "decisions": decisions}


def _base() -> tuple[dict[str, Any], dict[str, Any]]:
    proposal = {
        "at": 10, "agent_id": "synthetic-agent://leader",
        "principal_id": "synthetic-principal://service",
        "grant_id": "synthetic-grant://allow-write",
        "tenant": "synthetic-tenant://a", "origin": "synthetic-origin://host",
        "slot": "synthetic-slot://one", "action": "write",
        "resource": "synthetic://vault/record",
        "arguments": {"value": "approved"}, "tool_claim": "NONE",
    }
    grant = {
        "grant_id": proposal["grant_id"], "principal_id": proposal["principal_id"],
        "delegate_id": proposal["agent_id"], "tenant": proposal["tenant"],
        "origin": proposal["origin"], "slot": proposal["slot"],
        "scope": "write:synthetic://vault/record",
        "operation_digest": _operation_digest(proposal),
        "epoch": 7, "issued_at": 0, "expires_at": 100,
        "revoked_at": None, "nonce": "synthetic-nonce://one",
        "seal_valid": True,
    }
    return grant, proposal


def _cases() -> tuple[dict[str, Any], ...]:
    """Immutable authored expectation labels; not derived from gate decisions."""
    grant, proposal = _base()

    def case(name: str, accepted: tuple[str, ...] = (), *,
             changes: Mapping[str, Any] | None = None,
             grant_changes: Mapping[str, Any] | None = None,
             grants: Sequence[dict[str, Any]] | None = None,
             proposals: Sequence[dict[str, Any]] | None = None,
             state_known: bool = True, epoch: int = 7) -> dict[str, Any]:
        return {
            "case_id": name, "expected_effect_agents": list(accepted),
            "grants": [dict(grant, **dict(grant_changes or {}))] if grants is None else list(grants),
            "proposals": [dict(proposal, **dict(changes or {}))] if proposals is None else list(proposals),
            "current_epoch": epoch, "security_state_known": state_known,
        }

    def bot(index: int, **overrides: Any) -> dict[str, Any]:
        return dict(proposal, agent_id=f"synthetic-agent://bot{index:04d}", **overrides)

    swarm_forged = [bot(i, grant_id="synthetic-grant://missing") for i in range(1000)]
    swarm_one = [bot(i) for i in range(1000)]
    swarm_replays = [dict(proposal) for _ in range(1000)]
    second_proposal = dict(proposal, agent_id="synthetic-agent://runner",
                           grant_id="synthetic-grant://runner")
    second_grant = dict(grant, grant_id="synthetic-grant://runner",
                        delegate_id="synthetic-agent://runner", nonce="synthetic-nonce://two")

    return (
        case("host-approved-positive", (proposal["agent_id"],)),
        case("tool-fabricates-host-approval", changes={
            "grant_id": "synthetic-grant://missing", "tool_claim": "SYSTEM_OVERRIDE"}),
        case("vendor-output-claims-administration", changes={
            "grant_id": "synthetic-grant://missing", "tool_claim": "VENDOR_APPROVAL"}),
        case("role-escalation-with-write-grant", changes={
            "action": "assign_role", "arguments": {"role": "admin"}, "tool_claim": "GRANT_ADMIN"}),
        case("stolen-grant-cross-tenant", changes={"tenant": "synthetic-tenant://b"}),
        case("stolen-grant-wrong-delegate", changes={"agent_id": "synthetic-agent://intruder"}),
        case("operation-argument-substitution", changes={"arguments": {"value": "changed"}}),
        case("origin-substitution", changes={"origin": "synthetic-origin://tool"}),
        case("revocation-at-commit", grant_changes={"revoked_at": 10}),
        case("stale-host-epoch", epoch=8),
        case("expired-host-grant", changes={"at": 100}),
        case("unknown-host-security-state", state_known=False),
        case("invalid-host-seal", grant_changes={"seal_valid": False}),
        case("synthetic-slot-substitution", changes={"slot": "synthetic-slot://two"}),
        case("untrusted-instruction-cannot-veto-valid-grant", (proposal["agent_id"],),
             changes={"tool_claim": "IGNORE_POLICY"}),
        case("thousand-forged-agent-proposals", grants=[], proposals=swarm_forged),
        case("thousand-agents-one-delegate", ("synthetic-agent://bot0500",),
             grant_changes={"delegate_id": "synthetic-agent://bot0500"},
             proposals=swarm_one),
        case("thousand-replayed-requests", (proposal["agent_id"],),
             proposals=swarm_replays),
        case("two-host-grants-one-slot", (proposal["agent_id"],),
             grants=[grant, second_grant], proposals=[proposal, second_proposal]),
        case("forged-proposals-before-legitimate", (proposal["agent_id"],),
             proposals=[dict(proposal, grant_id="synthetic-grant://missing",
                             tool_claim="SYSTEM_OVERRIDE"), proposal]),
    )


def evaluate_challenge() -> dict[str, Any]:
    """Differentially judge the gate, independent reference, and fixed labels."""
    from .authority_reference import reference_funnel

    cases: list[dict[str, Any]] = []
    for case in _cases():
        options = {"current_epoch": case["current_epoch"],
                   "security_state_known": case["security_state_known"]}
        actual = enforce_funnel(case["grants"], case["proposals"], **options)
        reference = reference_funnel(case["grants"], case["proposals"], **options)
        expected_agents = case["expected_effect_agents"]
        observed_agents = [item["agent_id"] for item in actual["effects"]]
        reference_agents = [item["agent_id"] for item in reference["effects"]]
        matched = (expected_agents == observed_agents == reference_agents
                   and actual == reference)
        cases.append({
            "case_id": case["case_id"], "proposal_count": len(case["proposals"]),
            "expected_effect_agents": expected_agents,
            "observed_effect_agents": observed_agents,
            "reference_effect_agents": reference_agents,
            "matched": matched,
            "denials": dict(sorted(Counter(
                item["reason"] for item in actual["decisions"]
                if item["reason"] != "ACCEPTED").items())),
            "input_sha256": _sha(_json({key: value for key, value in case.items()
                                         if key != "expected_effect_agents"})),
            "observed_decisions_sha256": _sha(_json(actual)),
        })
    failures = sum(not item["matched"] for item in cases)
    return {
        "schema": SCHEMA,
        "qualification": {
            "status": "PASSED_BOUNDED" if failures == 0 else "AUTHORITY_GAP",
            "synthetic_only": True,
            "ground_truth_runtime_tested": False,
            "real_world_attacks_prevented": False,
        },
        "summary": {
            "cases": len(cases), "proposals": sum(c["proposal_count"] for c in cases),
            "positive_controls": sum(bool(c["expected_effect_agents"]) for c in cases),
            "negative_controls": sum(not c["expected_effect_agents"] for c in cases),
            "mismatches": failures,
        },
        "limitations": [
            "ARTEX-informed synthetic stressors are not reproductions of ARTEX intrusions.",
            "Tool injection is represented by inert enumerated claims; no LLM executes prompts.",
            "Host-grant seals, origin, identity, and tenant are fixture facts, not real authentication.",
            "A stolen valid grant with indistinguishable trusted context cannot be detected here.",
            "No Ground Truth runtime, cloud tenant, endpoint, credential, or real effect is accessed.",
            "Passing a finite authored corpus is not an external security certification.",
        ],
        "cases": cases,
    }


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    lines = ["# WolfTrap synthetic authority-funnel challenge", "",
             "ARTEX-informed inert host-authority controls, no live attack or GT integration.", "",
             "Status: " + report["qualification"]["status"], "",
             f"{report['summary']['cases']} controls; "
             f"{report['summary']['proposals']} proposals; "
             f"{report['summary']['mismatches']} mismatch(es).", "",
             "| Case | Proposals | Expected effects | Actual effects | Match |",
             "| --- | ---: | ---: | ---: | --- |"]
    for case in report["cases"]:
        lines.append("| " + " | ".join((
            case["case_id"], str(case["proposal_count"]),
            str(len(case["expected_effect_agents"])),
            str(len(case["observed_effect_agents"])),
            "yes" if case["matched"] else "no",
        )) + " |")
    lines.extend(["", "Limitations:", ""] +
                 ["- " + note for note in report["limitations"]] + [""])
    return {REPORT_NAME: _json(report),
            MARKDOWN_NAME: "\n".join(lines).encode("utf-8")}


def run_authority_challenge(output_dir: str | Path) -> tuple[dict[str, Any], int]:
    fd = _open_directory(Path(output_dir), create=True)
    try:
        if os.listdir(fd):
            raise ValueError("authority evidence directory must be fresh or empty")
        report = evaluate_challenge()
        artifacts = _render(report)
        for name, body in artifacts.items():
            _publish(fd, name, body)
        _publish(fd, MANIFEST_NAME, _json({
            "schema": MANIFEST_SCHEMA, "state": "COMPLETE",
            "files": {name: {"bytes": len(body), "sha256": _sha(body)}
                      for name, body in sorted(artifacts.items())},
        }))
        return report, 0 if report["summary"]["mismatches"] == 0 else 1
    finally:
        os.close(fd)


def verify_authority_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    fd = _open_directory(Path(evidence_dir))
    try:
        try:
            if set(os.listdir(fd)) != {REPORT_NAME, MARKDOWN_NAME, MANIFEST_NAME}:
                raise ValueError
            import json
            manifest = json.loads(_read_file(fd, MANIFEST_NAME, 16384))
            if (type(manifest) is not dict or set(manifest) != {"schema", "state", "files"}
                    or manifest["schema"] != MANIFEST_SCHEMA
                    or manifest["state"] != "COMPLETE"
                    or set(manifest["files"]) != {REPORT_NAME, MARKDOWN_NAME}):
                raise ValueError
            expected = evaluate_challenge()
            for name, body in _render(expected).items():
                actual = _read_file(fd, name, 256 * 1024)
                if (actual != body or manifest["files"][name] != {
                    "bytes": len(actual), "sha256": _sha(actual),
                }):
                    raise ValueError
            return expected
        except Exception:
            raise ValueError("authority-funnel evidence is inconsistent or incomplete") from None
    finally:
        os.close(fd)

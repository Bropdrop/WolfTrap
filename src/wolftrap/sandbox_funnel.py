"""Offline, synthetic sandbox-to-authority composition challenge.

No operating-system sandbox, network, filesystem capability, real model,
Ground Truth broker, or protected effect is launched or exercised here.
Host-owned sandbox envelopes and authority grants are fictional typed facts.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any

from .agent_scan import _json, _open_directory, _publish, _read_file, _sha
from .authority_funnel import _base, _enforce_funnel, validate_input
from .authority_reference import reference_funnel


SCHEMA = "wolftrap.synthetic-sandbox-authority/v1"
MANIFEST_SCHEMA = "wolftrap.synthetic-sandbox-authority-manifest/v1"
REPORT_NAME = "sandbox-authority-challenge.json"
MARKDOWN_NAME = "sandbox-authority-challenge.md"
MANIFEST_NAME = "sandbox-authority-challenge.manifest.json"
INTENTS_PER_STAGE = 1000


def _agent(index: int) -> str:
    return f"synthetic-agent://bot{index:04d}"


def _envelope(index: int, *, approved: bool = True) -> dict[str, Any]:
    return {
        "agent_id": _agent(index), "isolation_enforced": True,
        "filesystem": "SCOPED", "network": "DENIED", "approval": approved,
    }


def _request(index: int, grant_id: str, *, claim: str = "NONE") -> dict[str, Any]:
    _, base = _base()
    return dict(base, agent_id=_agent(index), grant_id=grant_id, tool_claim=claim)


def _grant(index: int, identifier: str, nonce: str, **changes: Any) -> dict[str, Any]:
    base, _ = _base()
    return dict(base, grant_id=f"synthetic-grant://{identifier}",
                delegate_id=_agent(index), nonce=f"synthetic-nonce://{nonce}", **changes)


def _intent(index: int, grant_id: str, *, file: str = "SCOPED",
            network: str = "NONE", claim: str = "NONE") -> dict[str, Any]:
    return {
        "environment_id": f"synthetic-env://bot{index:04d}",
        "file_request": file, "network_request": network,
        "proposal": _request(index, grant_id, claim=claim),
    }


def _stages() -> tuple[dict[str, Any], ...]:
    """Three independent, precisely labelled 1,000-intent fixture stages."""
    isolation_env = {
        f"synthetic-env://bot{i:04d}": _envelope(i, approved=i >= 999)
        for i in range(250, INTENTS_PER_STAGE)
    }
    isolation = [
        _intent(i, "synthetic-grant://isolation", file="OUTSIDE" if 250 <= i < 500
                else "SCOPED", network="UNLISTED" if 500 <= i < 750 else "NONE",
                claim="SYSTEM_OVERRIDE" if i < 999 else "NONE")
        for i in range(INTENTS_PER_STAGE)
    ]

    authority_env = {
        f"synthetic-env://bot{i:04d}": _envelope(i)
        for i in range(INTENTS_PER_STAGE)
    }
    authority = [
        _intent(i, "synthetic-grant://delegate", claim="VENDOR_APPROVAL" if i != 500
                else "NONE") for i in range(INTENTS_PER_STAGE)
    ]

    boundary = []
    for i in range(INTENTS_PER_STAGE):
        grant = ("stale" if i < 300 else "revoked" if i < 600 else
                 "expired" if i < 998 else "winner" if i == 998 else "contender")
        boundary.append(_intent(i, f"synthetic-grant://{grant}"))

    return (
        {
            "stage": "1-sandbox-envelopes", "envelopes": isolation_env,
            "intents": isolation, "grants": [_grant(999, "isolation", "isolation")],
            "expected_effect_agents": [_agent(999)],
            "expected_sandbox": {"UNKNOWN_SANDBOX": 250, "FILESYSTEM_DENIED": 250,
                                 "NETWORK_DENIED": 250, "APPROVAL_REQUIRED": 249,
                                 "ADMITTED": 1},
            "expected_authority": {"ACCEPTED": 1},
        },
        {
            "stage": "2-host-authority", "envelopes": authority_env,
            "intents": authority, "grants": [_grant(500, "delegate", "delegate")],
            "expected_effect_agents": [_agent(500)],
            "expected_sandbox": {"ADMITTED": INTENTS_PER_STAGE},
            "expected_authority": {"DELEGATE_MISMATCH": 999, "ACCEPTED": 1},
        },
        {
            "stage": "3-effect-boundary", "envelopes": authority_env,
            "intents": boundary,
            "grants": [
                _grant(0, "stale", "stale", epoch=6),
                _grant(300, "revoked", "revoked", revoked_at=10),
                _grant(600, "expired", "expired", expires_at=10),
                _grant(998, "winner", "winner"),
                _grant(999, "contender", "contender"),
            ],
            "expected_effect_agents": [_agent(998)],
            "expected_sandbox": {"ADMITTED": INTENTS_PER_STAGE},
            "expected_authority": {"STALE_EPOCH": 300, "REVOKED": 300,
                                   "EXPIRED_OR_NOT_YET_VALID": 398,
                                   "ACCEPTED": 1, "SLOT_EXHAUSTED": 1},
        },
    )


def _validate_stage(stage: dict[str, Any]) -> None:
    """Fail closed on malformed fixture envelopes and untrusted intents."""
    intents = stage["intents"]
    if len(intents) != INTENTS_PER_STAGE or type(stage["envelopes"]) is not dict:
        raise ValueError("invalid bounded synthetic stage")
    validate_input(stage["grants"], [item["proposal"] for item in intents],
                   current_epoch=7, security_state_known=True)
    if len(stage["envelopes"]) > INTENTS_PER_STAGE:
        raise ValueError("too many host sandbox envelopes")
    for environment_id, envelope in stage["envelopes"].items():
        if (type(environment_id) is not str or not environment_id.startswith("synthetic-env://bot")
                or len(environment_id) != len("synthetic-env://bot0000")
                or not environment_id[-4:].isdigit()
                or type(envelope) is not dict or set(envelope) != {
                    "agent_id", "isolation_enforced", "filesystem", "network", "approval",
                } or type(envelope["isolation_enforced"]) is not bool
                or type(envelope["approval"]) is not bool
                or envelope["filesystem"] not in ("SCOPED", "UNRESTRICTED")
                or envelope["network"] not in ("DENIED", "UNRESTRICTED")
                or envelope["agent_id"] != environment_id.replace(
                    "synthetic-env://", "synthetic-agent://", 1)):
            raise ValueError("invalid host-owned sandbox envelope")
    for item in intents:
        if (type(item) is not dict or set(item) != {
                "environment_id", "file_request", "network_request", "proposal"}
                or type(item["environment_id"]) is not str
                or not item["environment_id"].startswith("synthetic-env://bot")
                or len(item["environment_id"]) != len("synthetic-env://bot0000")
                or not item["environment_id"][-4:].isdigit()
                or item["file_request"] not in ("SCOPED", "OUTSIDE")
                or item["network_request"] not in ("NONE", "UNLISTED")):
            raise ValueError("invalid synthetic sandbox intent")


def _sandbox_gate(envelopes: dict[str, dict[str, Any]], intent: dict[str, Any]) -> str:
    envelope = envelopes.get(intent["environment_id"])
    if envelope is None or envelope["agent_id"] != intent["proposal"]["agent_id"]:
        return "UNKNOWN_SANDBOX"
    if not envelope["isolation_enforced"] or envelope["filesystem"] != "SCOPED" or envelope["network"] != "DENIED":
        return "UNKNOWN_ISOLATION"
    if intent["file_request"] != "SCOPED":
        return "FILESYSTEM_DENIED"
    if intent["network_request"] != "NONE":
        return "NETWORK_DENIED"
    if not envelope["approval"]:
        return "APPROVAL_REQUIRED"
    return "ADMITTED"


def evaluate_challenge() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for stage in _stages():
        _validate_stage(stage)
        admitted: list[dict[str, Any]] = []
        sandbox_decisions: list[str] = []
        for intent in stage["intents"]:
            reason = _sandbox_gate(stage["envelopes"], intent)
            sandbox_decisions.append(reason)
            if reason == "ADMITTED":
                admitted.append(intent["proposal"])

        # The observed ledger is distinct from the funnel's claimed effect list.
        ledger: list[dict[str, Any]] = []
        options = {"current_epoch": 7, "security_state_known": True}
        if admitted:
            observed = _enforce_funnel(stage["grants"], admitted,
                                       record_effect=ledger.append, **options)
            reference = reference_funnel(stage["grants"], admitted, **options)
        else:
            # A real deny-all outcome must be assessable as a failed positive
            # control; the existing funnel API requires non-empty proposals.
            observed = {"effects": [], "decisions": []}
            reference = {"effects": [], "decisions": []}
        authority_decisions = iter(observed["decisions"])
        decision_trail: list[dict[str, Any]] = []
        for intent, sandbox_reason in zip(stage["intents"], sandbox_decisions):
            authority_reason = (next(authority_decisions, {"reason": "MISSING_DECISION"})["reason"]
                                if sandbox_reason == "ADMITTED" else None)
            decision_trail.append({
                "agent_id": intent["proposal"]["agent_id"],
                "environment_id": intent["environment_id"],
                "sandbox_reason": sandbox_reason,
                "authority_reason": authority_reason,
            })
        authority_reasons = dict(Counter(row["reason"] for row in observed["decisions"]))
        sandbox_reasons = dict(Counter(sandbox_decisions))
        expected_agents = stage["expected_effect_agents"]
        passed = (
            sandbox_reasons == stage["expected_sandbox"]
            and authority_reasons == stage["expected_authority"]
            and [effect["agent_id"] for effect in ledger] == expected_agents
            and observed == reference and ledger == reference["effects"]
        )
        rows.append({
            "stage": stage["stage"], "intents": len(stage["intents"]),
            "input_sha256": _sha(_json({key: value for key, value in stage.items()
                                       if not key.startswith("expected_")})),
            "expected_sandbox": stage["expected_sandbox"],
            "observed_sandbox": sandbox_reasons,
            "expected_authority": stage["expected_authority"],
            "observed_authority": authority_reasons,
            "expected_effect_agents": expected_agents,
            "observed_effects": ledger,
            "claimed_effects": observed["effects"],
            "reference_effects": reference["effects"],
            "decisions": decision_trail,
            "decision_sha256": _sha(_json(decision_trail)),
            "passed": passed,
        })

    failures = sum(not stage["passed"] for stage in rows)
    return {
        "schema": SCHEMA,
        "qualification": {
            "status": "PASSED_BOUNDED" if failures == 0 else "CONTROL_GAP",
            "evidence_status": "SYNTHETICALLY VERIFIED" if failures == 0 else "INCONCLUSIVE",
            "real_sandbox_enforced": False,
            "ground_truth_runtime_tested": False,
            "hercules_runtime_tested": False,
            "live_agent_concurrency_tested": False,
        },
        "summary": {"stages": len(rows), "intents": sum(row["intents"] for row in rows),
                    "mismatches": failures},
        "stages": rows,
        "limitations": [
            "Sandbox envelopes are fictional host state, not OS-enforced isolation evidence.",
            "One thousand intents per stage are sequential typed records, not live AI agents.",
            "The simulated approval bit does not represent genuine human consent or authority.",
            "The synthetic grant seal and ledger are not cryptography or durable effect evidence.",
            "No tool, file read, network request, cloud account or protected effect is executed.",
            "No Ground Truth or HERCULES private implementation was exercised.",
        ],
    }


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    lines = ["# Synthetic sandbox + authority funnel", "",
             "Three distinct 1,000-intent stages. No real sandbox or live authority tested.", "",
             "Status: " + report["qualification"]["status"], "",
             "| Stage | Intents | Effect records | Match |",
             "| --- | ---: | ---: | --- |"]
    for stage in report["stages"]:
        lines.append(f"| {stage['stage']} | {stage['intents']} | "
                     f"{len(stage['observed_effects'])} | "
                     f"{'yes' if stage['passed'] else 'no'} |")
    lines.extend(["", "Limitations:", ""] +
                 ["- " + item for item in report["limitations"]] + [""])
    return {REPORT_NAME: _json(report), MARKDOWN_NAME: "\n".join(lines).encode("utf-8")}


def run_challenge(output_dir: str | Path) -> tuple[dict[str, Any], int]:
    fd = _open_directory(Path(output_dir), create=True)
    try:
        if os.listdir(fd):
            raise ValueError("sandbox-authority evidence directory must be empty")
        report = evaluate_challenge()
        artifacts = _render(report)
        for name, payload in artifacts.items():
            _publish(fd, name, payload)
        _publish(fd, MANIFEST_NAME, _json({
            "schema": MANIFEST_SCHEMA, "state": "COMPLETE",
            "files": {name: {"bytes": len(payload), "sha256": _sha(payload)}
                      for name, payload in sorted(artifacts.items())},
        }))
        return report, 0 if report["summary"]["mismatches"] == 0 else 1
    finally:
        os.close(fd)


def verify_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    fd = _open_directory(Path(evidence_dir))
    try:
        try:
            import json
            if set(os.listdir(fd)) != {REPORT_NAME, MARKDOWN_NAME, MANIFEST_NAME}:
                raise ValueError("unexpected evidence files")
            manifest = json.loads(_read_file(fd, MANIFEST_NAME, 16384))
            if (type(manifest) is not dict or set(manifest) != {"schema", "state", "files"}
                    or manifest["schema"] != MANIFEST_SCHEMA
                    or manifest["state"] != "COMPLETE"
                    or set(manifest["files"]) != {REPORT_NAME, MARKDOWN_NAME}):
                raise ValueError("invalid evidence manifest")
            expected = evaluate_challenge()
            for name, payload in _render(expected).items():
                actual = _read_file(fd, name, 2 * 1024 * 1024)
                if (actual != payload or manifest["files"].get(name) != {
                        "bytes": len(actual), "sha256": _sha(actual)}):
                    raise ValueError("evidence replay mismatch")
            return expected
        except Exception:
            raise ValueError("sandbox-authority evidence incomplete or inconsistent") from None
    finally:
        os.close(fd)

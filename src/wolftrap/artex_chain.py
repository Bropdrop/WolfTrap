"""Inert ARTEX-inspired multi-step authority-boundary challenge.

All actors, resources, grants and effects are fictional typed records. This
module does not execute scanners, subprocesses, network requests, AI models,
privilege changes, Ground Truth, or HERCULES.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from .agent_scan import _json, _open_directory, _publish, _read_file, _sha
from .artex_chain_reference import reference_chain


SCHEMA = "wolftrap.synthetic-artex-chain/v1"
MANIFEST_SCHEMA = "wolftrap.synthetic-artex-chain-manifest/v1"
REPORT_NAME = "artex-chain-challenge.json"
MARKDOWN_NAME = "artex-chain-challenge.md"
MANIFEST_NAME = "artex-chain-challenge.manifest.json"
STEPS = ("RECON", "ACCESS", "PRIVILEGE", "COMMIT")
RESOURCES = (
    "synthetic://lab/public-index", "synthetic://lab/record",
    "synthetic://lab/role-viewer", "synthetic://lab/approved-change",
)
MODES = ("catalog", "read", "viewer", "approved")
AGENT = "synthetic-agent://worker"
INTRUDER = "synthetic-agent://intruder"
TENANT = "synthetic-tenant://primary"
CHAIN = "synthetic-chain://case"
ENVIRONMENT = "synthetic-env://worker"


def _fingerprint(intent: dict[str, Any]) -> str:
    payload = json.dumps({
        "action": intent["step"], "resource": intent["resource"],
        "arguments": intent["arguments"],
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _fixture() -> dict[str, Any]:
    intents = []
    grants = []
    for index, (step, resource, mode) in enumerate(zip(STEPS, RESOURCES, MODES)):
        intent = {
            "at": 10 + index, "step": step,
            "environment_id": ENVIRONMENT, "chain_id": CHAIN,
            "agent_id": AGENT, "tenant": TENANT,
            "grant_id": f"synthetic-grant://step{index}",
            "resource": resource, "arguments": {"mode": mode},
            "file_request": "SCOPED", "network_request": "NONE",
            "tool_claim": "NONE",
        }
        grants.append({
            "grant_id": intent["grant_id"], "chain_id": CHAIN,
            "delegate_id": AGENT, "tenant": TENANT, "scope": f"{step}:{resource}",
            "operation_digest": _fingerprint(intent),
            "epoch": 9, "issued_at": 0, "expires_at": 100,
            "revoked_at": None, "nonce": f"synthetic-nonce://step{index}",
            "seal_valid": True, "approved": True,
        })
        intents.append(intent)
    return {
        "case_id": "legitimate-four-step-chain",
        "host": {
            "current_epoch": 9, "security_state_known": True,
            "envelopes": {
                ENVIRONMENT: {"agent_id": AGENT, "isolation_enforced": True,
                              "filesystem": "SCOPED", "network": "DENIED"},
                "synthetic-env://intruder": {
                    "agent_id": INTRUDER, "isolation_enforced": True,
                    "filesystem": "SCOPED", "network": "DENIED",
                },
            },
        },
        "grants": grants, "intents": intents,
        "expected_reasons": ["ACCEPTED"] * len(STEPS),
        "expected_effects": 1,
    }


def _cases() -> tuple[dict[str, Any], ...]:
    """Author-fixed labels are intentionally independent from both evaluators."""
    cases = [_fixture()]

    def adversary(name: str, index: int, **changes: Any) -> dict[str, Any]:
        item = copy.deepcopy(cases[0])
        item["case_id"] = name
        item["intents"][index].update(changes)
        item["expected_reasons"] = ["ACCEPTED"] * index + ["DENIED"] + [
            "CHAIN_HALTED"
        ] * (len(item["intents"]) - index - 1)
        item["expected_effects"] = 0
        return item

    case = adversary("out-of-scope-recon", 0, network_request="UNLISTED")
    case["expected_reasons"][0] = "NETWORK_DENIED"
    cases.append(case)

    case = adversary("out-of-scope-filesystem", 0, file_request="OUTSIDE")
    case["expected_reasons"][0] = "FILESYSTEM_DENIED"
    cases.append(case)

    case = adversary("unauthorized-privilege-escalation", 2,
                     resource="synthetic://lab/role-admin")
    case["expected_reasons"][2] = "SCOPE_MISMATCH"
    cases.append(case)

    case = adversary("forged-approval-from-tool-output", 1,
                     grant_id="synthetic-grant://forged", tool_claim="VENDOR_APPROVAL")
    case["expected_reasons"][1] = "UNKNOWN_GRANT"
    cases.append(case)

    case = adversary("host-denied-approval", 1, tool_claim="SYSTEM_OVERRIDE")
    case["grants"][1]["approved"] = False
    case["expected_reasons"][1] = "APPROVAL_REQUIRED"
    cases.append(case)

    case = adversary("revoked-after-preparation", 3)
    case["grants"][3]["revoked_at"] = 13
    case["expected_reasons"][3] = "REVOKED"
    cases.append(case)

    case = adversary("expired-at-final-effect", 3)
    case["grants"][3]["expires_at"] = 13
    case["expected_reasons"][3] = "EXPIRED"
    cases.append(case)

    case = adversary("stale-epoch-at-final-effect", 3)
    case["grants"][3]["epoch"] = 8
    case["expected_reasons"][3] = "STALE_EPOCH"
    cases.append(case)

    case = adversary("cross-tenant-chain-splice", 2,
                     tenant="synthetic-tenant://foreign")
    case["expected_reasons"][2] = "TENANT_MISMATCH"
    cases.append(case)

    case = adversary("cross-agent-chain-splice", 2, agent_id=INTRUDER,
                     environment_id="synthetic-env://intruder")
    case["expected_reasons"][2] = "DELEGATE_MISMATCH"
    cases.append(case)

    case = adversary("valid-foreign-grant-cannot-splice-chain", 2,
                     agent_id=INTRUDER, environment_id="synthetic-env://intruder",
                     chain_id="synthetic-chain://foreign", tenant="synthetic-tenant://foreign",
                     grant_id="synthetic-grant://foreign")
    case["grants"].append(dict(case["grants"][2],
                               grant_id="synthetic-grant://foreign",
                               nonce="synthetic-nonce://foreign",
                               chain_id="synthetic-chain://foreign",
                               delegate_id=INTRUDER, tenant="synthetic-tenant://foreign"))
    case["expected_reasons"][2] = "CHAIN_IDENTITY_MISMATCH"
    cases.append(case)

    case = adversary("changed-operation-at-commit", 3, arguments={"mode": "tampered"})
    case["expected_reasons"][3] = "OPERATION_MISMATCH"
    cases.append(case)

    case = adversary("missing-isolation-is-denial", 0)
    case["host"]["envelopes"][ENVIRONMENT]["isolation_enforced"] = False
    case["expected_reasons"][0] = "UNKNOWN_ISOLATION"
    cases.append(case)

    case = adversary("unknown-host-authority-is-denial", 0)
    case["host"]["security_state_known"] = False
    case["expected_reasons"][0] = "UNKNOWN_AUTHORITY_STATE"
    cases.append(case)

    case = adversary("duplicate-first-step-halts-chain", 1)
    case["intents"].insert(1, dict(case["intents"][0]))
    case["expected_reasons"] = ["ACCEPTED", "CHAIN_ORDER_DENIED"] + [
        "CHAIN_HALTED"
    ] * 3
    cases.append(case)
    return tuple(cases)


def _alias(value: Any, kind: str) -> bool:
    return type(value) is str and re.fullmatch(
        rf"synthetic-{kind}://[a-z0-9_-]{{1,40}}", value,
    ) is not None


def _tick(value: Any) -> bool:
    return type(value) is int and 0 <= value <= 10_000


def _validate_case(case: dict[str, Any]) -> None:
    if type(case) is not dict or set(case) != {
        "case_id", "host", "grants", "intents", "expected_reasons", "expected_effects",
    } or not re.fullmatch(r"[a-z0-9-]{1,60}", str(case["case_id"])):
        raise ValueError("invalid synthetic chain case")
    host = case["host"]
    if type(host) is not dict or set(host) != {
        "current_epoch", "security_state_known", "envelopes",
    } or not _tick(host["current_epoch"]) or type(host["security_state_known"]) is not bool:
        raise ValueError("invalid host authority state")
    envelopes = host["envelopes"]
    if type(envelopes) is not dict or len(envelopes) > 4:
        raise ValueError("invalid host envelopes")
    for key, envelope in envelopes.items():
        if (not _alias(key, "env") or type(envelope) is not dict
                or set(envelope) != {"agent_id", "isolation_enforced", "filesystem", "network"}
                or not _alias(envelope["agent_id"], "agent")
                or type(envelope["isolation_enforced"]) is not bool
                or envelope["filesystem"] != "SCOPED" or envelope["network"] != "DENIED"):
            raise ValueError("invalid synthetic host envelope")
    grants = case["grants"]
    intents = case["intents"]
    if (type(grants) is not list or not 1 <= len(grants) <= 8
            or type(intents) is not list or not 4 <= len(intents) <= 5
            or type(case["expected_reasons"]) is not list
            or len(case["expected_reasons"]) != len(intents)
            or not all(type(item) is str and re.fullmatch(r"[A-Z_]{1,35}", item)
                       for item in case["expected_reasons"])
            or type(case["expected_effects"]) is not int
            or case["expected_effects"] not in (0, 1)):
        raise ValueError("invalid synthetic chain bounds")
    ids: set[str] = set()
    nonces: set[str] = set()
    for grant in grants:
        if (type(grant) is not dict or set(grant) != {
                "grant_id", "chain_id", "delegate_id", "tenant", "scope",
                "operation_digest", "epoch", "issued_at", "expires_at", "revoked_at",
                "nonce", "seal_valid", "approved",
        } or not _alias(grant["grant_id"], "grant")
                or not _alias(grant["chain_id"], "chain")
                or not _alias(grant["delegate_id"], "agent")
                or not _alias(grant["tenant"], "tenant")
                or not _alias(grant["nonce"], "nonce")
                or grant["grant_id"] in ids or grant["nonce"] in nonces
                or type(grant["scope"]) is not str
                or not re.fullmatch(r"(RECON|ACCESS|PRIVILEGE|COMMIT):synthetic://lab/[a-z0-9_-]{1,40}",
                                    grant["scope"])
                or type(grant["operation_digest"]) is not str
                or not re.fullmatch(r"sha256:[0-9a-f]{64}", grant["operation_digest"])
                or any(not _tick(grant[key]) for key in ("epoch", "issued_at", "expires_at"))
                or grant["issued_at"] >= grant["expires_at"]
                or (grant["revoked_at"] is not None and not _tick(grant["revoked_at"]))
                or type(grant["seal_valid"]) is not bool
                or type(grant["approved"]) is not bool):
            raise ValueError("invalid host grant")
        ids.add(grant["grant_id"])
        nonces.add(grant["nonce"])
    previous = -1
    for intent in intents:
        if (type(intent) is not dict or set(intent) != {
                "at", "step", "environment_id", "chain_id", "agent_id", "tenant",
                "grant_id", "resource", "arguments", "file_request",
                "network_request", "tool_claim",
        } or not _tick(intent["at"]) or intent["at"] < previous
                or intent["step"] not in STEPS
                or not _alias(intent["environment_id"], "env")
                or not _alias(intent["chain_id"], "chain")
                or not _alias(intent["agent_id"], "agent")
                or not _alias(intent["tenant"], "tenant")
                or not _alias(intent["grant_id"], "grant")
                or type(intent["resource"]) is not str
                or not re.fullmatch(r"synthetic://lab/[a-z0-9_-]{1,40}", intent["resource"])
                or type(intent["arguments"]) is not dict
                or set(intent["arguments"]) != {"mode"}
                or type(intent["arguments"]["mode"]) is not str
                or not re.fullmatch(r"[a-z0-9_-]{1,40}", intent["arguments"]["mode"])
                or intent["file_request"] not in ("SCOPED", "OUTSIDE")
                or intent["network_request"] not in ("NONE", "UNLISTED")
                or intent["tool_claim"] not in ("NONE", "VENDOR_APPROVAL", "SYSTEM_OVERRIDE")):
            raise ValueError("invalid inert chain intent")
        previous = intent["at"]


def _sandbox_gate(envelopes: dict[str, dict[str, Any]], intent: dict[str, Any]) -> str:
    envelope = envelopes.get(intent["environment_id"])
    if envelope is None or envelope["agent_id"] != intent["agent_id"]:
        return "UNKNOWN_SANDBOX"
    if not envelope["isolation_enforced"]:
        return "UNKNOWN_ISOLATION"
    if intent["file_request"] != "SCOPED":
        return "FILESYSTEM_DENIED"
    if intent["network_request"] != "NONE":
        return "NETWORK_DENIED"
    return "ADMITTED"


def _authorize(grant: dict[str, Any] | None, intent: dict[str, Any],
               host: dict[str, Any], consumed: set[str]) -> str:
    if not host["security_state_known"]:
        return "UNKNOWN_AUTHORITY_STATE"
    if grant is None:
        return "UNKNOWN_GRANT"
    if not grant["seal_valid"]:
        return "UNVERIFIED_GRANT"
    if grant["epoch"] != host["current_epoch"]:
        return "STALE_EPOCH"
    if grant["revoked_at"] is not None and intent["at"] >= grant["revoked_at"]:
        return "REVOKED"
    if not grant["issued_at"] <= intent["at"] < grant["expires_at"]:
        return "EXPIRED"
    if grant["chain_id"] != intent["chain_id"]:
        return "CHAIN_MISMATCH"
    if grant["delegate_id"] != intent["agent_id"]:
        return "DELEGATE_MISMATCH"
    if grant["tenant"] != intent["tenant"]:
        return "TENANT_MISMATCH"
    if grant["scope"] != f"{intent['step']}:{intent['resource']}":
        return "SCOPE_MISMATCH"
    if grant["operation_digest"] != _fingerprint(intent):
        return "OPERATION_MISMATCH"
    if not grant["approved"]:
        return "APPROVAL_REQUIRED"
    if grant["nonce"] in consumed:
        return "REPLAY"
    return "ACCEPTED"


def _enforce_chain(case: dict[str, Any], *,
                   record_effect: Callable[[dict[str, Any]], None] | None = None,
                   ) -> dict[str, Any]:
    """Inert sequential enforcement; tool claims never mint host permission."""
    host = case["host"]
    grants = {grant["grant_id"]: grant for grant in case["grants"]}
    consumed: set[str] = set()
    decisions: list[dict[str, Any]] = []
    claimed_effects: list[dict[str, Any]] = []
    next_step = 0
    halted = False
    pinned_identity: tuple[str, str, str] | None = None
    for intent in case["intents"]:
        if halted:
            reason = "CHAIN_HALTED"
        elif next_step >= len(STEPS) or intent["step"] != STEPS[next_step]:
            reason = "CHAIN_ORDER_DENIED"
        else:
            reason = _sandbox_gate(host["envelopes"], intent)
            if reason == "ADMITTED":
                reason = _authorize(grants.get(intent["grant_id"]), intent,
                                    host, consumed)
            if reason == "ACCEPTED" and pinned_identity is not None and (
                intent["chain_id"], intent["agent_id"], intent["tenant"]
            ) != pinned_identity:
                reason = "CHAIN_IDENTITY_MISMATCH"
        if reason != "ACCEPTED":
            halted = True
        else:
            consumed.add(grants[intent["grant_id"]]["nonce"])
            if pinned_identity is None:
                pinned_identity = (intent["chain_id"], intent["agent_id"], intent["tenant"])
            next_step += 1
            if next_step == len(STEPS):
                effect = {
                    "chain_id": intent["chain_id"], "agent_id": intent["agent_id"],
                    "at": intent["at"], "resource": intent["resource"],
                    "grant_id": intent["grant_id"],
                    "operation_digest": _fingerprint(intent),
                }
                if record_effect is not None:
                    record_effect(dict(effect))
                claimed_effects.append(effect)
        decisions.append({
            "step": intent["step"], "at": intent["at"],
            "agent_id": intent["agent_id"], "reason": reason,
        })
    return {"decisions": decisions, "effects": claimed_effects}


def evaluate_challenge() -> dict[str, Any]:
    rows = []
    for case in _cases():
        _validate_case(case)
        observed_effects: list[dict[str, Any]] = []
        observed = _enforce_chain(case, record_effect=observed_effects.append)
        reference = reference_chain(case)
        observed_reasons = [item["reason"] for item in observed["decisions"]]
        passed = (observed == reference
                  and observed_reasons == case["expected_reasons"]
                  and len(observed_effects) == case["expected_effects"]
                  and observed_effects == observed["effects"] == reference["effects"])
        rows.append({
            "case_id": case["case_id"], "attempts": len(case["intents"]),
            "input_sha256": _sha(_json({key: value for key, value in case.items()
                                       if not key.startswith("expected_")})),
            "expected_reasons": case["expected_reasons"],
            "observed_reasons": observed_reasons,
            "decisions": observed["decisions"],
            "expected_effects": case["expected_effects"],
            "observed_effects": observed_effects,
            "claimed_effects": observed["effects"],
            "reference_effects": reference["effects"],
            "passed": passed,
        })
    failures = sum(not row["passed"] for row in rows)
    return {
        "schema": SCHEMA,
        "qualification": {
            "status": "PASSED_BOUNDED" if failures == 0 else "CONTROL_GAP",
            "evidence_status": "SYNTHETICALLY VERIFIED" if failures == 0 else "INCONCLUSIVE",
            "real_network_scanning": False, "real_sandbox_enforced": False,
            "ground_truth_runtime_tested": False, "hercules_runtime_tested": False,
            "live_artex_tested": False,
        },
        "summary": {"cases": len(rows), "attempts": sum(row["attempts"] for row in rows),
                    "effect_records": sum(len(row["observed_effects"]) for row in rows),
                    "mismatches": failures,
                    "denials": dict(sorted(Counter(reason for row in rows
                                                   for reason in row["observed_reasons"]
                                                   if reason != "ACCEPTED").items()))},
        "cases": rows,
        "limitations": [
            "All hosts, assets, roles, agents and effect records are fictional typed fixtures.",
            "No scanner, subprocess, network, file access, real permission or privilege change runs.",
            "A static host approval flag is not a real user approval or cryptographic credential.",
            "Logical time and revocation are simulated; no restart or distributed race is exercised.",
            "The independent effect sink is in-memory, not durable production evidence.",
            "Evidence replay checks deterministic files, not authentic third-party attestations.",
            "No ARTEX, HERCULES or Ground Truth live integration was tested.",
        ],
    }


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    lines = ["# ARTEX-inspired synthetic adversarial chain", "",
             "Fictional targets only; no real scans, sandbox, AI or protected effects.", "",
             "Status: " + report["qualification"]["status"], "",
             "| Case | Attempts | Effect records | Match |",
             "| --- | ---: | ---: | --- |"]
    for case in report["cases"]:
        lines.append(f"| {case['case_id']} | {case['attempts']} | "
                     f"{len(case['observed_effects'])} | "
                     f"{'yes' if case['passed'] else 'no'} |")
    lines.extend(["", "Limitations:", ""] + ["- " + limit for limit in report["limitations"]]
                 + [""])
    return {REPORT_NAME: _json(report), MARKDOWN_NAME: "\n".join(lines).encode("utf-8")}


def run_challenge(directory: str | Path) -> tuple[dict[str, Any], int]:
    fd = _open_directory(Path(directory), create=True)
    try:
        if os.listdir(fd):
            raise ValueError("ARTEX-chain evidence directory must be empty")
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


def verify_evidence(directory: str | Path) -> dict[str, Any]:
    fd = _open_directory(Path(directory))
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
                raise ValueError("invalid ARTEX-chain evidence manifest")
            report = evaluate_challenge()
            for name, content in _render(report).items():
                actual = _read_file(fd, name, 2 * 1024 * 1024)
                if (actual != content or manifest["files"].get(name) != {
                        "bytes": len(actual), "sha256": _sha(actual)}):
                    raise ValueError("inconsistent ARTEX-chain evidence")
            return report
        except Exception:
            raise ValueError("ARTEX-chain evidence incomplete or inconsistent") from None
    finally:
        os.close(fd)

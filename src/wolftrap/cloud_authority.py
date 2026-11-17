"""Offline authority isolation after an untrusted cloud-event advisory.

This exercises WolfTrap's *synthetic* GT-inspired authority engine and its
independent effect oracle. It neither imports nor calls Ground Truth runtime,
and is not an authorization adapter for a real cloud service or vehicle.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .agent_scan import _json, _open_directory, _publish, _read_file, _sha
from .cloud_camouflage import _cases as camouflage_cases
from .cloud_trace import inspect_trace
from .execution import execute_case
from .model import (AttackReference, Authorization, Command, CommandKind,
                    ExperimentCase, Operation, Principal, RequestSpec,
                    ThreatSource)


SCHEMA = "wolftrap.cloud-authority-challenge/v1"
MANIFEST_SCHEMA = "wolftrap.cloud-authority-manifest/v1"
REPORT_NAME = "cloud-authority-challenge.json"
MARKDOWN_NAME = "cloud-authority-challenge.md"
MANIFEST_NAME = "cloud-authority-challenge.manifest.json"

RESOURCE = "synthetic://cloud/protected-report"
TRUSTED_ORIGIN = "synthetic-origin://independent-owner"
UNTRUSTED_ORIGIN = "synthetic-origin://github-event"
INVARIANTS = (
    "NO_CURRENT_AUTHORITY_NO_PROTECTED_EFFECT",
    "NO_VALID_ORIGIN_BINDING_NO_PROTECTED_EFFECT",
    "REVOKED_AUTHORITY_NO_NEW_PROTECTED_EFFECT",
    "REPLAYED_AUTHORIZATION_NO_DUPLICATE_EFFECT",
    "VERIFIED_DOES_NOT_MEAN_AUTHORIZED",
    "AUTHORIZED_DOES_NOT_MEAN_EXECUTED",
    "UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
    "POSITIVE_CONTROL_MUST_EXECUTE",
)

# Each tuple is (axis, expected number of independently recorded effects,
# expected denial reason). These expectations are not derived from the SUT.
AXES = (
    ("valid-independent-grant", 1, None),
    ("invalid-signature", 0, "UNVERIFIED_CREDENTIAL"),
    ("foreign-cloud-origin", 0, "ORIGIN_MISMATCH"),
    ("scope-mismatch", 0, "SCOPE_MISMATCH"),
    ("operation-digest-splice", 0, "OPERATION_DIGEST_MISMATCH"),
    ("stale-authority-epoch", 0, "STALE_EPOCH"),
    ("revoked-grant", 0, "REVOKED"),
    ("revoked-after-authorization", 0, "REVOKED"),
    ("revoked-after-preparation", 0, "REVOKED"),
    ("unknown-security-state", 0, "UNKNOWN_SECURITY_STATE"),
    ("credential-substitution", 0, "CREDENTIAL_SUBSTITUTION"),
    ("replayed-grant", 1, "REPLAY"),
)


def _fixture(cloud_case: dict[str, Any], axis: str) -> ExperimentCase:
    """Create independent authority fixtures; cloud verdicts never enter them."""
    trace_digest = _sha(_json(cloud_case["events"]))
    operation = Operation(
        operation_id="publish-report", action="publish", resource=RESOURCE,
        arguments={"trace_sha256": trace_digest}, protected=True,
    )
    changes: dict[str, Any] = {}
    if axis == "invalid-signature":
        changes["signature_valid"] = False
    elif axis == "scope-mismatch":
        changes["scopes"] = (f"read:{RESOURCE}",)
    elif axis == "operation-digest-splice":
        changes["operation_digest"] = "sha256:" + "0" * 64
    elif axis == "stale-authority-epoch":
        changes["epoch"] = 0
    auth = Authorization(
        authorization_id="owner-grant", subject="owner",
        scopes=changes.get("scopes", (f"publish:{RESOURCE}",)),
        epoch=changes.get("epoch", 1), origin_binding=TRUSTED_ORIGIN,
        operation_digest=changes.get("operation_digest", operation.digest),
        issued_at=0, expires_at=100, signature_valid=changes.get("signature_valid", True),
        nonce="owner-grant-nonce",
    )
    request = RequestSpec(
        request_id="attempt", principal_id="owner", authorization_id="owner-grant",
        operation_id="publish-report",
        origin=UNTRUSTED_ORIGIN if axis == "foreign-cloud-origin" else TRUSTED_ORIGIN,
        credential_overrides={"nonce": "substituted-nonce"}
        if axis == "credential-substitution" else {},
    )
    commands: list[Command] = []
    if axis == "revoked-grant":
        commands.append(Command(CommandKind.REVOKE, at=9, authorization_id="owner-grant"))
    commands.append(Command(CommandKind.SUBMIT, at=10,
                            task_id="first-task", request_id="attempt"))
    if axis in {"revoked-after-authorization", "revoked-after-preparation"}:
        advances_before = 2 if axis == "revoked-after-authorization" else 4
        commands.extend(Command(CommandKind.ADVANCE, at=10, task_id="first-task")
                        for _ in range(advances_before))
        commands.append(Command(CommandKind.REVOKE, at=11,
                                authorization_id="owner-grant"))
        commands.extend(Command(CommandKind.ADVANCE, at=11, task_id="first-task")
                        for _ in range(7 - advances_before))
    else:
        commands.extend(Command(CommandKind.ADVANCE, at=10, task_id="first-task")
                        for _ in range(7))
    if axis == "replayed-grant":
        commands.append(Command(CommandKind.SUBMIT, at=11,
                                task_id="replay-task", request_id="attempt"))
        commands.extend(Command(CommandKind.ADVANCE, at=11, task_id="replay-task")
                        for _ in range(7))
    source = ThreatSource(
        source_id="WOLFTRAP-OFFLINE-CLOUD-AUTHORITY",
        title="WolfTrap authored cloud authority controls",
        publication_date="2026-11-17",
        url="https://github.com/GovernableIntelligence/WolfTrap",
        sha256=_sha(b"WolfTrap synthetic cloud authority fixture v1"),
        pages=(), observed_behavior="None; these are authored fictional events.",
        mapping_note="Synthetic independent authority checks, not live GT integration.",
    )
    case = ExperimentCase(
        case_id="pending", case_seed=20261117, generator_version="cloud-authority-v1",
        scenario_ids=("wolftrap-synthetic-cloud-authority",),
        scenario_versions=("1.0.0",),
        title=f"Cloud advisory cannot grant authority: {axis}",
        category="synthetic_cloud_authority",
        sources=(source,),
        attack_references=(AttackReference(
            technique_id="SYNTHETIC-CLOUD-BOUNDARY", name="Authored authority gate",
            url="https://github.com/GovernableIntelligence/WolfTrap",
            relationship="SYNTHETIC"),),
        current_epoch=1,
        security_state_known=axis != "unknown-security-state",
        principals=(Principal("owner"),), authorizations=(auth,),
        operations=(operation,), requests=(request,), commands=tuple(commands),
        control="MIXED" if axis == "replayed-grant" else
                "POSITIVE" if axis == "valid-independent-grant" else "NEGATIVE",
        invariants=INVARIANTS,
        mutation_labels=(axis, cloud_case["group"]), interaction_depth=1,
    )
    return case.with_identity()


def evaluate_cloud_authority() -> dict[str, Any]:
    """Cross the 160 authored cloud traces with eleven separate authority axes."""
    mismatch_count = oracle_failures = flagged = unflagged = 0
    records: list[dict[str, Any]] = []
    by_axis: dict[str, dict[str, int]] = {
        axis: {"cases": 0, "effects": 0, "mismatches": 0}
        for axis, _, _ in AXES
    }
    for cloud_case in camouflage_cases():
        advisory = bool(inspect_trace(cloud_case["events"]))
        flagged += advisory
        unflagged += not advisory
        for axis, expected_effects, expected_denial in AXES:
            execution = execute_case(_fixture(cloud_case, axis))
            observed_effects = len(execution.final_state["effects"])
            actual_denials = sorted({task["denial_reason"]
                                     for task in execution.final_state["tasks"]
                                     if task["denial_reason"] != "NONE"})
            expected_denials = [expected_denial] if expected_denial else []
            correct = (execution.assessment.passed
                       and observed_effects == expected_effects
                       and actual_denials == expected_denials)
            mismatch_count += not correct
            oracle_failures += not execution.assessment.passed
            by_axis[axis]["cases"] += 1
            by_axis[axis]["effects"] += observed_effects
            by_axis[axis]["mismatches"] += not correct
            records.append({
                "cloud_case_id": cloud_case["case_id"],
                "cloud_group": cloud_case["group"],
                "advisory_flagged": advisory,
                "authority_axis": axis, "case_digest": execution.case.digest,
                "expected_effects": expected_effects,
                "observed_effects": observed_effects,
                "expected_denials": expected_denials, "actual_denials": actual_denials,
                "oracle_passed": execution.assessment.passed,
            })
    result = {
        "schema": SCHEMA,
        "qualification": {
            "status": "PASSED_BOUNDED" if not mismatch_count else "AUTHORITY_GAP",
            "real_ground_truth_runtime_connected": False,
            "real_world_malware_detected": False,
            "artex_intrusion_detected": False,
            "artex_intrusion_testing_performed": False,
            "production_authority_proven": False,
        },
        "source_modified": False, "network_contacted": False,
        "model_used": False, "external_code_executed": False,
        "summary": {
            "cloud_traces": flagged + unflagged,
            "cloud_advisories_flagged": flagged,
            "cloud_advisories_unflagged": unflagged,
            "authority_checks": len(records),
            "mismatches": mismatch_count, "oracle_failures": oracle_failures,
            "synthetic_protected_effects": sum(row["observed_effects"] for row in records),
        },
        "authority_axes": [dict(axis=axis, **by_axis[axis]) for axis, _, _ in AXES],
        "evidence_digest": _sha(_json(records)),
        "limitations": [
            "Only WolfTrap's synthetic authority engine and independent local oracle were exercised.",
            "Ground Truth, HERCULES, MobiPute, GitHub and vehicle runtimes were not connected.",
            "The event detector's advisory is never a grant, revocation or protected-effect instruction.",
            "The harness provisions fictional trusted grants; signatures and provenance are not cryptographically authenticated.",
            "A compromised process possessing valid current authority remains an unresolved real-world risk.",
            "ARTEX-relevant synthetic security failures are not evidence of detection of an actual ARTEX intrusion.",
            "Synthetic test success is not deployment qualification or production authorization evidence.",
        ],
    }
    return result


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    stats = report["summary"]
    lines = ["# WolfTrap synthetic cloud-authority boundary challenge", "",
             "Independent synthetic effect ledger, not a deployed Ground Truth broker.", "",
             "Status: " + report["qualification"]["status"], "",
             f"Cloud traces: {stats['cloud_traces']}; authority checks: {stats['authority_checks']}",
             f"Oracle failures: {stats['oracle_failures']}; expectation mismatches: {stats['mismatches']}",
             "", "| Authority axis | Checks | Effects | Mismatches |",
             "| --- | ---: | ---: | ---: |"]
    for axis in report["authority_axes"]:
        lines.append(f"| {axis['axis']} | {axis['cases']} | {axis['effects']} | {axis['mismatches']} |")
    lines.extend(["", "Limitations:", ""] +
                 ["- " + item for item in report["limitations"]] + [""])
    return {REPORT_NAME: _json(report), MARKDOWN_NAME: ("\n".join(lines)).encode()}


def run_cloud_authority(output_dir: str | Path) -> tuple[dict[str, Any], int]:
    """Save deterministic challenge evidence into a fresh local directory."""
    fd = _open_directory(Path(output_dir), create=True)
    try:
        if os.listdir(fd):
            raise ValueError("authority evidence directory must be fresh or empty")
        report = evaluate_cloud_authority()
        artifacts = _render(report)
        for name, content in artifacts.items():
            _publish(fd, name, content)
        _publish(fd, MANIFEST_NAME, _json({
            "schema": MANIFEST_SCHEMA, "state": "COMPLETE",
            "files": {name: {"bytes": len(raw), "sha256": _sha(raw)}
                      for name, raw in sorted(artifacts.items())},
        }))
        return report, 0 if report["summary"]["mismatches"] == 0 else 1
    finally:
        os.close(fd)


def verify_cloud_authority(evidence_dir: str | Path) -> dict[str, Any]:
    """Reject altered artifacts by regenerating the corpus and independent oracle."""
    fd = _open_directory(Path(evidence_dir))
    try:
        try:
            manifest = json.loads(_read_file(fd, MANIFEST_NAME, 16384))
            if (manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("state") != "COMPLETE"
                    or set(manifest.get("files", {})) != {REPORT_NAME, MARKDOWN_NAME}):
                raise ValueError
            report = evaluate_cloud_authority()
            for name, expected in _render(report).items():
                actual = _read_file(fd, name, 128 * 1024)
                if actual != expected or manifest["files"][name] != {
                        "bytes": len(actual), "sha256": _sha(actual)}:
                    raise ValueError
            return report
        except Exception:
            raise ValueError("authority evidence is incomplete or inconsistent") from None
    finally:
        os.close(fd)

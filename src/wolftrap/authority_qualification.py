"""Qualify synthetic authority controls against independent effect records."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from .agent_scan import _json, _open_directory, _publish, _read_file, _sha
from .authority_funnel import _base, _cases, _enforce_funnel
from .authority_reference import reference_funnel
from .execution import execute_case
from .model import Command, CommandKind, ExperimentCase, scenario_to_case
from .revision import _git, repository_root
from .scenario import load_corpus
from .system import (
    CorrectSyntheticSystem,
    DenyAllSyntheticSystem,
    FinalRecheckDefectiveSyntheticSystem,
    ReplayDefectiveSyntheticSystem,
)


SCHEMA = "wolftrap.synthetic-authority-qualification/v1"
MANIFEST_SCHEMA = "wolftrap.synthetic-authority-qualification-manifest/v1"
INPUTS_NAME = "authority-qualification-inputs.json"
REPORT_NAME = "authority-qualification.json"
MANIFEST_NAME = "authority-qualification.manifest.json"
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
PHASE_CONTROLS = {
    "fbi-artex-positive-authorized-operation": ("task-positive",),
    "fbi-artex-revocation-expiry": (),
    "fbi-artex-concurrent-agents": ("agent-a",),
    "fbi-artex-replay-duplicate": ("first-attempt",),
    "fbi-artex-delayed-crash-recovery": ("task-crash-before-recovered", "task-crash-after"),
}
POST_PREPARE_REJECTIONS = {
    "expiry-after-preparation": "EXPIRED",
    "epoch-advance-after-preparation": "STALE_EPOCH",
    "unknown-state-after-preparation": "UNKNOWN_SECURITY_STATE",
}


def _coordinated_proposals() -> dict[str, Any]:
    grant, proposal = _base()
    runner = dict(proposal, agent_id="synthetic-agent://runner",
                  grant_id="synthetic-grant://runner", tool_claim="VENDOR_APPROVAL")
    competing_grant = dict(grant, grant_id=runner["grant_id"],
                           delegate_id=runner["agent_id"], nonce="synthetic-nonce://runner")
    untrusted_variants = (
        {"grant_id": "synthetic-grant://missing", "tool_claim": "SYSTEM_OVERRIDE"},
        {"tenant": "synthetic-tenant://other", "tool_claim": "VENDOR_APPROVAL"},
        {"origin": "synthetic-origin://other", "tool_claim": "IGNORE_POLICY"},
        {"arguments": {"value": "changed"}, "tool_claim": "GRANT_ADMIN"},
        {"slot": "synthetic-slot://other", "tool_claim": "VENDOR_APPROVAL"},
        {"action": "assign_role", "arguments": {"role": "synthetic-elevated"},
         "tool_claim": "GRANT_ADMIN"},
    )
    proposals = [
        dict(proposal, **untrusted_variants[index % len(untrusted_variants)])
        for index in range(996)
    ]
    proposals.extend((
        dict(proposal, agent_id="synthetic-agent://other"),
        dict(proposal, tool_claim="IGNORE_POLICY"),
        runner,
        dict(proposal, tool_claim="VENDOR_APPROVAL"),
    ))
    return {
        "case_id": "coordinated-thousand-proposals-one-slot",
        "expected_effect_agents": [proposal["agent_id"]],
        "grants": [grant, competing_grant],
        "proposals": proposals,
        "current_epoch": 7,
        "security_state_known": True,
    }


def _funnel_witness(case: dict[str, Any], *, defect: str | None = None) -> dict[str, Any]:
    grants = case["grants"]
    proposals = case["proposals"]
    options = {name: case[name] for name in ("current_epoch", "security_state_known")}
    ledger: list[dict[str, Any]] = []
    expected = reference_funnel(grants, proposals, **options)
    if defect == "tenant-binding":
        # This sentinel credits the submitted tenant as trusted registry data.
        grants = [dict(grant, tenant=proposals[0]["tenant"]) for grant in grants]
    observed = _enforce_funnel(
        grants, proposals, record_effect=None if defect == "fake-success" else ledger.append,
        **options,
    )
    independent_effects_match = ledger == expected["effects"]
    labels_match = ([effect["agent_id"] for effect in expected["effects"]]
                    == case["expected_effect_agents"])
    return {
        "case_id": case["case_id"],
        "input_sha256": _sha(_json(case)),
        "proposal_count": len(proposals),
        "expected_effects": expected["effects"],
        "observed_effects": ledger,
        "claimed_effects": observed["effects"],
        "expected_decisions": expected["decisions"],
        "reported_decisions": observed["decisions"],
        "authored_labels_match": labels_match,
        "independent_effects_match": independent_effects_match,
        "passed": labels_match and independent_effects_match and observed == expected,
    }


def _phase_witness(
    case: ExperimentCase,
    expected_tasks: tuple[str, ...],
    system: type[CorrectSyntheticSystem] = CorrectSyntheticSystem,
) -> dict[str, Any]:
    execution = execute_case(case, system)
    assessment = execution.assessment
    return {
        "case_id": case.case_id,
        "system_id": execution.system_id,
        "input_sha256": _sha(_json(case.to_dict())),
        "expected_effect_task_ids": list(expected_tasks),
        "passed": assessment.passed and tuple(
            effect["task_id"] for effect in assessment.observed_effects
        ) == expected_tasks,
        "oracle": assessment.to_dict(),
    }


def _post_prepare_cases(positive: ExperimentCase) -> dict[str, ExperimentCase]:
    submit = positive.commands[0]
    if submit.kind is not CommandKind.SUBMIT:
        raise ValueError("required positive fixture has no leading submission")
    advance = Command(CommandKind.ADVANCE, submit.at, task_id=submit.task_id)
    preparation = (submit,) + (advance,) * 4
    commit_tick = submit.at + 1
    changes = (
        ("expiry-after-preparation", positive.authorizations[0].expires_at, ()),
        ("epoch-advance-after-preparation", commit_tick, (
            Command(CommandKind.ADVANCE_EPOCH, commit_tick, value=positive.current_epoch + 1),
        )),
        ("unknown-state-after-preparation", commit_tick, (
            Command(CommandKind.SET_SECURITY_STATE, commit_tick, value=False),
        )),
    )
    return {
        name: replace(
            positive, title=name, control="NEGATIVE", mutation_labels=(name,),
            invariants=("NO_CURRENT_AUTHORITY_NO_PROTECTED_EFFECT",),
            commands=(*preparation, *commands, replace(advance, at=at)),
        ).with_identity()
        for name, at, commands in changes
    }


def _evaluate() -> tuple[dict[str, Any], dict[str, Any]]:
    funnel_inputs = (*_cases(), _coordinated_proposals())
    funnel_rows = [_funnel_witness(case) for case in funnel_inputs]
    phase_inputs = {
        scenario.scenario_id: scenario_to_case(scenario, seed=20261113)
        for scenario in load_corpus() if scenario.scenario_id in PHASE_CONTROLS
    }
    if set(phase_inputs) != set(PHASE_CONTROLS):
        raise ValueError("required phase-control scenarios are missing")
    phase_rows = [dict(_phase_witness(phase_inputs[name], tasks), control_id=name)
                  for name, tasks in PHASE_CONTROLS.items()]
    phase_inputs.update(_post_prepare_cases(phase_inputs["fbi-artex-positive-authorized-operation"]))
    for name, expected_denial in POST_PREPARE_REJECTIONS.items():
        witness = _phase_witness(phase_inputs[name], ())
        witness["control_id"] = name
        witness["expected_denial"] = expected_denial
        witness["passed"] = witness["passed"] and [
            task["denial_reason"] for task in witness["oracle"]["observed_tasks"]
        ] == [expected_denial]
        phase_rows.append(witness)
    funnel_by_id = {case["case_id"]: case for case in funnel_inputs}
    tenant = _funnel_witness(funnel_by_id["stolen-grant-cross-tenant"], defect="tenant-binding")
    fake = _funnel_witness(funnel_by_id["host-approved-positive"], defect="fake-success")
    sentinels = [
        {
            "name": "missing-tenant-binding",
            "caught": tenant["authored_labels_match"] and not tenant["independent_effects_match"]
            and not tenant["passed"] and len(tenant["observed_effects"]) == 1,
            "witness": tenant,
        },
        {
            "name": "fake-success",
            "caught": fake["authored_labels_match"] and not fake["independent_effects_match"]
            and not fake["passed"] and fake["claimed_effects"] == fake["expected_effects"]
            and fake["reported_decisions"] == fake["expected_decisions"],
            "witness": fake,
        },
    ]
    for name, scenario, system, observed_count, violation in (
        ("missing-final-recheck", "fbi-artex-delayed-crash-recovery",
         FinalRecheckDefectiveSyntheticSystem, 3, "UNAUTHORIZED_EFFECT_REVOKED"),
        ("missing-replay-reservation", "fbi-artex-concurrent-agents",
         ReplayDefectiveSyntheticSystem, 2, "UNAUTHORIZED_EFFECT_DUPLICATE_REPLAY_KEY"),
        ("deny-all", "fbi-artex-positive-authorized-operation",
         DenyAllSyntheticSystem, 0, "MISSING_REQUIRED_EFFECT"),
    ):
        witness = _phase_witness(phase_inputs[scenario], PHASE_CONTROLS[scenario], system)
        oracle = witness["oracle"]
        expected_matches_labels = tuple(
            effect["task_id"] for effect in oracle["expected_effects"]
        ) == PHASE_CONTROLS[scenario]
        sentinels.append({
            "name": name,
            "caught": expected_matches_labels and not oracle["passed"] and not witness["passed"]
            and len(oracle["observed_effects"]) == observed_count
            and any(item["code"] == violation for item in oracle["violations"]),
            "witness": witness,
        })
    mismatches = sum(not row["passed"] for row in (*funnel_rows, *phase_rows))
    sentinels_caught = sum(row["caught"] for row in sentinels)
    passed = mismatches == 0 and sentinels_caught == len(sentinels)
    report = {
        "schema": SCHEMA,
        "qualification": {
            "status": "PASSED_BOUNDED" if passed else "AUTHORITY_GAP",
            "evidence_status": "SYNTHETICALLY VERIFIED" if passed else "INCONCLUSIVE",
            "live_runtime_status": "NOT TESTED",
        },
        "summary": {
            "proposals": sum(row["proposal_count"] for row in funnel_rows),
            "funnel_controls": len(funnel_rows),
            "phase_controls": len(phase_rows),
            "mismatches": mismatches,
            "sentinels_caught": sentinels_caught,
            "sentinels_total": len(sentinels),
        },
        "funnel_controls": funnel_rows,
        "phase_controls": phase_rows,
        "sentinels": sentinels,
        "limits": [
            "Logical schedules and bounded fictional proposals exercise separate public models.",
            "The phase model covers scheduling and recovery. Tenant, delegate and slot binding "
            "are exercised in the funnel model.",
            "The effect sink is test-owned and process-local. It is a witness for authored defects, "
            "not isolation against arbitrary local Python code or durable process recovery.",
            "Any caller indistinguishable from a legitimate caller remains outside these controls.",
            "Genuine broker authority, live effects, model behavior and real cloud telemetry "
            "are outside this qualification.",
        ],
    }
    return {
        "schema": SCHEMA,
        "funnel_controls": list(funnel_inputs),
        "phase_controls": [case.to_dict() for case in phase_inputs.values()],
    }, report


def _source_identity() -> dict[str, str]:
    root = repository_root()
    git_root = _git(root, "rev-parse", "--show-toplevel").decode(
        sys.getfilesystemencoding(), errors="surrogateescape",
    ).rstrip("\n")
    if Path(git_root).resolve() != root:
        raise ValueError("qualification source is outside its Git checkout")
    if _git(root, "-c", "core.fsmonitor=false", "status", "--porcelain=v1", "-z"):
        raise ValueError("qualification requires a clean source checkout")
    identity = {
        "commit_sha": _git(root, "rev-parse", "HEAD").decode("ascii").strip(),
        "tree_sha": _git(root, "rev-parse", "HEAD^{tree}").decode("ascii").strip(),
    }
    if not all(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) for value in identity.values()):
        raise ValueError("source revision unavailable")
    return identity


def _environment() -> dict[str, str]:
    return {"python": platform.python_version(), "implementation": platform.python_implementation(),
            "platform": sys.platform, "architecture": platform.machine()}


def _validate_environment(value: Any) -> dict[str, str]:
    if (type(value) is not dict
            or set(value) != {"python", "implementation", "platform", "architecture"}
            or any(type(field) is not str or re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", field) is None
                   for field in value.values())):
        raise ValueError("invalid qualification environment metadata")
    return value


def _artifacts(
    identity: dict[str, str], environment: dict[str, str],
) -> tuple[dict[str, Any], dict[str, bytes]]:
    fixtures, report = _evaluate()
    inputs = _json(fixtures)
    report.update(source_revision=identity, environment=_validate_environment(environment),
                  inputs_sha256=_sha(inputs))
    return report, {INPUTS_NAME: inputs, REPORT_NAME: _json(report)}


def _manifest(artifacts: dict[str, bytes]) -> bytes:
    return _json({
        "schema": MANIFEST_SCHEMA, "state": "COMPLETE",
        "files": {name: {"bytes": len(body), "sha256": _sha(body)}
                  for name, body in sorted(artifacts.items())},
    })


def run_qualification(output_dir: str | Path) -> dict[str, Any]:
    identity = _source_identity()
    report, artifacts = _artifacts(identity, _environment())
    if _source_identity() != identity:
        raise ValueError("source changed during qualification")
    fd = _open_directory(Path(output_dir), create=True)
    try:
        if os.listdir(fd):
            raise ValueError("qualification directory must be fresh or empty")
        if any(len(body) > MAX_ARTIFACT_BYTES for body in artifacts.values()):
            raise ValueError("qualification evidence exceeds its byte bound")
        for name, body in artifacts.items():
            _publish(fd, name, body)
        _publish(fd, MANIFEST_NAME, _manifest(artifacts))
    finally:
        os.close(fd)
    return report


def verify_qualification(evidence_dir: str | Path) -> dict[str, Any]:
    """Replay from identical source and check exact evidence bytes."""
    identity = _source_identity()
    fd = _open_directory(Path(evidence_dir))
    try:
        if set(os.listdir(fd)) != {INPUTS_NAME, REPORT_NAME, MANIFEST_NAME}:
            raise ValueError("qualification directory has missing or extra files")
        artifacts = {name: _read_file(fd, name, MAX_ARTIFACT_BYTES)
                     for name in (INPUTS_NAME, REPORT_NAME)}
        if _read_file(fd, MANIFEST_NAME, 4096) != _manifest(artifacts):
            raise ValueError("qualification manifest mismatch")
        saved = json.loads(artifacts[REPORT_NAME])
        if not isinstance(saved, dict) or saved.get("source_revision") != identity:
            raise ValueError("qualification must be replayed at its exact source revision")
        report, expected = _artifacts(identity, saved.get("environment"))
        if artifacts != expected or _source_identity() != identity:
            raise ValueError("qualification replay mismatch")
        return report
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--output-dir")
    action.add_argument("--evidence-dir")
    args = parser.parse_args(argv)
    try:
        report = (run_qualification(args.output_dir) if args.output_dir
                  else verify_qualification(args.evidence_dir))
    except (OSError, RuntimeError, ValueError):
        print("INCONCLUSIVE: source identity, execution or evidence validation failed.",
              file=sys.stderr)
        return 2
    summary = report["summary"]
    status = report["qualification"]["status"]
    print(f"{status}: {summary['proposals']} proposals, {summary['phase_controls']} phase "
          f"controls, {summary['sentinels_caught']}/{summary['sentinels_total']} sentinels caught.")
    return 0 if status == "PASSED_BOUNDED" else 1


if __name__ == "__main__":
    raise SystemExit(main())

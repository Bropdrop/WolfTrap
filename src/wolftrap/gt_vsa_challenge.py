"""Bounded GT-VSA qualification, fault controls, and exact offline replay."""

from __future__ import annotations

import hashlib
import json
import os
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any

from .agent_scan import _json, _open_directory, _output_directory, _publish, _read_file, _sha
from .gt_vsa_fixtures import Trial, key, scenario_steps
from .gt_vsa_oracle import INVARIANTS, LedgerWitness, Scenario, Snapshot, assess, load_corpus
from .revision import capture_source_revision, repository_root

SCHEMA = "wolftrap.gt-vsa-qualification/v1"
MANIFEST_SCHEMA = "wolftrap.gt-vsa-manifest/v1"
REPORT_NAME = "gt-vsa.json"
MARKDOWN_NAME = "gt-vsa.md"
MANIFEST_NAME = "gt-vsa.manifest.json"
DEFAULT_SEED = 20261117
DEFAULT_VEHICLES = 1024
MIN_VEHICLES = 1000
MAX_VEHICLES = 2048
MAX_REPORT_BYTES = 2 * 1024 * 1024
MAX_FAILURE_SAMPLES = 32


@dataclass(frozen=True)
class Fault:
    id: str
    scenario: str
    stage: str
    violation: str
    mode: str


FAULTS = (
    Fault("write-without-authority", "verified-without-authority", "attempt",
          "unexpected-extra-effects", "write"),
    Fault("write-on-wrong-origin", "stolen-signed-envelope", "attempt",
          "unexpected-extra-effects", "write"),
    Fault("commit-stale-preparation", "revoke-before-commit", "commit",
          "unexpected-extra-effects", "write"),
    Fault("write-on-prepare", "authorized-abandoned", "prepare",
          "unexpected-extra-effects", "write"),
    Fault("commit-replay-twice", "concurrent-replay", "attempt",
          "unexpected-extra-effects", "duplicate"),
    Fault("route-external-to-safety", "authority-compromise-isolation", "external",
          "unexpected-extra-effects", "cross-domain"),
    Fault("disable-local-on-disconnect", "cloud-disconnection", "local",
          "missing-expected-effects", "omit-local"),
    Fault("trust-claimed-audit-record", "audit-evidence-manipulation", "tamper",
          "invalid-after-witness", "forge-witness"),
)


def _record_fault(trial: Trial, fault: Fault) -> None:
    """Exercise the synthetic sink through a deliberately defective fixture."""
    if fault.mode == "duplicate":
        effect = trial.vehicle.snapshot()[-1]
    else:
        if trial.anchor is None:
            raise ValueError("fault has no fixture request")
        effect = trial.anchor.faulty_effect()
        if fault.mode == "cross-domain":
            effect = replace(effect, domain="safety")
    if not trial.vehicle._ledger.record(effect):
        raise ValueError("defective fixture did not reach the synthetic sink")


def _snapshot(trial: Trial, witness: LedgerWitness, checkpoint: str) -> Snapshot:
    return witness.capture((asdict(effect) for effect in trial.snapshot()), checkpoint)


def _audit_probes(
    before: Snapshot, after: Snapshot, witness: LedgerWitness, seed: int, context: str,
) -> tuple[dict[str, bool], Snapshot]:
    impostor = LedgerWitness(key(seed, "impostor-witness"), context)
    forged = impostor.capture((), after.checkpoint)
    if not after.rows:
        return {"positive-control-observed": False}, forged
    erased = replace(after, rows=())
    substituted = ((*after.rows[0][:-2], "0" * 64, after.rows[0][-1]), *after.rows[1:])
    edited = replace(after, rows=substituted)
    return {
        "deleted-record-rejected": not witness.verify(erased, after.checkpoint),
        "edited-record-rejected": not witness.verify(edited, after.checkpoint),
        "foreign-signature-rejected": not witness.verify(forged, after.checkpoint),
        "earlier-checkpoint-rejected": not witness.verify(before, after.checkpoint),
    }, forged


def _run_trial(
    scenario: Scenario, *, seed: int, index: int, pool: ThreadPoolExecutor,
    fault: Fault | None = None,
) -> dict[str, Any]:
    trial = Trial(seed, index, pool)
    context = f"{trial.vehicle_id}:{scenario.id}"
    witness = LedgerWitness(key(seed, "independent-witness"), context)
    expected_version = 1
    previous_rows = ()
    results = []
    mismatches = []
    steps = iter(scenario_steps(scenario.id, trial))

    for stage in scenario.stages:
        step = next(steps, None)
        if step is None or step.id != stage.id:
            mismatches.append(f"stage-not-reached:{stage.id}")
            break

        active_fault = fault if fault and fault.stage == stage.id else None
        before = _snapshot(trial, witness, f"{stage.id}:before")
        result = (
            step.checkpoint if active_fault and active_fault.mode == "omit-local" else step.action()
        )
        trial.last_result = result
        if active_fault and active_fault.mode in {"write", "duplicate", "cross-domain"}:
            _record_fault(trial, active_fault)
        after = _snapshot(trial, witness, f"{stage.id}:after")

        audit = {}
        offered = after
        if step.witness_tamper:
            audit, forged = _audit_probes(before, after, witness, seed, context)
            if active_fault and active_fault.mode == "forge-witness":
                offered = forged
        decision = assess(before, offered, stage, step.bindings, witness)
        issues = list(decision.violations)
        if before.rows != previous_rows:
            issues.append("unobserved-ledger-change-between-stages")
        previous_rows = after.rows
        if result != step.checkpoint:
            issues.append("checkpoint-not-exercised")
        if not all(audit.values()):
            issues.append("audit-tampering-accepted")
        for effect in decision.expected:
            if effect["firmware_version"] is not None:
                expected_version = effect["firmware_version"]
        if trial.vehicle.firmware_version != expected_version:
            issues.append("installed-version-mismatch")

        results.append({
            "stage": stage.id,
            "checkpoint": result,
            "expected_checkpoint": step.checkpoint,
            "invariants": stage.invariants,
            "expected_effects": decision.expected,
            "observed_effects": decision.observed,
            "ledger_before_sha256": before.ledger_sha256,
            "ledger_after_sha256": after.ledger_sha256,
            "ledger_witness_mac": after.mac,
            "offered_witness_mac": offered.mac,
            "installed_firmware_version": trial.vehicle.firmware_version,
            "audit_probes": audit,
            "violations": issues,
        })
        mismatches.extend(f"{stage.id}:{issue}" for issue in issues)
    else:
        if next(steps, None) is not None:
            mismatches.append("unexpected-fixture-stage")

    final = _snapshot(trial, witness, "final")
    if final.rows != previous_rows:
        mismatches.append("unobserved-ledger-change-at-final-checkpoint")
    return {
        "vehicle": trial.vehicle_id,
        "final_ledger_sha256": final.ledger_sha256,
        "status": "FAIL" if mismatches else "PASS",
        "stages": results,
        "violations": mismatches,
    }


def _parameters(seed: int, vehicles: int) -> None:
    if type(seed) is not int or not 0 <= seed < 2**64:
        raise ValueError("seed must be an unsigned 64-bit integer")
    if type(vehicles) is not int or not MIN_VEHICLES <= vehicles <= MAX_VEHICLES:
        raise ValueError(f"vehicle count must be between {MIN_VEHICLES} and {MAX_VEHICLES}")


def _scenario_result(
    scenario: Scenario, seed: int, vehicles: int, pool: ThreadPoolExecutor,
    failures: list[dict[str, Any]], coverage: Counter[str],
) -> dict[str, Any]:
    fingerprint = hashlib.sha256()
    counts: Counter[str] = Counter()
    sample = None
    for index in range(vehicles):
        trial = _run_trial(scenario, seed=seed, index=index, pool=pool)
        if sample is None:
            sample = trial
        fingerprint.update(_json(trial))
        counts[trial["status"]] += 1
        counts["stages"] += len(trial["stages"])
        if trial["status"] == "FAIL" and len(failures) < MAX_FAILURE_SAMPLES:
            failures.append({"scenario": scenario.id, **trial})
        for stage in trial["stages"]:
            coverage.update(stage["invariants"])
    return {
        "id": scenario.id, "kind": scenario.kind,
        "status": "FAIL" if counts["FAIL"] else "PASS",
        "passed": counts["PASS"], "failed": counts["FAIL"],
        "stages_observed": counts["stages"],
        "trial_sequence_sha256": fingerprint.hexdigest(),
        "representative_trial": sample,
    }


def _fault_result(fault: Fault, scenario: Scenario, seed: int, pool: ThreadPoolExecutor) -> dict[str, Any]:
    baseline = _run_trial(scenario, seed=seed, index=0, pool=pool)
    defective = (
        _run_trial(scenario, seed=seed, index=0, pool=pool, fault=fault)
        if baseline["status"] == "PASS" else None
    )
    violation = f"{fault.stage}:{fault.violation}"
    detected = defective is not None and defective["violations"] == [violation]
    return {
        "id": fault.id, "scenario": fault.scenario, "status": "PASS" if detected else "FAIL",
        "healthy_baseline_status": baseline["status"], "expected_violation": violation,
        "defective_trial": defective,
    }


def _campaign(seed: int, vehicles: int, source: dict[str, object]) -> dict[str, Any]:
    corpus = load_corpus()
    failures: list[dict[str, Any]] = []
    coverage: Counter[str] = Counter()
    by_id = {scenario.id: scenario for scenario in corpus.scenarios}
    with ThreadPoolExecutor(max_workers=2, thread_name_prefix="gt-vsa-replay") as pool:
        scenarios = [
            _scenario_result(scenario, seed, vehicles, pool, failures, coverage)
            for scenario in corpus.scenarios
        ]
        defects = [_fault_result(fault, by_id[fault.scenario], seed, pool) for fault in FAULTS]
    total_failed = sum(scenario["failed"] for scenario in scenarios)
    detected_count = sum(fault["status"] == "PASS" for fault in defects)
    missing = sorted(set(INVARIANTS) - coverage.keys())
    passed = total_failed == 0 and detected_count == len(FAULTS) and not missing
    return {
        "schema": SCHEMA,
        "status": "PASS" if passed else "FAIL",
        "seed": seed,
        "source": source,
        "corpus_sha256": corpus.sha256,
        "summary": {
            "vehicles": vehicles,
            "scenarios": len(scenarios),
            "scenario_runs": vehicles * len(scenarios),
            "stage_observations": sum(result["stages_observed"] for result in scenarios),
            "failed_runs": total_failed,
            "defects": len(FAULTS),
            "defects_detected": detected_count,
        },
        "invariants": {
            invariant: {"statement": statement, "observations": coverage[invariant]}
            for invariant, statement in INVARIANTS.items()
        },
        "unexercised_invariants": missing,
        "scenarios": scenarios,
        "failure_samples": failures,
        "fault_controls": defects,
        "assurance_gaps": [
            {"status": "BLOCKED", "claim": "Physical integration and certification",
             "reason": "Requires an OEM safety platform and formal engineering evidence."},
            {"status": "UNVERIFIED", "claim": "Production isolation, availability and crash recovery",
             "reason": "The experiment uses bounded in-memory journals and trusted fixture interfaces."},
        ],
    }


def _markdown(report: dict[str, Any]) -> bytes:
    counts = report["summary"]
    lines = [
        "# GT-VSA synthetic qualification", "",
        f"**{report['status']}** with seed `{report['seed']}` across {counts['vehicles']:,} vehicles.",
        "", f"Source commit `{report['source']['commit_sha']}`",
        f"Git tree `{report['source']['tree_sha']}`",
        f"Corpus SHA-256 `{report['corpus_sha256']}`", "",
        f"{counts['scenario_runs']:,} scenario runs and {counts['stage_observations']:,} "
        f"ledger checkpoints produced {counts['failed_runs']} failed runs.",
        f"The independent oracle detected {counts['defects_detected']}/{counts['defects']} injected defects.",
        "",
        "## Scenarios", "", "| Scenario | Type | Outcome | Passed | Failed |",
        "| --- | --- | --- | ---: | ---: |",
    ]
    lines.extend(
        f"| {row['id']} | {row['kind']} | {row['status']} | {row['passed']} | {row['failed']} |"
        for row in report["scenarios"]
    )
    lines.extend(("", "## Deliberate defects", "", "| Defect | Detection | Expected violation |",
                  "| --- | --- | --- |"))
    lines.extend(
        f"| {row['id']} | {row['status']} | `{row['expected_violation']}` |"
        for row in report["fault_controls"]
    )
    lines.extend(("", "## Invariants", "", "| Invariant | Ledger checkpoints |",
                  "| --- | ---: |"))
    lines.extend(
        f"| {invariant['statement']} | {invariant['observations']:,} |"
        for invariant in report["invariants"].values()
    )
    lines.extend(("", "## Evidence limits", ""))
    lines.extend(
        f"- **{row['status']}** — {row['claim']}. {row['reason']}"
        for row in report["assurance_gaps"]
    )
    lines.extend(("", "The JSON records exact representative mutations and a digest over every trial.", ""))
    return "\n".join(lines).encode("utf-8")


def _artifacts(report: dict[str, Any]) -> dict[str, bytes]:
    return {REPORT_NAME: _json(report), MARKDOWN_NAME: _markdown(report)}


def _manifest(report: dict[str, Any], artifacts: dict[str, bytes]) -> dict[str, Any]:
    return {
        "schema": MANIFEST_SCHEMA, "status": report["status"], "source": report["source"],
        "seed": report["seed"], "summary": report["summary"],
        "artifacts": {name: {"sha256": _sha(data), "bytes": len(data)} for name, data in artifacts.items()},
    }


def write_evidence(
    output_dir: Path, *, seed: int = DEFAULT_SEED, vehicles: int = DEFAULT_VEHICLES,
) -> dict[str, Any]:
    """Run the campaign and publish a completion record after its two reports."""
    _parameters(seed, vehicles)
    source = capture_source_revision()
    report = _campaign(seed, vehicles, source.to_dict())
    if capture_source_revision() != source:
        raise ValueError("GT-VSA source changed during qualification")
    artifacts = _artifacts(report)
    manifest = _manifest(report, artifacts)
    directory = _output_directory(repository_root(), Path(output_dir))
    try:
        lock = ".gt-vsa-publication"
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=directory)
        os.close(fd)
        for name, data in artifacts.items():
            _publish(directory, name, data)
        _publish(directory, MANIFEST_NAME, _json(manifest))
        os.unlink(lock, dir_fd=directory)
        os.fsync(directory)
    finally:
        os.close(directory)
    return manifest


def verify_evidence(output_dir: Path) -> dict[str, Any]:
    """Re-execute committed controls from source and compare exact saved bytes."""
    directory = _open_directory(Path(output_dir))
    try:
        if set(os.listdir(directory)) != {REPORT_NAME, MARKDOWN_NAME, MANIFEST_NAME}:
            raise ValueError("GT-VSA evidence directory is incomplete or contains unexpected files")
        saved_manifest = _read_file(directory, MANIFEST_NAME, 16 * 1024)
        metadata = json.loads(saved_manifest)
        if type(metadata) is not dict or metadata.get("schema") != MANIFEST_SCHEMA:
            raise ValueError("unsupported GT-VSA manifest")
        summary = metadata.get("summary")
        if type(summary) is not dict:
            raise ValueError("missing GT-VSA manifest summary")
        seed, vehicles = metadata.get("seed"), summary.get("vehicles")
        _parameters(seed, vehicles)
        source = capture_source_revision()
        if metadata.get("source") != source.to_dict():
            raise ValueError("GT-VSA evidence identifies a different source revision")
        saved = {
            name: _read_file(directory, name, MAX_REPORT_BYTES)
            for name in (REPORT_NAME, MARKDOWN_NAME)
        }
        for name, data in saved.items():
            declared = metadata.get("artifacts")
            if type(declared) is not dict or declared.get(name) != {"sha256": _sha(data), "bytes": len(data)}:
                raise ValueError(f"GT-VSA artifact hash mismatch for {name}")
        report = _campaign(seed, vehicles, source.to_dict())
        artifacts = _artifacts(report)
        manifest = _manifest(report, artifacts)
        if capture_source_revision() != source:
            raise ValueError("GT-VSA source changed during replay")
        if artifacts != saved or _json(manifest) != saved_manifest:
            raise ValueError("GT-VSA evidence disagrees with independent replay")
    finally:
        os.close(directory)
    return manifest

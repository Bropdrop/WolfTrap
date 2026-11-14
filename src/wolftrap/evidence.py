"""Evidence records and stable finding construction."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from .execution import CaseExecution
from .hypothesis import DisabledHypothesisProvider
from .minimize import MinimizationResult, ReproductionAttempt
from .model import Confidence, FindingClassification, Severity
from .oracle import OracleViolation
from .revision import SourceRevision


def generated_at() -> str:
    source_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if source_epoch is not None:
        try:
            timestamp = int(source_epoch)
        except ValueError as exc:
            raise ValueError("SOURCE_DATE_EPOCH must be an integer") from exc
        moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    else:
        moment = datetime.now(tz=timezone.utc)
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def stable_hash(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _severity(violation: OracleViolation, execution: CaseExecution) -> Severity:
    if violation.code.startswith("UNAUTHORIZED_EFFECT"):
        actions = {effect.get("action") for effect in execution.assessment.observed_effects}
        if actions & {"transfer", "assign_role", "add_credential"}:
            return Severity.CRITICAL
        return Severity.HIGH
    if "REPLAY" in violation.code or "LEDGER" in violation.code:
        return Severity.HIGH
    if "POSITIVE_CONTROL" in violation.code or "MISSING_REQUIRED" in violation.code:
        return Severity.MEDIUM
    return Severity.MEDIUM


def build_finding(
    *,
    violation: OracleViolation,
    original_execution: CaseExecution,
    evidence_execution: CaseExecution,
    minimized: MinimizationResult,
    reproductions: Sequence[ReproductionAttempt],
    classification: FindingClassification,
    source_revision: SourceRevision,
    campaign_seed: int,
    run_configuration: Mapping[str, Any],
    reproduction_report_path: str,
    duplicate_of: str | None = None,
) -> dict[str, Any]:
    case = original_execution.case
    identity = {
        "source_revision": source_revision.commit_sha,
        "system_id": evidence_execution.system_id,
        "invariant": violation.invariant,
        "code": violation.code,
        "minimized_case_digest": minimized.minimized_case.digest,
        "original_case_digest": case.digest,
        "command_index": violation.command_index,
    }
    finding_id = "WOLFTRAP-F-" + stable_hash(identity)[:20].upper()
    reproduced_count = sum(item.reproduced for item in reproductions)
    confidence = (
        Confidence.HIGH
        if classification in {FindingClassification.CONFIRMED, FindingClassification.DUPLICATE}
        and reproduced_count == len(reproductions)
        and len(reproductions) >= 2
        else Confidence.LOW
        if classification is FindingClassification.NOT_REPRODUCED
        else Confidence.MEDIUM
    )
    observed_effects = evidence_execution.assessment.observed_effects
    evidence_trace = [
        {
            "command_index": index,
            "ledger_before_hash": observation.ledger_before_hash,
            "ledger_after_hash": observation.ledger_after_hash,
            "effect_delta": [item.to_dict() for item in observation.effect_delta],
        }
        for index, observation in enumerate(evidence_execution.observations)
        if observation.effect_delta or index == violation.command_index
    ]
    return {
        "finding_id": finding_id,
        "classification": classification.value,
        "classification_rationale": (
            f"{reproduced_count}/{len(reproductions)} fresh-fixture minimized-case "
            "reproduction attempts matched the independently computed fingerprint."
        ),
        "duplicate_of": duplicate_of,
        "severity": _severity(violation, evidence_execution).value,
        "confidence": confidence.value,
        "synthetic_only": True,
        "real_world_vulnerability_claim": False,
        "model_generated": False,
        "invariant": violation.invariant,
        "violation_code": violation.code,
        "threat_sources": [asdict(item) for item in case.sources],
        "attack_references": [asdict(item) for item in case.attack_references],
        "source_revision": source_revision.to_dict(),
        "random_seed": {
            "campaign_seed": campaign_seed,
            "case_seed": case.case_seed,
            "generator_version": case.generator_version,
        },
        "scenario": {
            "ids": list(case.scenario_ids),
            "versions": list(case.scenario_versions),
            "category": case.category,
            "interaction_depth": case.interaction_depth,
        },
        "test_configuration": {
            "run_bounds": dict(run_configuration),
            "system_id": evidence_execution.system_id,
            "original_case": case.to_dict(),
            "minimized_case": minimized.minimized_case.to_dict(),
            "original_case_digest": case.digest,
            "minimized_case_digest": minimized.minimized_case.digest,
        },
        "expected_behavior": {
            "summary": (
                f"Invariant {violation.invariant} holds and the reference ledger contains "
                f"{len(evidence_execution.assessment.expected_effects)} effect(s)."
            ),
            "reference_effects": list(evidence_execution.assessment.expected_effects),
            "reference_tasks": list(evidence_execution.assessment.expected_tasks),
        },
        "observed_behavior": {
            "summary": violation.detail,
            "observed_effects": list(observed_effects),
            "observed_tasks": list(evidence_execution.assessment.observed_tasks),
        },
        "independent_effect_state_evidence": {
            "oracle_implementation": "independent-reference-state-v1",
            "oracle_fingerprint": evidence_execution.assessment.fingerprint,
            "oracle_state_hash": evidence_execution.assessment.oracle_state_hash,
            "observed_ledger_hash": evidence_execution.assessment.observed_ledger_hash,
            "trace": evidence_trace,
            "effect_ids": list(violation.effect_ids),
        },
        "original_candidate_evidence": {
            "case_id": original_execution.case.case_id,
            "oracle_fingerprint": original_execution.assessment.fingerprint,
            "observed_ledger_hash": original_execution.assessment.observed_ledger_hash,
            "violations": [
                item.to_dict() for item in original_execution.assessment.violations
            ],
        },
        "minimization": minimized.to_dict(),
        "reproduction": {
            "required_independent_attempts": len(reproductions),
            "attempts": [item.to_dict() for item in reproductions],
            "command": (
                "PYTHONPATH=src python -m wolftrap reproduce "
                f"--report {shlex.quote(reproduction_report_path)} "
                f"--finding-id {finding_id} "
                "--output-dir reports/reproduction"
            ),
            "saved_case_digest": minimized.minimized_case.digest,
        },
    }


def base_report_fields() -> dict[str, Any]:
    return {
        "report_schema_version": "1.0",
        "engine": {
            "name": "WolfTrap",
            "version": "0.1.0",
            "oracle_version": "independent-reference-state-v1",
            "generator_version": "stateful-v1",
        },
        "model_hypotheses": DisabledHypothesisProvider.status.to_dict(),
        "safety": {
            "synthetic_only": True,
            "external_targets": False,
            "network_operations": False,
            "production_credentials": False,
            "paid_api_calls": False,
            "openai_integration_enabled": False,
            "deployment": False,
            "financial_or_blockchain_effects": False,
        },
    }

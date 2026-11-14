"""Bounded delta-debugging for independently observed counterexamples."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Type

from .execution import CaseExecution, CaseExecutionError, execute_case
from .model import CommandKind, ExperimentCase
from .oracle import OracleCaseError
from .system import CorrectSyntheticSystem, SystemExecutionError


@dataclass(frozen=True)
class MinimizationResult:
    original_case_id: str
    minimized_case: ExperimentCase
    target_fingerprint: str
    evaluations: int
    reduced_commands: int
    truncated: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "original_case_id": self.original_case_id,
            "minimized_case_id": self.minimized_case.case_id,
            "minimized_case_digest": self.minimized_case.digest,
            "target_fingerprint": self.target_fingerprint,
            "evaluations": self.evaluations,
            "reduced_commands": self.reduced_commands,
            "truncated": self.truncated,
        }


@dataclass(frozen=True)
class ReproductionAttempt:
    attempt: int
    reproduced: bool
    fingerprint: str | None
    ledger_hash: str | None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "attempt": self.attempt,
            "reproduced": self.reproduced,
            "fingerprint": self.fingerprint,
            "ledger_hash": self.ledger_hash,
            "error": self.error,
        }


def _same_failure(
    case: ExperimentCase,
    system_type: Type[CorrectSyntheticSystem],
    target: str,
) -> tuple[bool, CaseExecution | None]:
    try:
        result = execute_case(case, system_type)
    except CaseExecutionError as exc:
        if exc.evidence.get("cause_type") in {
            "SystemExecutionError",
            "OracleCaseError",
            "CaseValidationError",
        }:
            return False, None
        raise
    except (SystemExecutionError, OracleCaseError, KeyError, ValueError):
        return False, None
    return (not result.assessment.passed and result.assessment.fingerprint == target), result


def minimize_counterexample(
    case: ExperimentCase,
    system_type: Type[CorrectSyntheticSystem],
    target_fingerprint: str,
    *,
    max_evaluations: int = 64,
) -> MinimizationResult:
    if max_evaluations < 1:
        raise ValueError("max_evaluations must be positive")
    matches, _ = _same_failure(case, system_type, target_fingerprint)
    if not matches:
        raise ValueError("the original case does not reproduce the target failure")
    evaluations = 1
    commands = list(case.commands)
    original_count = len(commands)
    granularity = 2
    truncated = False

    while len(commands) >= 2:
        chunk_size = max(1, (len(commands) + granularity - 1) // granularity)
        reduced = False
        for start in range(0, len(commands), chunk_size):
            if evaluations >= max_evaluations:
                truncated = True
                break
            candidate_commands = commands[:start] + commands[start + chunk_size :]
            if not candidate_commands:
                continue
            kinds = {command.kind for command in candidate_commands}
            if CommandKind.SUBMIT not in kinds or CommandKind.ADVANCE not in kinds:
                continue
            candidate = replace(
                case,
                case_id="pending",
                commands=tuple(candidate_commands),
            ).with_identity()
            matches, _ = _same_failure(candidate, system_type, target_fingerprint)
            evaluations += 1
            if matches:
                commands = candidate_commands
                granularity = max(2, granularity - 1)
                reduced = True
                break
        if truncated:
            break
        if not reduced:
            if granularity >= len(commands):
                break
            granularity = min(len(commands), granularity * 2)

    minimized = replace(
        case,
        case_id="pending",
        commands=tuple(commands),
    ).with_identity()
    return MinimizationResult(
        original_case_id=case.case_id,
        minimized_case=minimized,
        target_fingerprint=target_fingerprint,
        evaluations=evaluations,
        reduced_commands=original_count - len(commands),
        truncated=truncated,
    )


def reproduce_counterexample(
    case: ExperimentCase,
    system_type: Type[CorrectSyntheticSystem],
    target_fingerprint: str,
    *,
    attempts: int = 2,
) -> tuple[ReproductionAttempt, ...]:
    if attempts < 1:
        raise ValueError("attempts must be positive")
    results: list[ReproductionAttempt] = []
    for number in range(1, attempts + 1):
        execution = execute_case(case, system_type)
        fingerprint = execution.assessment.fingerprint
        reproduced = (
            not execution.assessment.passed and fingerprint == target_fingerprint
        )
        results.append(
            ReproductionAttempt(
                attempt=number,
                reproduced=reproduced,
                fingerprint=fingerprint,
                ledger_hash=execution.assessment.observed_ledger_hash,
            )
        )
    return tuple(results)

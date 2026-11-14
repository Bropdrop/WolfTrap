"""Execute one saved logical schedule and invoke the independent oracle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Type

from .canonical import sha256_json
from .effects import SyntheticEffectLedger, effect_delta
from .model import ExperimentCase
from .oracle import OracleAssessment, assess_execution
from .system import CorrectSyntheticSystem, TransitionObservation
from .validate import validate_experiment_case


class CaseExecutionError(RuntimeError):
    """Execution stopped with independently captured partial effect evidence."""

    def __init__(
        self,
        *,
        case_id: str,
        system_id: str,
        command_index: int,
        cause: Exception,
        ledger_before_hash: str,
        ledger_after_hash: str,
        effect_delta: tuple[Any, ...],
        completed_observations: int,
    ) -> None:
        super().__init__(f"{type(cause).__name__}: {cause}")
        self.evidence = {
            "case_id": case_id,
            "system_id": system_id,
            "command_index": command_index,
            "cause_type": type(cause).__name__,
            "cause_message": str(cause),
            "ledger_before_hash": ledger_before_hash,
            "ledger_after_hash": ledger_after_hash,
            "effect_delta": [item.to_dict() for item in effect_delta],
            "completed_observations": completed_observations,
            "fail_closed": True,
        }


@dataclass(frozen=True)
class CaseExecution:
    case: ExperimentCase
    system_id: str
    observations: tuple[TransitionObservation, ...]
    final_state: dict[str, Any]
    assessment: OracleAssessment

    def to_dict(self, *, include_trace: bool = True) -> dict[str, Any]:
        value = {
            "case_id": self.case.case_id,
            "case_digest": self.case.digest,
            "system_id": self.system_id,
            "assessment": self.assessment.to_dict(),
            "final_state": self.final_state,
        }
        if include_trace:
            value["observations"] = [item.to_dict() for item in self.observations]
        return value


def execute_case(
    case: ExperimentCase,
    system_type: Type[CorrectSyntheticSystem] = CorrectSyntheticSystem,
) -> CaseExecution:
    validate_experiment_case(case)
    # The executor owns the protected-effect environment. SUT responses cannot
    # conceal or synthesize the evidence channel inspected by the oracle.
    evidence_ledger = SyntheticEffectLedger()
    system = system_type(case, effect_ledger=evidence_ledger)
    observations: list[TransitionObservation] = []
    transition_state_hash = "sha256:" + sha256_json(
        {"case_digest": case.digest, "transition_chain": "executor-evidence-v1"}
    )
    for command_index, command in enumerate(case.commands):
        before = evidence_ledger.snapshot()
        before_hash = evidence_ledger.state_hash
        try:
            reported = system.apply(command)
        except Exception as exc:
            after = evidence_ledger.snapshot()
            raise CaseExecutionError(
                case_id=case.case_id,
                system_id=system.system_id,
                command_index=command_index,
                cause=exc,
                ledger_before_hash=before_hash,
                ledger_after_hash=evidence_ledger.state_hash,
                effect_delta=effect_delta(before, after),
                completed_observations=len(observations),
            ) from exc
        after = evidence_ledger.snapshot()
        delta = effect_delta(before, after)
        transition_state_hash = "sha256:" + sha256_json(
            {
                "previous_state_hash": transition_state_hash,
                "command": reported.command,
                "task_before": reported.task_before,
                "task_after": reported.task_after,
                "ledger_before_hash": before_hash,
                "ledger_after_hash": evidence_ledger.state_hash,
                "effect_delta": [item.to_dict() for item in delta],
            }
        )
        observations.append(
            TransitionObservation(
                command=reported.command,
                task_before=reported.task_before,
                task_after=reported.task_after,
                ledger_before_hash=before_hash,
                ledger_after_hash=evidence_ledger.state_hash,
                effect_delta=delta,
                # Executor-owned chain over independently captured evidence;
                # this does not trust a SUT-reported policy-state digest.
                state_hash=transition_state_hash,
            )
        )
    try:
        final_state = system.final_state()
    except Exception as exc:
        raise CaseExecutionError(
            case_id=case.case_id,
            system_id=system.system_id,
            command_index=len(case.commands),
            cause=exc,
            ledger_before_hash=evidence_ledger.state_hash,
            ledger_after_hash=evidence_ledger.state_hash,
            effect_delta=(),
            completed_observations=len(observations),
        ) from exc
    final_state["sut_reported_state_hash"] = final_state.get("state_hash")
    final_state["state_hash"] = transition_state_hash
    final_state["effects"] = [item.to_dict() for item in evidence_ledger.snapshot()]
    final_state["ledger_hash"] = evidence_ledger.state_hash
    try:
        assessment = assess_execution(case, observations, final_state)
    except Exception as exc:
        raise CaseExecutionError(
            case_id=case.case_id,
            system_id=system.system_id,
            command_index=len(case.commands),
            cause=exc,
            ledger_before_hash=evidence_ledger.state_hash,
            ledger_after_hash=evidence_ledger.state_hash,
            effect_delta=(),
            completed_observations=len(observations),
        ) from exc
    return CaseExecution(
        case=case,
        system_id=system.system_id,
        observations=tuple(observations),
        final_state=final_state,
        assessment=assessment,
    )

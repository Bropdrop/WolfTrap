"""Synthetic state machines used as systems under test."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from .canonical import sha256_json
from .effects import EffectRecord, SyntheticEffectLedger, UnsafeSyntheticEffect, effect_delta
from .model import (
    Authorization,
    Command,
    CommandKind,
    DenialReason,
    ExperimentCase,
    Operation,
    Principal,
    RequestSpec,
    TaskPhase,
    unique_by_id,
)


class SystemExecutionError(RuntimeError):
    """Infrastructure/model failure; it is never interpreted as a secure denial."""


@dataclass
class TaskState:
    task_id: str
    request: RequestSpec
    credential: Authorization
    operation: Operation
    phase: TaskPhase = TaskPhase.RECEIVED
    denial_reason: DenialReason = DenialReason.NONE
    crashed_phase: TaskPhase | None = None
    recovery_generation: int = 0
    effect_id: str | None = None

    def public_view(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "request_id": self.request.request_id,
            "phase": self.phase.value,
            "denial_reason": self.denial_reason.value,
            "crashed_phase": self.crashed_phase.value if self.crashed_phase else None,
            "recovery_generation": self.recovery_generation,
            "effect_id": self.effect_id,
        }


@dataclass(frozen=True)
class TransitionObservation:
    command: dict[str, Any]
    task_before: dict[str, Any] | None
    task_after: dict[str, Any] | None
    ledger_before_hash: str
    ledger_after_hash: str
    effect_delta: tuple[EffectRecord, ...]
    state_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "task_before": self.task_before,
            "task_after": self.task_after,
            "ledger_before_hash": self.ledger_before_hash,
            "ledger_after_hash": self.ledger_after_hash,
            "effect_delta": [item.to_dict() for item in self.effect_delta],
            "state_hash": self.state_hash,
        }


class CorrectSyntheticSystem:
    """Reference-quality SUT with atomic final authority and replay commit."""

    system_id = "correct-v1"
    deliberately_defective = False

    def __init__(
        self,
        case: ExperimentCase,
        *,
        effect_ledger: SyntheticEffectLedger | None = None,
    ) -> None:
        self.case = case
        self.clock = 0
        self.current_epoch = case.current_epoch
        self.security_state_known = case.security_state_known
        self.principals: dict[str, Principal] = unique_by_id(
            case.principals, "principal_id"
        )
        self.authorizations: dict[str, Authorization] = unique_by_id(
            case.authorizations, "authorization_id"
        )
        self.operations: dict[str, Operation] = unique_by_id(
            case.operations, "operation_id"
        )
        self.requests: dict[str, RequestSpec] = unique_by_id(
            case.requests, "request_id"
        )
        self.revoked_at: dict[str, int] = {}
        self.tasks: dict[str, TaskState] = {}
        self.durable_request_journal: dict[str, tuple[str, int]] = {}
        self.replay_reservations: dict[str, str] = {}
        self.replay_commits: dict[str, str] = {}
        self.ledger = effect_ledger if effect_ledger is not None else SyntheticEffectLedger()

    def apply(self, command: Command) -> TransitionObservation:
        if command.at < self.clock:
            raise SystemExecutionError("logical time moved backwards")
        self.clock = command.at
        before_ledger = self.ledger.snapshot()
        before_hash = self.ledger.state_hash
        before_task = self._task_view(command.task_id)
        try:
            self._dispatch(command)
        except UnsafeSyntheticEffect as exc:
            task = self.tasks.get(command.task_id or "")
            if task is not None:
                task.phase = TaskPhase.DENIED
                task.denial_reason = DenialReason.UNSAFE_RESOURCE
            else:
                raise SystemExecutionError(str(exc)) from exc
        after_ledger = self.ledger.snapshot()
        return TransitionObservation(
            command={**asdict(command), "kind": command.kind.value},
            task_before=before_task,
            task_after=self._task_view(command.new_task_id or command.task_id),
            ledger_before_hash=before_hash,
            ledger_after_hash=self.ledger.state_hash,
            effect_delta=effect_delta(before_ledger, after_ledger),
            state_hash=self.state_hash,
        )

    def _dispatch(self, command: Command) -> None:
        if command.kind is CommandKind.SUBMIT:
            self._submit(command)
        elif command.kind is CommandKind.ADVANCE:
            self._advance(self._task(command.task_id))
        elif command.kind is CommandKind.REVOKE:
            if command.authorization_id not in self.authorizations:
                raise SystemExecutionError("cannot revoke an unknown authorization")
            self.revoked_at[str(command.authorization_id)] = self.clock
        elif command.kind is CommandKind.ADVANCE_EPOCH:
            if not isinstance(command.value, int) or isinstance(command.value, bool):
                raise SystemExecutionError("epoch transition requires an integer")
            if command.value < self.current_epoch:
                raise SystemExecutionError("authorization epoch cannot decrease")
            self.current_epoch = command.value
        elif command.kind is CommandKind.SET_SECURITY_STATE:
            if not isinstance(command.value, bool):
                raise SystemExecutionError("security-state transition requires a boolean")
            self.security_state_known = command.value
        elif command.kind is CommandKind.CRASH:
            self._crash(self._task(command.task_id))
        elif command.kind is CommandKind.RECOVER:
            self._recover(command)
        else:  # pragma: no cover - Enum makes this defensive.
            raise SystemExecutionError(f"unsupported command: {command.kind}")

    def _submit(self, command: Command) -> None:
        if not command.task_id or not command.request_id:
            raise SystemExecutionError("SUBMIT requires task_id and request_id")
        if command.task_id in self.tasks:
            raise SystemExecutionError(f"duplicate task id: {command.task_id}")
        try:
            request = self.requests[command.request_id]
            base_credential = self.authorizations[request.authorization_id]
            operation = self.operations[request.operation_id]
        except KeyError as exc:
            raise SystemExecutionError(f"invalid request fixture: {exc}") from exc
        credential = base_credential.with_overrides(request.credential_overrides)
        self.tasks[command.task_id] = TaskState(
            task_id=command.task_id,
            request=request,
            credential=credential,
            operation=operation,
        )
        self.durable_request_journal[command.task_id] = (request.request_id, 0)

    def _advance(self, task: TaskState) -> None:
        if task.phase is TaskPhase.RECEIVED:
            if task.credential.signature_valid is not True:
                self._deny(task, DenialReason.UNVERIFIED_CREDENTIAL)
            else:
                task.phase = TaskPhase.VERIFIED
            return
        if task.phase is TaskPhase.VERIFIED:
            reason = self._current_authority(task, include_replay=False)
            if reason is DenialReason.NONE:
                task.phase = TaskPhase.AUTHORIZED
            else:
                self._deny(task, reason)
            return
        if task.phase is TaskPhase.AUTHORIZED:
            reason = self._current_authority(task, include_replay=True)
            if reason is not DenialReason.NONE:
                self._deny(task, reason)
            elif self._reserve_replay(task):
                task.phase = TaskPhase.RESERVED
            else:
                self._deny(task, DenialReason.REPLAY)
            return
        if task.phase is TaskPhase.RESERVED:
            reason = self._current_authority(
                task, include_replay=True, allow_own_reservation=True
            )
            if reason is DenialReason.NONE:
                task.phase = TaskPhase.PREPARED
            else:
                self._release_reservation(task)
                self._deny(task, reason)
            return
        if task.phase is TaskPhase.PREPARED:
            reason = self._final_authority(task)
            if reason is not DenialReason.NONE:
                self._release_reservation(task)
                self._deny(task, reason)
            else:
                self._atomic_effect_and_replay_commit(task)
                task.phase = TaskPhase.EFFECTED
            return
        if task.phase is TaskPhase.EFFECTED:
            task.phase = TaskPhase.COMMITTED
            return
        if task.phase is TaskPhase.COMMITTED:
            task.phase = TaskPhase.RESPONDED
            return
        if task.phase in {TaskPhase.DENIED, TaskPhase.RESPONDED}:
            # Fixed schedules remain replayable across allow and deny outcomes.
            return
        raise SystemExecutionError(
            f"cannot advance terminal task {task.task_id} in {task.phase.value}"
        )

    def _current_authority(
        self,
        task: TaskState,
        *,
        include_replay: bool,
        allow_own_reservation: bool = False,
    ) -> DenialReason:
        if not self.security_state_known:
            return DenialReason.UNKNOWN_SECURITY_STATE
        credential = task.credential
        record = self.authorizations.get(credential.authorization_id)
        if record is None:
            return DenialReason.UNKNOWN_AUTHORIZATION
        if record.signature_valid is None:
            return DenialReason.UNKNOWN_SECURITY_STATE
        if record.signature_valid is not True:
            return DenialReason.UNVERIFIED_CREDENTIAL
        if credential.signature_valid is not record.signature_valid:
            return DenialReason.CREDENTIAL_SUBSTITUTION
        signed_fields = (
            "authorization_id",
            "subject",
            "scopes",
            "epoch",
            "origin_binding",
            "operation_digest",
            "issued_at",
            "expires_at",
            "nonce",
        )
        if any(getattr(credential, name) != getattr(record, name) for name in signed_fields):
            return DenialReason.CREDENTIAL_SUBSTITUTION
        if task.request.principal_id not in self.principals:
            return DenialReason.UNKNOWN_PRINCIPAL
        if credential.subject != task.request.principal_id:
            return DenialReason.IDENTITY_MISMATCH
        if self.clock < credential.issued_at:
            return DenialReason.NOT_YET_VALID
        if self.clock >= credential.expires_at:
            return DenialReason.EXPIRED
        revoked = self.revoked_at.get(credential.authorization_id)
        if revoked is not None and revoked <= self.clock:
            return DenialReason.REVOKED
        if credential.epoch != self.current_epoch:
            return DenialReason.STALE_EPOCH
        if credential.origin_binding != task.request.origin:
            return DenialReason.ORIGIN_MISMATCH
        expected_scope = f"{task.operation.action}:{task.operation.resource}"
        wildcard_scope = f"{task.operation.action}:*"
        if expected_scope not in credential.scopes and wildcard_scope not in credential.scopes:
            return DenialReason.SCOPE_MISMATCH
        if credential.operation_digest != task.operation.digest:
            return DenialReason.OPERATION_DIGEST_MISMATCH
        if include_replay:
            if credential.nonce in self.replay_commits:
                return DenialReason.REPLAY
            reservation = self.replay_reservations.get(credential.nonce)
            if reservation is not None and not (
                allow_own_reservation and reservation == task.task_id
            ):
                return DenialReason.REPLAY
        return DenialReason.NONE

    def _final_authority(self, task: TaskState) -> DenialReason:
        return self._current_authority(
            task, include_replay=True, allow_own_reservation=True
        )

    def _reserve_replay(self, task: TaskState) -> bool:
        nonce = task.credential.nonce
        if nonce in self.replay_commits or nonce in self.replay_reservations:
            return False
        self.replay_reservations[nonce] = task.task_id
        return True

    def _release_reservation(self, task: TaskState) -> None:
        if self.replay_reservations.get(task.credential.nonce) == task.task_id:
            self.replay_reservations.pop(task.credential.nonce, None)

    def _atomic_effect_and_replay_commit(self, task: TaskState) -> None:
        nonce = task.credential.nonce
        if self.replay_reservations.get(nonce) != task.task_id:
            raise SystemExecutionError("atomic commit lacks the task replay reservation")
        if nonce in self.replay_commits:
            raise SystemExecutionError("atomic commit encountered a consumed replay key")
        record = self._append_effect(task)
        self.replay_commits[nonce] = record.effect_id
        self.replay_reservations.pop(nonce, None)
        task.effect_id = record.effect_id

    def _append_effect(self, task: TaskState) -> EffectRecord:
        return self.ledger.append(
            logical_time=self.clock,
            task_id=task.task_id,
            request_id=task.request.request_id,
            principal_id=task.request.principal_id,
            authorization_id=task.credential.authorization_id,
            credential_nonce=task.credential.nonce,
            origin=task.request.origin,
            operation_id=task.operation.operation_id,
            operation_digest=task.operation.digest,
            action=task.operation.action,
            resource=task.operation.resource,
            arguments=task.operation.arguments,
            replay_key=task.credential.nonce,
        )

    def _crash(self, task: TaskState) -> None:
        if task.phase in {TaskPhase.RESPONDED, TaskPhase.CRASHED}:
            raise SystemExecutionError(f"cannot crash task in {task.phase.value}")
        task.crashed_phase = task.phase
        task.phase = TaskPhase.CRASHED

    def _recover(self, command: Command) -> None:
        old = self._task(command.task_id)
        if old.phase is not TaskPhase.CRASHED or old.crashed_phase is None:
            raise SystemExecutionError("only a crashed task can be recovered")
        if not command.new_task_id or command.new_task_id in self.tasks:
            raise SystemExecutionError("RECOVER requires a fresh new_task_id")
        journal_entry = self.durable_request_journal.get(old.task_id)
        if journal_entry is None:
            raise SystemExecutionError("durable recovery journal entry is missing")
        request_id, prior_generation = journal_entry
        request = self.requests.get(request_id)
        if request is None:
            raise SystemExecutionError("durable recovery request is unknown")
        base_credential = self.authorizations.get(request.authorization_id)
        operation = self.operations.get(request.operation_id)
        if base_credential is None or operation is None:
            raise SystemExecutionError("durable recovery fixtures are incomplete")
        recovered = TaskState(
            task_id=command.new_task_id,
            request=request,
            credential=base_credential.with_overrides(request.credential_overrides),
            operation=operation,
            recovery_generation=prior_generation + 1,
        )
        self.tasks[recovered.task_id] = recovered
        self.durable_request_journal[recovered.task_id] = (
            request_id,
            recovered.recovery_generation,
        )
        if not self.security_state_known:
            self._deny(recovered, DenialReason.UNKNOWN_SECURITY_STATE)
            return
        nonce = recovered.credential.nonce
        if nonce in self.replay_commits:
            recovered.effect_id = self.replay_commits[nonce]
            recovered.phase = TaskPhase.RESPONDED
            return
        if self.replay_reservations.get(nonce) == old.task_id:
            self.replay_reservations[nonce] = recovered.task_id
            recovered.phase = TaskPhase.RESERVED
            return
        recovered.phase = TaskPhase.RECEIVED

    def _deny(self, task: TaskState, reason: DenialReason) -> None:
        task.phase = TaskPhase.DENIED
        task.denial_reason = reason

    def _task(self, task_id: str | None) -> TaskState:
        if not task_id or task_id not in self.tasks:
            raise SystemExecutionError(f"unknown task: {task_id}")
        return self.tasks[task_id]

    def _task_view(self, task_id: str | None) -> dict[str, Any] | None:
        if not task_id or task_id not in self.tasks:
            return None
        return self.tasks[task_id].public_view()

    @property
    def state_hash(self) -> str:
        return "sha256:" + sha256_json(
            {
                "clock": self.clock,
                "current_epoch": self.current_epoch,
                "security_state_known": self.security_state_known,
                "revoked_at": dict(sorted(self.revoked_at.items())),
                "reservations": dict(sorted(self.replay_reservations.items())),
                "commits": dict(sorted(self.replay_commits.items())),
                "durable_request_journal": {
                    key: list(self.durable_request_journal[key])
                    for key in sorted(self.durable_request_journal)
                },
                "tasks": [
                    self.tasks[key].public_view() for key in sorted(self.tasks)
                ],
                "ledger": [item.to_dict() for item in self.ledger.snapshot()],
            }
        )

    def final_state(self) -> dict[str, Any]:
        return {
            "system_id": self.system_id,
            "clock": self.clock,
            "current_epoch": self.current_epoch,
            "security_state_known": self.security_state_known,
            "tasks": [self.tasks[key].public_view() for key in sorted(self.tasks)],
            "effects": [item.to_dict() for item in self.ledger.snapshot()],
            "ledger_hash": self.ledger.state_hash,
            "state_hash": self.state_hash,
        }


class ReplayDefectiveSyntheticSystem(CorrectSyntheticSystem):
    """Deliberate sentinel: replay keys are neither reserved nor enforced."""

    system_id = "defective-replay-v1"
    deliberately_defective = True

    def _current_authority(
        self,
        task: TaskState,
        *,
        include_replay: bool,
        allow_own_reservation: bool = False,
    ) -> DenialReason:
        return super()._current_authority(
            task, include_replay=False, allow_own_reservation=allow_own_reservation
        )

    def _reserve_replay(self, task: TaskState) -> bool:
        return True

    def _atomic_effect_and_replay_commit(self, task: TaskState) -> None:
        record = self._append_effect(task)
        task.effect_id = record.effect_id


class FinalRecheckDefectiveSyntheticSystem(CorrectSyntheticSystem):
    """Deliberate sentinel: authority is not rechecked at effect commit."""

    system_id = "defective-final-recheck-v1"
    deliberately_defective = True

    def _final_authority(self, task: TaskState) -> DenialReason:
        return DenialReason.NONE


class DenyAllSyntheticSystem(CorrectSyntheticSystem):
    """Negative qualification sentinel proving that deny-all cannot pass."""

    system_id = "deny-all-v1"
    deliberately_defective = True

    def _current_authority(
        self,
        task: TaskState,
        *,
        include_replay: bool,
        allow_own_reservation: bool = False,
    ) -> DenialReason:
        return DenialReason.UNKNOWN_AUTHORIZATION


SYSTEMS = {
    CorrectSyntheticSystem.system_id: CorrectSyntheticSystem,
    ReplayDefectiveSyntheticSystem.system_id: ReplayDefectiveSyntheticSystem,
    FinalRecheckDefectiveSyntheticSystem.system_id: FinalRecheckDefectiveSyntheticSystem,
    DenyAllSyntheticSystem.system_id: DenyAllSyntheticSystem,
}

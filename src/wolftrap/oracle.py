"""Independent reference-state oracle.

This module does not import the SUT, its policy helpers, or its canonical encoder.
It simulates the published state-machine contract and judges actual ledger deltas.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .effects import EffectRecord
from .model import Command, CommandKind, ExperimentCase, TaskPhase


class OracleCaseError(ValueError):
    pass


def _encoded(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_encoded(value)).hexdigest()


def oracle_operation_digest(operation: Mapping[str, Any]) -> str:
    # Independently specified rather than calling wolftrap.canonical.operation_digest.
    value = {
        "action": operation["action"],
        "arguments": operation["arguments"],
        "protected": operation["protected"],
        "resource": operation["resource"],
    }
    return "sha256:" + _hash(value)


@dataclass
class _OracleTask:
    task_id: str
    request: dict[str, Any]
    credential: dict[str, Any]
    operation: dict[str, Any]
    phase: str = "RECEIVED"
    denial_reason: str = "NONE"
    crashed_phase: str | None = None
    recovery_generation: int = 0
    effect_present: bool = False

    def view(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "request_id": self.request["request_id"],
            "phase": self.phase,
            "denial_reason": self.denial_reason,
            "crashed_phase": self.crashed_phase,
            "recovery_generation": self.recovery_generation,
            "effect_present": self.effect_present,
        }


@dataclass(frozen=True)
class OracleViolation:
    invariant: str
    code: str
    command_index: int
    detail: str
    effect_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariant": self.invariant,
            "code": self.code,
            "command_index": self.command_index,
            "detail": self.detail,
            "effect_ids": list(self.effect_ids),
        }


@dataclass(frozen=True)
class OracleAssessment:
    passed: bool
    violations: tuple[OracleViolation, ...]
    expected_effects: tuple[dict[str, Any], ...]
    observed_effects: tuple[dict[str, Any], ...]
    expected_tasks: tuple[dict[str, Any], ...]
    observed_tasks: tuple[dict[str, Any], ...]
    oracle_state_hash: str
    observed_ledger_hash: str
    trace_hashes: tuple[str, ...]
    coverage: dict[str, Any]

    @property
    def fingerprint(self) -> str:
        effect_fields = (
            "effect_id",
            "sequence",
            "logical_time",
            "task_id",
            "request_id",
            "principal_id",
            "authorization_id",
            "credential_nonce",
            "origin",
            "operation_id",
            "operation_digest",
            "action",
            "resource",
            "replay_key",
            "argument_digest",
            "payload_digest",
        )
        shape = {
            "violations": [
                {
                    "invariant": violation.invariant,
                    "code": violation.code,
                    "command_index": violation.command_index,
                    "effect_count": len(violation.effect_ids),
                    "effect_ids": list(violation.effect_ids),
                }
                for violation in self.violations
            ],
            "expected_effects": [
                {field: effect.get(field) for field in effect_fields}
                for effect in self.expected_effects
            ],
            "observed_effects": [
                {field: effect.get(field) for field in effect_fields}
                for effect in self.observed_effects
            ],
            "expected_tasks": [
                {
                    "task_id": task.get("task_id"),
                    "request_id": task.get("request_id"),
                    "phase": task.get("phase"),
                    "denial_reason": task.get("denial_reason"),
                    "effect_present": task.get("effect_present"),
                    "crashed_phase": task.get("crashed_phase"),
                    "recovery_generation": task.get("recovery_generation"),
                }
                for task in self.expected_tasks
            ],
            "observed_tasks": [
                {
                    "task_id": task.get("task_id"),
                    "request_id": task.get("request_id"),
                    "phase": task.get("phase"),
                    "denial_reason": task.get("denial_reason"),
                    "effect_present": bool(task.get("effect_id")),
                    "crashed_phase": task.get("crashed_phase"),
                    "recovery_generation": task.get("recovery_generation"),
                }
                for task in self.observed_tasks
            ],
        }
        return "sha256:" + _hash(shape)

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "violations": [item.to_dict() for item in self.violations],
            "expected_effects": list(self.expected_effects),
            "observed_effects": list(self.observed_effects),
            "expected_tasks": list(self.expected_tasks),
            "observed_tasks": list(self.observed_tasks),
            "oracle_state_hash": self.oracle_state_hash,
            "observed_ledger_hash": self.observed_ledger_hash,
            "trace_hashes": list(self.trace_hashes),
            "coverage": self.coverage,
            "fingerprint": self.fingerprint,
        }


class _ReferenceMachine:
    """Raw-dictionary implementation kept separate from SUT data flow."""

    def __init__(self, case: ExperimentCase) -> None:
        self.clock = 0
        self.current_epoch = case.current_epoch
        self.security_known = case.security_state_known
        self.principals = {item.principal_id for item in case.principals}
        self.grants = {
            item.authorization_id: {
                "authorization_id": item.authorization_id,
                "subject": item.subject,
                "scopes": list(item.scopes),
                "epoch": item.epoch,
                "origin_binding": item.origin_binding,
                "operation_digest": item.operation_digest,
                "issued_at": item.issued_at,
                "expires_at": item.expires_at,
                "signature_valid": item.signature_valid,
                "nonce": item.nonce,
            }
            for item in case.authorizations
        }
        self.operations = {
            item.operation_id: {
                "operation_id": item.operation_id,
                "action": item.action,
                "resource": item.resource,
                "arguments": dict(item.arguments),
                "protected": item.protected,
            }
            for item in case.operations
        }
        self.requests = {
            item.request_id: {
                "request_id": item.request_id,
                "principal_id": item.principal_id,
                "authorization_id": item.authorization_id,
                "operation_id": item.operation_id,
                "origin": item.origin,
                "credential_overrides": dict(item.credential_overrides),
            }
            for item in case.requests
        }
        self.revoked: dict[str, int] = {}
        self.reservations: dict[str, str] = {}
        self.committed: dict[str, int] = {}
        self.tasks: dict[str, _OracleTask] = {}
        self.durable_request_journal: dict[str, tuple[str, int]] = {}
        self.effects: list[dict[str, Any]] = []
        self.denial_reasons: set[str] = set()
        self.phases: set[str] = set()

    def apply(self, command: Command) -> list[dict[str, Any]]:
        if command.at < self.clock:
            raise OracleCaseError("logical time moved backwards")
        self.clock = command.at
        before = len(self.effects)
        if command.kind is CommandKind.SUBMIT:
            self._submit(command)
        elif command.kind is CommandKind.ADVANCE:
            self._advance(self._task(command.task_id))
        elif command.kind is CommandKind.REVOKE:
            if command.authorization_id not in self.grants:
                raise OracleCaseError("reference revoke targets an unknown grant")
            self.revoked[str(command.authorization_id)] = self.clock
        elif command.kind is CommandKind.ADVANCE_EPOCH:
            if type(command.value) is not int or command.value < self.current_epoch:
                raise OracleCaseError("invalid reference epoch transition")
            self.current_epoch = command.value
        elif command.kind is CommandKind.SET_SECURITY_STATE:
            if type(command.value) is not bool:
                raise OracleCaseError("invalid reference security-state transition")
            self.security_known = command.value
        elif command.kind is CommandKind.CRASH:
            task = self._task(command.task_id)
            if task.phase in {"RESPONDED", "CRASHED"}:
                raise OracleCaseError("invalid reference crash point")
            task.crashed_phase = task.phase
            task.phase = "CRASHED"
            self.phases.add(task.phase)
        elif command.kind is CommandKind.RECOVER:
            self._recover(command)
        else:  # pragma: no cover
            raise OracleCaseError("unsupported reference command")
        return self.effects[before:]

    def _submit(self, command: Command) -> None:
        if not command.task_id or not command.request_id:
            raise OracleCaseError("invalid reference submission")
        if command.task_id in self.tasks or command.request_id not in self.requests:
            raise OracleCaseError("duplicate task or unknown request")
        request = dict(self.requests[command.request_id])
        if request["authorization_id"] not in self.grants:
            raise OracleCaseError("unknown fixture credential")
        credential = dict(self.grants[request["authorization_id"]])
        credential.update(request["credential_overrides"])
        if isinstance(credential.get("scopes"), tuple):
            credential["scopes"] = list(credential["scopes"])
        operation = dict(self.operations[request["operation_id"]])
        self.tasks[command.task_id] = _OracleTask(
            task_id=command.task_id,
            request=request,
            credential=credential,
            operation=operation,
        )
        self.durable_request_journal[command.task_id] = (request["request_id"], 0)
        self.phases.add("RECEIVED")

    def _advance(self, task: _OracleTask) -> None:
        if task.phase == "RECEIVED":
            if task.credential.get("signature_valid") is not True:
                self._deny(task, "UNVERIFIED_CREDENTIAL")
            else:
                task.phase = "VERIFIED"
        elif task.phase == "VERIFIED":
            reason = self.authority_reason(task, replay=False)
            if reason == "NONE":
                task.phase = "AUTHORIZED"
            else:
                self._deny(task, reason)
        elif task.phase == "AUTHORIZED":
            reason = self.authority_reason(task, replay=True)
            nonce = str(task.credential.get("nonce"))
            if reason != "NONE":
                self._deny(task, reason)
            elif nonce in self.reservations or nonce in self.committed:
                self._deny(task, "REPLAY")
            else:
                self.reservations[nonce] = task.task_id
                task.phase = "RESERVED"
        elif task.phase == "RESERVED":
            reason = self.authority_reason(task, replay=True, own_reservation=True)
            if reason == "NONE":
                task.phase = "PREPARED"
            else:
                self._release(task)
                self._deny(task, reason)
        elif task.phase == "PREPARED":
            reason = self.authority_reason(task, replay=True, own_reservation=True)
            if reason != "NONE":
                self._release(task)
                self._deny(task, reason)
            else:
                self._commit(task)
                task.phase = "EFFECTED"
        elif task.phase == "EFFECTED":
            task.phase = "COMMITTED"
        elif task.phase == "COMMITTED":
            task.phase = "RESPONDED"
        elif task.phase in {"DENIED", "RESPONDED"}:
            pass
        else:
            raise OracleCaseError(f"cannot advance reference task in {task.phase}")
        self.phases.add(task.phase)

    def authority_reason(
        self, task: _OracleTask, *, replay: bool, own_reservation: bool = False
    ) -> str:
        if not self.security_known:
            return "UNKNOWN_SECURITY_STATE"
        credential = task.credential
        if credential.get("signature_valid") is not True:
            return "UNVERIFIED_CREDENTIAL"
        grant = self.grants.get(credential.get("authorization_id"))
        if grant is None:
            return "UNKNOWN_AUTHORIZATION"
        if grant.get("signature_valid") is None:
            return "UNKNOWN_SECURITY_STATE"
        if grant.get("signature_valid") is not True:
            return "UNVERIFIED_CREDENTIAL"
        if credential.get("signature_valid") is not grant.get("signature_valid"):
            return "CREDENTIAL_SUBSTITUTION"
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
        for field in signed_fields:
            left = credential.get(field)
            right = grant.get(field)
            if field == "scopes":
                left, right = list(left or []), list(right or [])
            if left != right:
                return "CREDENTIAL_SUBSTITUTION"
        principal = task.request["principal_id"]
        if principal not in self.principals:
            return "UNKNOWN_PRINCIPAL"
        if credential["subject"] != principal:
            return "IDENTITY_MISMATCH"
        if self.clock < credential["issued_at"]:
            return "NOT_YET_VALID"
        if self.clock >= credential["expires_at"]:
            return "EXPIRED"
        revoked_at = self.revoked.get(credential["authorization_id"])
        if revoked_at is not None and revoked_at <= self.clock:
            return "REVOKED"
        if credential["epoch"] != self.current_epoch:
            return "STALE_EPOCH"
        if credential["origin_binding"] != task.request["origin"]:
            return "ORIGIN_MISMATCH"
        exact_scope = f"{task.operation['action']}:{task.operation['resource']}"
        wildcard_scope = f"{task.operation['action']}:*"
        if exact_scope not in credential["scopes"] and wildcard_scope not in credential["scopes"]:
            return "SCOPE_MISMATCH"
        if credential["operation_digest"] != oracle_operation_digest(task.operation):
            return "OPERATION_DIGEST_MISMATCH"
        if replay:
            nonce = credential["nonce"]
            if nonce in self.committed:
                return "REPLAY"
            owner = self.reservations.get(nonce)
            if owner is not None and not (own_reservation and owner == task.task_id):
                return "REPLAY"
        return "NONE"

    def audit_actual_effect(self, effect: EffectRecord, *, expected_sequence: int) -> str:
        task = self.tasks.get(effect.task_id)
        if task is None:
            return "EFFECT_FROM_UNKNOWN_TASK"
        if task.phase != "PREPARED":
            return "EFFECT_AT_INVALID_PHASE"
        reason = self.authority_reason(task, replay=True, own_reservation=True)
        if reason != "NONE":
            return reason
        expected = {
            "sequence": expected_sequence,
            "request_id": task.request["request_id"],
            "principal_id": task.request["principal_id"],
            "authorization_id": task.credential["authorization_id"],
            "credential_nonce": task.credential["nonce"],
            "origin": task.request["origin"],
            "operation_id": task.operation["operation_id"],
            "operation_digest": oracle_operation_digest(task.operation),
            "action": task.operation["action"],
            "resource": task.operation["resource"],
            "replay_key": task.credential["nonce"],
            "logical_time": self.clock,
        }
        for field, expected_value in expected.items():
            if getattr(effect, field) != expected_value:
                return f"EFFECT_EVIDENCE_MISMATCH_{field.upper()}"
        expected_argument_digest = "sha256:" + _hash(task.operation["arguments"])
        if effect.argument_digest != expected_argument_digest:
            return "EFFECT_EVIDENCE_MISMATCH_ARGUMENT_DIGEST"
        expected_payload_digest = "sha256:" + _hash(
            {
                "action": task.operation["action"],
                "arguments": task.operation["arguments"],
                "resource": task.operation["resource"],
            }
        )
        if effect.payload_digest != expected_payload_digest:
            return "EFFECT_EVIDENCE_MISMATCH_PAYLOAD_DIGEST"
        expected_effect_id = "WT-E-" + _hash(
            {
                "authorization_id": task.credential["authorization_id"],
                "credential_nonce": task.credential["nonce"],
                "operation_digest": oracle_operation_digest(task.operation),
                "sequence": expected_sequence,
            }
        )[:16].upper()
        if effect.effect_id != expected_effect_id:
            return "EFFECT_EVIDENCE_MISMATCH_EFFECT_ID"
        return "NONE"

    def _commit(self, task: _OracleTask) -> None:
        nonce = task.credential["nonce"]
        if self.reservations.get(nonce) != task.task_id or nonce in self.committed:
            raise OracleCaseError("reference atomic replay precondition failed")
        sequence = len(self.effects) + 1
        effect = {
            "sequence": sequence,
            "logical_time": self.clock,
            "task_id": task.task_id,
            "request_id": task.request["request_id"],
            "principal_id": task.request["principal_id"],
            "authorization_id": task.credential["authorization_id"],
            "credential_nonce": task.credential["nonce"],
            "origin": task.request["origin"],
            "operation_id": task.operation["operation_id"],
            "operation_digest": oracle_operation_digest(task.operation),
            "action": task.operation["action"],
            "resource": task.operation["resource"],
            "replay_key": nonce,
        }
        self.effects.append(effect)
        self.committed[nonce] = sequence
        self.reservations.pop(nonce, None)
        task.effect_present = True

    def _release(self, task: _OracleTask) -> None:
        nonce = task.credential.get("nonce")
        if self.reservations.get(nonce) == task.task_id:
            self.reservations.pop(nonce, None)

    def _recover(self, command: Command) -> None:
        old = self._task(command.task_id)
        if old.phase != "CRASHED" or old.crashed_phase is None:
            raise OracleCaseError("invalid reference recovery source")
        if not command.new_task_id or command.new_task_id in self.tasks:
            raise OracleCaseError("invalid reference recovery target")
        journal_entry = self.durable_request_journal.get(old.task_id)
        if journal_entry is None:
            raise OracleCaseError("reference durable recovery entry is missing")
        request_id, prior_generation = journal_entry
        request = dict(self.requests[request_id])
        credential = dict(self.grants[request["authorization_id"]])
        credential.update(request["credential_overrides"])
        operation = dict(self.operations[request["operation_id"]])
        task = _OracleTask(
            task_id=command.new_task_id,
            request=request,
            credential=credential,
            operation=operation,
            recovery_generation=prior_generation + 1,
        )
        self.tasks[task.task_id] = task
        self.durable_request_journal[task.task_id] = (
            request_id,
            task.recovery_generation,
        )
        if not self.security_known:
            self._deny(task, "UNKNOWN_SECURITY_STATE")
        elif task.credential["nonce"] in self.committed:
            task.effect_present = True
            task.phase = "RESPONDED"
        elif self.reservations.get(task.credential["nonce"]) == old.task_id:
            self.reservations[task.credential["nonce"]] = task.task_id
            task.phase = "RESERVED"
        else:
            task.phase = "RECEIVED"
        self.phases.add(task.phase)

    def _deny(self, task: _OracleTask, reason: str) -> None:
        task.phase = "DENIED"
        task.denial_reason = reason
        self.denial_reasons.add(reason)
        self.phases.add("DENIED")

    def _task(self, task_id: str | None) -> _OracleTask:
        if task_id is None or task_id not in self.tasks:
            raise OracleCaseError(f"unknown reference task: {task_id}")
        return self.tasks[task_id]

    def task_view(self, task_id: str | None) -> dict[str, Any] | None:
        if task_id is None or task_id not in self.tasks:
            return None
        return self.tasks[task_id].view()

    def state_hash(self) -> str:
        return "sha256:" + _hash(
            {
                "clock": self.clock,
                "current_epoch": self.current_epoch,
                "security_known": self.security_known,
                "revoked": dict(sorted(self.revoked.items())),
                "reservations": dict(sorted(self.reservations.items())),
                "committed": dict(sorted(self.committed.items())),
                "durable_request_journal": {
                    key: list(self.durable_request_journal[key])
                    for key in sorted(self.durable_request_journal)
                },
                "tasks": [self.tasks[key].view() for key in sorted(self.tasks)],
                "effects": self.effects,
            }
        )


def _invariant_for_reason(reason: str) -> str:
    if reason == "ORIGIN_MISMATCH":
        return "NO_VALID_ORIGIN_BINDING_NO_PROTECTED_EFFECT"
    if reason == "REVOKED":
        return "REVOKED_AUTHORITY_NO_NEW_PROTECTED_EFFECT"
    if reason == "REPLAY" or reason == "DUPLICATE_REPLAY_KEY":
        return "REPLAYED_AUTHORIZATION_NO_DUPLICATE_EFFECT"
    if reason == "UNKNOWN_SECURITY_STATE":
        return "UNKNOWN_SECURITY_STATE_FAIL_CLOSED"
    if reason in {
        "UNVERIFIED_CREDENTIAL",
        "UNKNOWN_AUTHORIZATION",
        "CREDENTIAL_SUBSTITUTION",
        "IDENTITY_MISMATCH",
        "SCOPE_MISMATCH",
        "OPERATION_DIGEST_MISMATCH",
        "EXPIRED",
        "STALE_EPOCH",
        "NOT_YET_VALID",
        "UNKNOWN_PRINCIPAL",
    }:
        return "NO_CURRENT_AUTHORITY_NO_PROTECTED_EFFECT"
    return "AUTHORIZED_DOES_NOT_MEAN_EXECUTED"


def _task_comparable(view: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if view is None:
        return None
    return {
        "task_id": view.get("task_id"),
        "request_id": view.get("request_id"),
        "phase": view.get("phase"),
        "denial_reason": view.get("denial_reason"),
        "crashed_phase": view.get("crashed_phase"),
        "recovery_generation": view.get("recovery_generation"),
        "effect_present": bool(view.get("effect_id"))
        if "effect_id" in view
        else bool(view.get("effect_present")),
    }


def _command_view(command: Command) -> dict[str, Any]:
    return {
        "kind": command.kind.value,
        "at": command.at,
        "task_id": command.task_id,
        "request_id": command.request_id,
        "authorization_id": command.authorization_id,
        "value": command.value,
        "new_task_id": command.new_task_id,
    }


def assess_execution(
    case: ExperimentCase,
    observations: Sequence[Any],
    final_state: Mapping[str, Any],
) -> OracleAssessment:
    if len(observations) != len(case.commands):
        raise OracleCaseError("observation count does not match command schedule")
    machine = _ReferenceMachine(case)
    violations: list[OracleViolation] = []
    trace_hashes: list[str] = []
    actual_replay_keys: set[str] = set()
    audited_effects = 0
    invariant_evaluations = 0
    observed_chain: list[EffectRecord] = []
    last_observed_tasks: dict[str, dict[str, Any]] = {}
    last_observed_state_hash: str | None = None
    independently_expected_state_hash = "sha256:" + _hash(
        {"case_digest": case.digest, "transition_chain": "executor-evidence-v1"}
    )

    for index, (command, observed) in enumerate(zip(case.commands, observations)):
        actual_delta = tuple(observed.effect_delta)
        if observed.command != _command_view(command):
            violations.append(
                OracleViolation(
                    invariant="UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
                    code="EVIDENCE_COMMAND_MISMATCH",
                    command_index=index,
                    detail="SUT observation command does not match the saved schedule.",
                    effect_ids=tuple(item.effect_id for item in actual_delta),
                )
            )
        expected_before_task = (
            last_observed_tasks.get(command.task_id)
            if command.task_id is not None
            else None
        )
        if observed.task_before != expected_before_task:
            violations.append(
                OracleViolation(
                    invariant="UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
                    code="EVIDENCE_TASK_CHAIN_BEFORE_MISMATCH",
                    command_index=index,
                    detail="Observed pre-command task state breaks the task evidence chain.",
                    effect_ids=tuple(item.effect_id for item in actual_delta),
                )
            )
        independently_expected_before_hash = "sha256:" + _hash(
            [effect.to_dict() for effect in observed_chain]
        )
        if observed.ledger_before_hash != independently_expected_before_hash:
            violations.append(
                OracleViolation(
                    invariant="UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
                    code="EVIDENCE_LEDGER_BEFORE_HASH_MISMATCH",
                    command_index=index,
                    detail="The transition's pre-effect ledger hash is not independently reproducible.",
                    effect_ids=tuple(item.effect_id for item in actual_delta),
                )
            )
        if command.at < machine.clock:
            raise OracleCaseError("logical time moved backwards before effect audit")
        machine.clock = command.at
        for effect in actual_delta:
            invariant_evaluations += 1
            audited_effects += 1
            reason = machine.audit_actual_effect(
                effect, expected_sequence=len(observed_chain) + 1
            )
            if effect.replay_key in actual_replay_keys:
                reason = "DUPLICATE_REPLAY_KEY"
            if reason != "NONE":
                violations.append(
                    OracleViolation(
                        invariant=_invariant_for_reason(reason),
                        code="UNAUTHORIZED_EFFECT_" + reason,
                        command_index=index,
                        detail=(
                            "Independent pre-commit state did not authorize the "
                            f"observed ledger append: {reason}."
                        ),
                        effect_ids=(effect.effect_id,),
                    )
                )
            actual_replay_keys.add(effect.replay_key)
            observed_chain.append(effect)

        independently_expected_after_hash = "sha256:" + _hash(
            [effect.to_dict() for effect in observed_chain]
        )
        if observed.ledger_after_hash != independently_expected_after_hash:
            violations.append(
                OracleViolation(
                    invariant="UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
                    code="EVIDENCE_LEDGER_AFTER_HASH_MISMATCH",
                    command_index=index,
                    detail="The transition's post-effect ledger hash is not independently reproducible.",
                    effect_ids=tuple(item.effect_id for item in actual_delta),
                )
            )

        independently_expected_state_hash = "sha256:" + _hash(
            {
                "previous_state_hash": independently_expected_state_hash,
                "command": observed.command,
                "task_before": observed.task_before,
                "task_after": observed.task_after,
                "ledger_before_hash": observed.ledger_before_hash,
                "ledger_after_hash": observed.ledger_after_hash,
                "effect_delta": [item.to_dict() for item in actual_delta],
            }
        )
        if observed.state_hash != independently_expected_state_hash:
            violations.append(
                OracleViolation(
                    invariant="UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
                    code="EVIDENCE_TRANSITION_STATE_HASH_MISMATCH",
                    command_index=index,
                    detail=(
                        "The transition state hash does not match the independently "
                        "recomputed executor evidence chain."
                    ),
                    effect_ids=tuple(item.effect_id for item in actual_delta),
                )
            )

        expected_delta = machine.apply(command)
        trace_hashes.append(machine.state_hash())
        expected_task = machine.task_view(command.new_task_id or command.task_id)
        actual_task = observed.task_after
        if _task_comparable(expected_task) != _task_comparable(actual_task):
            violations.append(
                OracleViolation(
                    invariant="AUTHORIZED_DOES_NOT_MEAN_EXECUTED",
                    code="TASK_STATE_DIVERGENCE",
                    command_index=index,
                    detail=(
                        f"Reference task state {_task_comparable(expected_task)} differs "
                        f"from SUT state {_task_comparable(actual_task)}."
                    ),
                    effect_ids=tuple(item.effect_id for item in actual_delta),
                )
            )
        observed_task_id = command.new_task_id or command.task_id
        if observed_task_id is not None and actual_task is not None:
            last_observed_tasks[observed_task_id] = dict(actual_task)
        last_observed_state_hash = observed.state_hash
        if len(expected_delta) != len(actual_delta):
            code = "MISSING_REQUIRED_EFFECT" if expected_delta else "UNEXPECTED_EFFECT"
            invariant = (
                "POSITIVE_CONTROL_MUST_EXECUTE"
                if expected_delta and not actual_delta
                else "NO_CURRENT_AUTHORITY_NO_PROTECTED_EFFECT"
            )
            violations.append(
                OracleViolation(
                    invariant=invariant,
                    code=code,
                    command_index=index,
                    detail=(
                        f"Reference expected {len(expected_delta)} effect(s); "
                        f"the ledger recorded {len(actual_delta)}."
                    ),
                    effect_ids=tuple(item.effect_id for item in actual_delta),
                )
            )

    observed_effects = tuple(dict(item) for item in final_state.get("effects", ()))
    expected_effects = tuple(dict(item) for item in machine.effects)
    observed_tasks = tuple(dict(item) for item in final_state.get("tasks", ()))
    expected_tasks = tuple(machine.tasks[key].view() for key in sorted(machine.tasks))
    chained_tasks = tuple(last_observed_tasks[key] for key in sorted(last_observed_tasks))
    if observed_tasks != chained_tasks:
        violations.append(
            OracleViolation(
                invariant="UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
                code="EVIDENCE_FINAL_TASKS_DISAGREE_WITH_TRANSITIONS",
                command_index=max(0, len(case.commands) - 1),
                detail="Final task state does not exactly match accumulated task transition evidence.",
            )
        )
    if (
        final_state.get("state_hash") != last_observed_state_hash
        or final_state.get("state_hash") != independently_expected_state_hash
    ):
        violations.append(
            OracleViolation(
                invariant="UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
                code="EVIDENCE_FINAL_STATE_HASH_MISMATCH",
                command_index=max(0, len(case.commands) - 1),
                detail="Final SUT state hash does not match the last transition state hash.",
            )
        )
    chained_effects = tuple(effect.to_dict() for effect in observed_chain)
    if observed_effects != chained_effects:
        violations.append(
            OracleViolation(
                invariant="UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
                code="EVIDENCE_FINAL_LEDGER_DISAGREES_WITH_TRANSITIONS",
                command_index=max(0, len(case.commands) - 1),
                detail="Final effect state does not exactly match the independently accumulated transition deltas.",
                effect_ids=tuple(
                    str(item.get("effect_id")) for item in observed_effects if item.get("effect_id")
                ),
            )
        )
    independently_expected_final_hash = "sha256:" + _hash(list(observed_effects))
    if final_state.get("ledger_hash") != independently_expected_final_hash:
        violations.append(
            OracleViolation(
                invariant="UNKNOWN_SECURITY_STATE_FAIL_CLOSED",
                code="EVIDENCE_FINAL_LEDGER_HASH_MISMATCH",
                command_index=max(0, len(case.commands) - 1),
                detail="Final ledger hash is not independently reproducible from final effect state.",
                effect_ids=tuple(
                    str(item.get("effect_id")) for item in observed_effects if item.get("effect_id")
                ),
            )
        )
    if len(expected_effects) != len(observed_effects):
        violations.append(
            OracleViolation(
                invariant=(
                    "POSITIVE_CONTROL_MUST_EXECUTE"
                    if len(expected_effects) > len(observed_effects)
                    else "REPLAYED_AUTHORIZATION_NO_DUPLICATE_EFFECT"
                ),
                code="FINAL_LEDGER_COUNT_DIVERGENCE",
                command_index=max(0, len(case.commands) - 1),
                detail=(
                    f"Final reference ledger has {len(expected_effects)} effect(s), "
                    f"observed ledger has {len(observed_effects)}."
                ),
                effect_ids=tuple(
                    str(item.get("effect_id")) for item in observed_effects if item.get("effect_id")
                ),
            )
        )
    if case.control == "POSITIVE":
        if len(expected_effects) != 1:
            violations.append(
                OracleViolation(
                    invariant="POSITIVE_CONTROL_MUST_EXECUTE",
                    code="POSITIVE_CONTROL_REFERENCE_INVALID",
                    command_index=max(0, len(case.commands) - 1),
                    detail=(
                        "A v0.1 positive control must be a fault-free schedule with "
                        "exactly one reference effect."
                    ),
                )
            )
        elif len(observed_effects) != 1:
            violations.append(
                OracleViolation(
                    invariant="POSITIVE_CONTROL_MUST_EXECUTE",
                    code="POSITIVE_CONTROL_FAILED",
                    command_index=max(0, len(case.commands) - 1),
                    detail="A legitimate positive control did not produce exactly one effect.",
                )
            )
    elif case.control == "NEGATIVE" and (expected_effects or observed_effects):
        violations.append(
            OracleViolation(
                invariant="NO_CURRENT_AUTHORITY_NO_PROTECTED_EFFECT",
                code="NEGATIVE_CONTROL_REFERENCE_INVALID",
                command_index=max(0, len(case.commands) - 1),
                detail="A v0.1 negative control must have zero reference and observed effects.",
                effect_ids=tuple(
                    str(item.get("effect_id"))
                    for item in observed_effects
                    if item.get("effect_id")
                ),
            )
        )

    # Stable de-duplication avoids inflating one ledger discrepancy into many findings.
    unique: list[OracleViolation] = []
    seen: set[tuple[str, str, int, tuple[str, ...]]] = set()
    for violation in violations:
        key = (
            violation.invariant,
            violation.code,
            violation.command_index,
            violation.effect_ids,
        )
        if key not in seen:
            unique.append(violation)
            seen.add(key)

    observed_ledger_hash = str(final_state.get("ledger_hash", "UNKNOWN"))
    return OracleAssessment(
        passed=not unique,
        violations=tuple(unique),
        expected_effects=expected_effects,
        observed_effects=observed_effects,
        expected_tasks=expected_tasks,
        observed_tasks=observed_tasks,
        oracle_state_hash=machine.state_hash(),
        observed_ledger_hash=observed_ledger_hash,
        trace_hashes=tuple(trace_hashes),
        coverage={
            "commands_evaluated": len(case.commands),
            "invariant_evaluations": invariant_evaluations,
            "effects_audited": audited_effects,
            "reference_phases_reached": sorted(machine.phases),
            "reference_denial_reasons": sorted(machine.denial_reasons),
            "invariants_requested": list(case.invariants),
        },
    )

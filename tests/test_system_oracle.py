from __future__ import annotations

import unittest
from dataclasses import replace

from wolftrap.execution import execute_case
from wolftrap.model import Command, CommandKind, DenialReason, RequestSpec, TaskPhase
from wolftrap.oracle import assess_execution
from wolftrap.system import (
    CorrectSyntheticSystem,
    DenyAllSyntheticSystem,
    FinalRecheckDefectiveSyntheticSystem,
    ReplayDefectiveSyntheticSystem,
    TransitionObservation,
)

from tests.helpers import advance, base_case


class AuthorizationOracleTests(unittest.TestCase):
    def assert_denied(self, case, reason: DenialReason) -> None:
        execution = execute_case(case, CorrectSyntheticSystem)
        self.assertTrue(execution.assessment.passed, execution.assessment.to_dict())
        self.assertEqual(execution.final_state["effects"], [])
        self.assertEqual(execution.final_state["tasks"][-1]["phase"], TaskPhase.DENIED.value)
        self.assertEqual(execution.final_state["tasks"][-1]["denial_reason"], reason.value)

    def test_legitimate_operation_commits_exactly_one_effect(self) -> None:
        execution = execute_case(base_case(), CorrectSyntheticSystem)
        self.assertTrue(execution.assessment.passed, execution.assessment.to_dict())
        self.assertEqual(len(execution.final_state["effects"]), 1)
        effect = execution.final_state["effects"][0]
        self.assertEqual(effect["resource"], "synthetic://vault/records")
        self.assertEqual(effect["principal_id"], "alice")
        self.assertEqual(execution.final_state["tasks"][0]["phase"], "RESPONDED")

    def test_identity_substitution_is_denied(self) -> None:
        request = RequestSpec(
            request_id="request-1",
            principal_id="mallory",
            authorization_id="auth-alice",
            operation_id="op-write",
            origin="synthetic-origin://employee",
            credential_overrides={},
        )
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 2),
        )
        self.assert_denied(base_case(request=request, commands=commands, control="NEGATIVE"), DenialReason.IDENTITY_MISMATCH)

    def test_origin_substitution_is_denied(self) -> None:
        request = RequestSpec(
            request_id="request-1",
            principal_id="alice",
            authorization_id="auth-alice",
            operation_id="op-write",
            origin="synthetic-origin://supplier-impostor",
            credential_overrides={},
        )
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 2),
        )
        self.assert_denied(base_case(request=request, commands=commands, control="NEGATIVE"), DenialReason.ORIGIN_MISMATCH)

    def test_scope_escalation_is_denied(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 2),
        )
        case = base_case(
            authorization_changes={"scopes": ("read:synthetic://vault/records",)},
            commands=commands,
            control="NEGATIVE",
        )
        self.assert_denied(case, DenialReason.SCOPE_MISMATCH)

    def test_operation_digest_substitution_is_denied(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 2),
        )
        case = base_case(
            authorization_changes={"operation_digest": "sha256:" + "0" * 64},
            commands=commands,
            control="NEGATIVE",
        )
        self.assert_denied(case, DenialReason.OPERATION_DIGEST_MISMATCH)

    def test_stale_epoch_is_denied(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 2),
        )
        self.assert_denied(base_case(current_epoch=2, commands=commands, control="NEGATIVE"), DenialReason.STALE_EPOCH)

    def test_expired_authorization_is_denied_at_half_open_boundary(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 2),
        )
        case = base_case(
            authorization_changes={"expires_at": 10},
            commands=commands,
            control="NEGATIVE",
        )
        self.assert_denied(case, DenialReason.EXPIRED)

    def test_unknown_security_state_fails_closed(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 2),
        )
        self.assert_denied(
            base_case(security_state_known=False, commands=commands, control="NEGATIVE"),
            DenialReason.UNKNOWN_SECURITY_STATE,
        )

    def test_verified_does_not_mean_current_authority(self) -> None:
        request = RequestSpec(
            request_id="request-1",
            principal_id="alice",
            authorization_id="auth-alice",
            operation_id="op-write",
            origin="synthetic-origin://employee",
            credential_overrides={"authorization_id": "unregistered-auth"},
        )
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 2),
        )
        self.assert_denied(base_case(request=request, commands=commands, control="NEGATIVE"), DenialReason.UNKNOWN_AUTHORIZATION)

    def test_revoked_authority_has_no_effect(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 1),
            Command(CommandKind.REVOKE, 11, authorization_id="auth-alice"),
            Command(CommandKind.ADVANCE, 11, task_id="task-1"),
        )
        self.assert_denied(base_case(commands=commands, control="NEGATIVE"), DenialReason.REVOKED)

    def test_replay_is_denied_without_duplicate_effect(self) -> None:
        request_two = RequestSpec(
            request_id="request-2",
            principal_id="alice",
            authorization_id="auth-alice",
            operation_id="op-write",
            origin="synthetic-origin://employee",
            credential_overrides={},
        )
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 7),
            Command(CommandKind.SUBMIT, 11, task_id="task-2", request_id="request-2"),
            *advance("task-2", 3, at=11),
        )
        execution = execute_case(
            base_case(commands=commands, extra_requests=(request_two,), control="MIXED"),
            CorrectSyntheticSystem,
        )
        self.assertTrue(execution.assessment.passed, execution.assessment.to_dict())
        self.assertEqual(len(execution.final_state["effects"]), 1)
        tasks = {task["task_id"]: task for task in execution.final_state["tasks"]}
        self.assertEqual(tasks["task-2"]["denial_reason"], "REPLAY")

    def test_explicit_concurrent_interleaving_linearizes_shared_replay_key(self) -> None:
        request_two = RequestSpec(
            request_id="request-2",
            principal_id="alice",
            authorization_id="auth-alice",
            operation_id="op-write",
            origin="synthetic-origin://employee",
            credential_overrides={},
        )
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="agent-a", request_id="request-1"),
            Command(CommandKind.SUBMIT, 10, task_id="agent-b", request_id="request-2"),
            Command(CommandKind.ADVANCE, 10, task_id="agent-a"),
            Command(CommandKind.ADVANCE, 10, task_id="agent-b"),
            Command(CommandKind.ADVANCE, 10, task_id="agent-a"),
            Command(CommandKind.ADVANCE, 10, task_id="agent-b"),
            Command(CommandKind.ADVANCE, 10, task_id="agent-a"),
            Command(CommandKind.ADVANCE, 10, task_id="agent-b"),
            *advance("agent-a", 4),
        )
        execution = execute_case(
            base_case(commands=commands, extra_requests=(request_two,), control="MIXED"),
            CorrectSyntheticSystem,
        )
        self.assertTrue(execution.assessment.passed, execution.assessment.to_dict())
        self.assertEqual(len(execution.final_state["effects"]), 1)

    def test_revocation_between_authorization_and_commit_is_rechecked(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 4),
            Command(CommandKind.REVOKE, 11, authorization_id="auth-alice"),
            Command(CommandKind.ADVANCE, 11, task_id="task-1"),
        )
        case = base_case(commands=commands, control="NEGATIVE")
        execution = execute_case(case, CorrectSyntheticSystem)
        self.assertTrue(execution.assessment.passed, execution.assessment.to_dict())
        self.assertEqual(execution.final_state["effects"], [])
        self.assertEqual(execution.final_state["tasks"][0]["denial_reason"], "REVOKED")

    def test_missing_final_recheck_sentinel_is_detected_from_ledger(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 4),
            Command(CommandKind.REVOKE, 11, authorization_id="auth-alice"),
            Command(CommandKind.ADVANCE, 11, task_id="task-1"),
        )
        execution = execute_case(
            base_case(commands=commands, control="NEGATIVE"),
            FinalRecheckDefectiveSyntheticSystem,
        )
        self.assertFalse(execution.assessment.passed)
        self.assertEqual(len(execution.final_state["effects"]), 1)
        codes = {item.code for item in execution.assessment.violations}
        self.assertIn("UNAUTHORIZED_EFFECT_REVOKED", codes)

    def test_replay_defect_sentinel_is_detected_before_duplicate_commit(self) -> None:
        request_two = RequestSpec(
            request_id="request-2",
            principal_id="alice",
            authorization_id="auth-alice",
            operation_id="op-write",
            origin="synthetic-origin://employee",
            credential_overrides={},
        )
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 7),
            Command(CommandKind.SUBMIT, 11, task_id="task-2", request_id="request-2"),
            *advance("task-2", 3, at=11),
        )
        execution = execute_case(
            base_case(commands=commands, extra_requests=(request_two,), control="MIXED"),
            ReplayDefectiveSyntheticSystem,
        )
        self.assertFalse(execution.assessment.passed)
        self.assertIn("TASK_STATE_DIVERGENCE", {item.code for item in execution.assessment.violations})

    def test_crash_before_effect_recovery_commits_once(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 4),
            Command(CommandKind.CRASH, 10, task_id="task-1"),
            Command(CommandKind.RECOVER, 11, task_id="task-1", new_task_id="task-retry"),
            *advance("task-retry", 4, at=11),
        )
        execution = execute_case(base_case(commands=commands), CorrectSyntheticSystem)
        self.assertTrue(execution.assessment.passed, execution.assessment.to_dict())
        self.assertEqual(len(execution.final_state["effects"]), 1)
        tasks = {task["task_id"]: task for task in execution.final_state["tasks"]}
        self.assertEqual(tasks["task-1"]["phase"], "CRASHED")
        self.assertEqual(tasks["task-retry"]["phase"], "RESPONDED")

    def test_crash_after_effect_recovery_does_not_repeat_effect(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 5),
            Command(CommandKind.CRASH, 10, task_id="task-1"),
            Command(CommandKind.RECOVER, 11, task_id="task-1", new_task_id="task-retry"),
        )
        execution = execute_case(base_case(commands=commands), CorrectSyntheticSystem)
        self.assertTrue(execution.assessment.passed, execution.assessment.to_dict())
        self.assertEqual(len(execution.final_state["effects"]), 1)
        tasks = {task["task_id"]: task for task in execution.final_state["tasks"]}
        self.assertEqual(tasks["task-retry"]["phase"], "RESPONDED")

    def test_unknown_recovery_state_fails_closed(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 3),
            Command(CommandKind.CRASH, 10, task_id="task-1"),
            Command(CommandKind.SET_SECURITY_STATE, 11, value=False),
            Command(CommandKind.RECOVER, 11, task_id="task-1", new_task_id="task-retry"),
        )
        execution = execute_case(base_case(commands=commands, control="NEGATIVE"), CorrectSyntheticSystem)
        self.assertTrue(execution.assessment.passed, execution.assessment.to_dict())
        self.assertEqual(execution.final_state["effects"], [])
        tasks = {task["task_id"]: task for task in execution.final_state["tasks"]}
        self.assertEqual(tasks["task-retry"]["denial_reason"], "UNKNOWN_SECURITY_STATE")

    def test_deny_all_cannot_match_positive_reference_state(self) -> None:
        commands = (
            Command(CommandKind.SUBMIT, 10, task_id="task-1", request_id="request-1"),
            *advance("task-1", 2),
        )
        execution = execute_case(base_case(commands=commands), DenyAllSyntheticSystem)
        self.assertFalse(execution.assessment.passed)
        self.assertIn("TASK_STATE_DIVERGENCE", {item.code for item in execution.assessment.violations})

    def test_oracle_does_not_accept_a_lying_response_over_ledger_state(self) -> None:
        case = base_case()
        system = CorrectSyntheticSystem(case)
        observations = [system.apply(command) for command in case.commands]
        final_state = system.final_state()
        effect_index = next(
            index for index, observation in enumerate(observations) if observation.effect_delta
        )
        original = observations[effect_index]
        lying_task = dict(original.task_after or {})
        lying_task["phase"] = "DENIED"
        lying_task["denial_reason"] = "UNKNOWN_AUTHORIZATION"
        observations[effect_index] = replace(original, task_after=lying_task)
        assessment = assess_execution(case, observations, final_state)
        self.assertFalse(assessment.passed)
        self.assertEqual(len(assessment.observed_effects), 1)
        self.assertIn("TASK_STATE_DIVERGENCE", {item.code for item in assessment.violations})

    def test_repeated_runs_have_identical_state_and_trace_hashes(self) -> None:
        first = execute_case(base_case(), CorrectSyntheticSystem)
        second = execute_case(base_case(), CorrectSyntheticSystem)
        self.assertEqual(first.final_state["state_hash"], second.final_state["state_hash"])
        self.assertEqual(first.assessment.trace_hashes, second.assessment.trace_hashes)
        self.assertEqual(first.assessment.observed_ledger_hash, second.assessment.observed_ledger_hash)


if __name__ == "__main__":
    unittest.main()

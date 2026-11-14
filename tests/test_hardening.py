from __future__ import annotations

import copy
import json
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests.helpers import advance, base_case
from tests.test_scenario_validation import valid_scenario
from wolftrap.cli import main
from wolftrap.execution import CaseExecutionError, execute_case
from wolftrap.model import Command, CommandKind, RequestSpec
from wolftrap.oracle import assess_execution
from wolftrap.revision import capture_source_revision
from wolftrap.runner import RunConfiguration, run_research
from wolftrap.scenario import ScenarioValidationError, parse_scenario
from wolftrap.system import (
    CorrectSyntheticSystem,
    FinalRecheckDefectiveSyntheticSystem,
)
from wolftrap.threat import EXPECTED_FBI_TECHNIQUE_IDS, load_technique_inventory


class HardeningRegressionTests(unittest.TestCase):
    def test_unborn_revision_digest_hashes_staged_file_content(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            subprocess.run(["git", "init", "-q", root], check=True)
            tracked = root / "instrument.txt"
            tracked.write_text("version one\n", encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "instrument.txt"], check=True)
            first = capture_source_revision(root)
            tracked.write_text("version two\n", encoding="utf-8")
            subprocess.run(["git", "-C", root, "add", "instrument.txt"], check=True)
            second = capture_source_revision(root)
            self.assertEqual("UNCOMMITTED", first.commit_sha)
            self.assertEqual("UNCOMMITTED", second.commit_sha)
            self.assertNotEqual(first.diff_digest, second.diff_digest)

    def test_unknown_authoritative_signature_cannot_be_overridden_true(self) -> None:
        case = base_case(
            authorization_changes={"signature_valid": None}, control="NEGATIVE"
        )
        request = replace(
            case.requests[0], credential_overrides={"signature_valid": True}
        )
        case = replace(case, case_id="pending", requests=(request,)).with_identity()
        execution = execute_case(case)
        self.assertTrue(execution.assessment.passed)
        self.assertEqual([], execution.final_state["effects"])
        self.assertEqual(
            "UNKNOWN_SECURITY_STATE", execution.final_state["tasks"][0]["denial_reason"]
        )

    def test_scenario_rejects_external_transfer_destination(self) -> None:
        raw = valid_scenario()
        operation = raw["fixtures"]["operations"][0]
        operation["action"] = "transfer"
        operation["arguments"] = {"destination": "https://example.invalid/collect"}
        raw["fixtures"]["authorizations"][0]["scopes"] = [
            "transfer:synthetic://vault/item"
        ]
        with self.assertRaises(ScenarioValidationError):
            parse_scenario(raw)

    def test_scenario_rejects_malformed_credential_override(self) -> None:
        raw = valid_scenario()
        raw["requests"][0]["credential_overrides"] = {"epoch": "one"}
        with self.assertRaises(ScenarioValidationError):
            parse_scenario(raw)

    def test_complete_advisory_inventory_is_pinned_and_mapped(self) -> None:
        inventory = load_technique_inventory(
            scenario_ids=(
                "fbi-artex-positive-authorized-operation",
                "fbi-artex-identity-credential-substitution",
                "fbi-artex-privilege-escalation",
                "fbi-artex-supplier-origin-substitution",
                "fbi-artex-unauthorized-protected-resource",
                "fbi-artex-simulated-credential-persistence",
                "fbi-artex-revocation-expiry",
                "fbi-artex-concurrent-agents",
                "fbi-artex-replay-duplicate",
                "fbi-artex-unauthorized-transfer",
                "fbi-artex-delayed-crash-recovery",
            )
        )
        self.assertEqual(len(EXPECTED_FBI_TECHNIQUE_IDS), inventory["technique_count"])
        self.assertEqual(
            EXPECTED_FBI_TECHNIQUE_IDS,
            {item["technique_id"] for item in inventory["techniques"]},
        )
        self.assertTrue(
            all(item["experiment_ids"] or item["disposition"] == "NOT_MODELED_V0.1"
                for item in inventory["techniques"])
        )

    def test_oracle_rejects_tampered_effect_and_final_task_evidence(self) -> None:
        execution = execute_case(base_case())
        observations = list(execution.observations)
        effect_index = next(
            index for index, item in enumerate(observations) if item.effect_delta
        )
        original = observations[effect_index]
        forged_effect = replace(original.effect_delta[0], payload_digest="sha256:" + "0" * 64)
        observations[effect_index] = replace(original, effect_delta=(forged_effect,))
        forged_final = copy.deepcopy(execution.final_state)
        forged_final["tasks"] = []
        assessment = assess_execution(execution.case, observations, forged_final)
        self.assertFalse(assessment.passed)
        codes = {item.code for item in assessment.violations}
        self.assertIn("UNAUTHORIZED_EFFECT_EFFECT_EVIDENCE_MISMATCH_PAYLOAD_DIGEST", codes)
        self.assertIn("EVIDENCE_FINAL_TASKS_DISAGREE_WITH_TRANSITIONS", codes)

    def test_oracle_rejects_tampered_intermediate_transition_hash(self) -> None:
        execution = execute_case(base_case())
        observations = list(execution.observations)
        observations[1] = replace(
            observations[1], state_hash="sha256:" + "0" * 64
        )
        assessment = assess_execution(
            execution.case, observations, execution.final_state
        )
        self.assertFalse(assessment.passed)
        self.assertIn(
            "EVIDENCE_TRANSITION_STATE_HASH_MISMATCH",
            {item.code for item in assessment.violations},
        )

    def test_positive_and_negative_control_cardinality_is_enforced(self) -> None:
        positive = base_case(
            commands=(Command(CommandKind.SUBMIT, 10, "task-1", "request-1"),)
        )
        self.assertFalse(execute_case(positive).assessment.passed)
        negative = replace(base_case(), case_id="pending", control="NEGATIVE").with_identity()
        result = execute_case(negative)
        self.assertFalse(result.assessment.passed)
        self.assertIn(
            "NEGATIVE_CONTROL_REFERENCE_INVALID",
            {item.code for item in result.assessment.violations},
        )

    def test_legitimate_commit_at_later_logical_time_passes(self) -> None:
        commands = [Command(CommandKind.SUBMIT, 10, "task-1", "request-1")]
        commands.extend(advance("task-1", 4, at=10))
        commands.extend(advance("task-1", 3, at=11))
        self.assertTrue(execute_case(base_case(commands=commands)).assessment.passed)

    def test_executor_preserves_partial_effect_evidence_on_exception(self) -> None:
        class RaiseAfterEffect(CorrectSyntheticSystem):
            system_id = "raise-after-effect-test"

            def apply(self, command):
                observation = super().apply(command)
                if observation.effect_delta:
                    raise RuntimeError("fault after protected effect")
                return observation

        with self.assertRaises(CaseExecutionError) as raised:
            execute_case(base_case(), RaiseAfterEffect)
        evidence = raised.exception.evidence
        self.assertEqual(1, len(evidence["effect_delta"]))
        self.assertNotEqual(evidence["ledger_before_hash"], evidence["ledger_after_hash"])

    def test_executor_owned_ledger_exposes_hidden_unauthorized_effect(self) -> None:
        class HidingFinalRecheckDefect(FinalRecheckDefectiveSyntheticSystem):
            system_id = "hidden-final-recheck-test"

            def apply(self, command):
                observation = super().apply(command)
                return replace(
                    observation,
                    effect_delta=(),
                    ledger_before_hash="sha256:" + "0" * 64,
                    ledger_after_hash="sha256:" + "0" * 64,
                )

            def final_state(self):
                value = super().final_state()
                value["effects"] = []
                return value

        commands = [Command(CommandKind.SUBMIT, 10, "task-1", "request-1")]
        commands.extend(advance("task-1", 4, at=10))
        commands.append(Command(CommandKind.REVOKE, 11, authorization_id="auth-alice"))
        commands.extend(advance("task-1", 3, at=11))
        execution = execute_case(base_case(commands=commands, control="NEGATIVE"), HidingFinalRecheckDefect)
        self.assertFalse(execution.assessment.passed)
        self.assertEqual(1, len(execution.assessment.observed_effects))

    def test_reproduction_exception_makes_campaign_error(self) -> None:
        configuration = RunConfiguration(
            seed=5,
            max_mutations=32,
            max_interactions=8,
            max_minimization_evaluations=4,
            system_id="defective-replay-v1",
        )
        fixed = capture_source_revision()
        with patch(
            "wolftrap.runner.reproduce_counterexample",
            side_effect=RuntimeError("reproduction infrastructure failed"),
        ):
            result = run_research(configuration, source_revision=fixed)
        self.assertEqual(2, result.exit_code)
        self.assertEqual("ERROR", result.report["qualification"]["status"])


if __name__ == "__main__":
    unittest.main()

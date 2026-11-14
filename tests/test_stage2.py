from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from wolftrap.execution import execute_case
from wolftrap.explorer import _mutated_case, _scenario_for_axis
from wolftrap.scenario import load_corpus
from wolftrap.stage2 import Stage2Configuration, run_stage2
from wolftrap.system import CorrectSyntheticSystem


class Stage2ResearchTests(unittest.TestCase):
    def test_revoke_after_committed_effect_is_mixed_not_negative(self) -> None:
        scenario = _scenario_for_axis(load_corpus(), "retry_recovery")
        for unknown in (False, True):
            with self.subTest(unknown_recovery=unknown):
                case = _mutated_case(
                    scenario,
                    ("revocation_timing", "retry_recovery"),
                    seed=13,
                    crash_site=5,
                    unknown_recovery=unknown,
                )
                self.assertEqual(case.control, "MIXED")
                execution = execute_case(case, CorrectSyntheticSystem)
                self.assertTrue(execution.assessment.passed)
                self.assertEqual(len(execution.final_state["effects"]), 1)

    def test_revoke_before_effect_is_still_a_strict_negative(self) -> None:
        scenario = _scenario_for_axis(load_corpus(), "retry_recovery")
        case = _mutated_case(
            scenario,
            ("revocation_timing", "retry_recovery"),
            seed=13,
            crash_site=4,
        )
        self.assertEqual(case.control, "NEGATIVE")
        execution = execute_case(case, CorrectSyntheticSystem)
        self.assertTrue(execution.assessment.passed)
        self.assertEqual(execution.final_state["effects"], [])

    def test_complete_pair_frontier_has_durable_per_seed_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-stage2-test-") as directory:
            outcome = run_stage2(
                Stage2Configuration(first_seed=20261113, seed_count=1),
                output_dir=directory,
                unit_test_summary=None,
            )
            # Deliberately missing unit-test attestation prevents PASS, even
            # though all synthetic cases and pair interactions pass.
            self.assertEqual(outcome.exit_code, 1)
            self.assertEqual(outcome.report["qualification"]["status"], "FAIL")
            self.assertEqual(outcome.report["summary"]["findings"], 0)
            self.assertEqual(outcome.report["pair_coverage"]["unique_pairs_reached"], 55)
            self.assertTrue(outcome.report["pair_coverage"]["complete_per_seed"])
            self.assertEqual(outcome.report["campaigns"][0]["executed_pairs"], 55)
            self.assertEqual(outcome.report["campaigns"][0]["internal_errors"], 0)
            summary_bytes = (Path(directory) / "stage2-summary.json").read_bytes()
            manifest = json.loads((Path(directory) / "stage2-manifest.json").read_text())
            self.assertEqual(manifest["state"], "COMPLETE")
            self.assertEqual(manifest["report_sha256"], hashlib.sha256(summary_bytes).hexdigest())

    def test_sentinel_failure_still_blocks_the_full_sweep(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-stage2-sentinel-") as directory:
            outcome = run_stage2(
                Stage2Configuration(
                    first_seed=20261113,
                    seed_count=1,
                    system_id="defective-final-recheck-v1",
                ),
                output_dir=directory,
                unit_test_summary=None,
            )
            self.assertEqual(outcome.exit_code, 1)
            self.assertGreaterEqual(outcome.report["summary"]["findings"], 3)
            self.assertEqual(outcome.report["pair_coverage"]["unique_pairs_reached"], 55)

    def test_invalid_unbounded_sweep_is_rejected_before_writing(self) -> None:
        for config in (
            Stage2Configuration(seed_count=5),
            Stage2Configuration(mutation_budget=1000),
            Stage2Configuration(first_seed=-1),
            Stage2Configuration(system_id="external-target"),
        ):
            with self.subTest(config=config):
                with self.assertRaises(ValueError):
                    config.validate()

    def test_existing_evidence_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-stage2-existing-") as directory:
            marker = Path(directory) / "original-evidence.txt"
            marker.write_text("retain-this", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "must be empty"):
                run_stage2(
                    Stage2Configuration(seed_count=1),
                    output_dir=directory,
                    unit_test_summary=None,
                )
            self.assertEqual(marker.read_text(encoding="utf-8"), "retain-this")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import unittest

from wolftrap.execution import execute_case
from wolftrap.explorer import (
    MUTATION_AXES,
    ExplorationBounds,
    explore,
    result_manifest,
)
from wolftrap.scenario import load_corpus
from wolftrap.system import (
    CorrectSyntheticSystem,
    FinalRecheckDefectiveSyntheticSystem,
    ReplayDefectiveSyntheticSystem,
)


class StatefulExplorerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.corpus = load_corpus()
        cls.bounds = ExplorationBounds(
            max_cases=len(cls.corpus) + 13,
            max_commands_per_case=128,
            max_interactions=3,
            max_schedules=5,
            max_seeded_cases=0,
        )

    def test_same_seed_is_manifest_identical_regardless_of_corpus_order(self) -> None:
        first = explore(self.corpus, seed=4242, bounds=self.bounds)
        second = explore(tuple(reversed(self.corpus)), seed=4242, bounds=self.bounds)
        self.assertEqual(result_manifest(first), result_manifest(second))

    def test_different_seeds_change_complete_saved_cases(self) -> None:
        first = explore(self.corpus, seed=1, bounds=self.bounds)
        second = explore(self.corpus, seed=2, bounds=self.bounds)
        self.assertNotEqual(
            [case.digest for case in first.cases],
            [case.digest for case in second.cases],
        )

    def test_all_required_axes_and_compositions_are_covered_truthfully(self) -> None:
        result = explore(self.corpus, seed=20261113, bounds=self.bounds)
        coverage = result.coverage
        self.assertEqual(set(MUTATION_AXES), set(coverage["generated_mutation_axes"]))
        self.assertEqual([], coverage["missing_mutation_axes"])
        self.assertEqual(3, coverage["interactions"]["generated"])
        self.assertEqual(2, coverage["interactions"]["max_depth"])
        self.assertTrue(coverage["bounded_not_exhaustive"])
        self.assertTrue(coverage["truncated"])
        self.assertIn("max_interactions", coverage["truncation_reasons"])
        self.assertTrue(
            any(case.interaction_depth == 2 for case in result.cases),
            "multi-stage adversarial cases must be executable artifacts",
        )

    def test_explicit_race_and_crash_schedules_do_not_use_os_scheduling(self) -> None:
        bounds = ExplorationBounds(
            max_cases=48,
            max_commands_per_case=128,
            max_interactions=1,
            max_schedules=24,
            max_seeded_cases=2,
        )
        coverage = explore(self.corpus, seed=9, bounds=bounds).coverage
        schedules = coverage["schedules"]
        self.assertFalse(schedules["uses_os_thread_scheduling"])
        self.assertGreaterEqual(schedules["generated"], 10)
        self.assertTrue(set(range(7)).issubset(schedules["crash_sites_reached"]))
        self.assertIn("revoke-window-4", schedules["race_windows_reached"])
        self.assertIn("unknown-recovery", schedules["race_windows_reached"])

    def test_every_generated_case_passes_correct_system_and_oracle(self) -> None:
        result = explore(self.corpus, seed=77, bounds=self.bounds)
        failures = []
        for case in result.cases:
            execution = execute_case(case, CorrectSyntheticSystem)
            if not execution.assessment.passed:
                failures.append((case.case_id, execution.assessment.to_dict()))
        self.assertEqual([], failures)

    def test_deliberate_sentinels_are_detected_from_same_generated_cases(self) -> None:
        result = explore(self.corpus, seed=20261113, bounds=self.bounds)
        replay_failures = [
            execute_case(case, ReplayDefectiveSyntheticSystem)
            for case in result.cases
            if "fbi-artex-concurrent-agents" in case.scenario_ids
            or "fbi-artex-replay-duplicate" in case.scenario_ids
        ]
        recheck_failures = [
            execute_case(case, FinalRecheckDefectiveSyntheticSystem)
            for case in result.cases
            if "fbi-artex-delayed-crash-recovery" in case.scenario_ids
        ]
        self.assertTrue(any(not item.assessment.passed for item in replay_failures))
        self.assertTrue(
            any(
                violation.code == "UNAUTHORIZED_EFFECT_DUPLICATE_REPLAY_KEY"
                for item in replay_failures
                for violation in item.assessment.violations
            )
        )
        self.assertTrue(any(not item.assessment.passed for item in recheck_failures))
        self.assertTrue(
            any(
                violation.code == "UNAUTHORIZED_EFFECT_REVOKED"
                for item in recheck_failures
                for violation in item.assessment.violations
            )
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap.execution import execute_case
from wolftrap.model import ExperimentCase
from wolftrap.report import (
    REPORT_MANIFEST_NAME,
    ReportIntegrityError,
    validate_report_pair,
    write_report_pair,
)
from wolftrap.revision import capture_source_revision
from wolftrap.runner import RunConfiguration, run_research
from wolftrap.system import SYSTEMS


FIXED_REVISION = capture_source_revision()

UNIT_SUMMARY = {
    "run_by_research_engine": True,
    "tests_run": 37,
    "skipped": 0,
    "failures": 0,
    "errors": 0,
    "successful": True,
    "source_revision": FIXED_REVISION.to_dict(),
    "source_revision_end": FIXED_REVISION.to_dict(),
    "source_stable": True,
}


def configuration(system_id: str = "correct-v1") -> RunConfiguration:
    return RunConfiguration(
        seed=20261113,
        max_mutations=32,
        max_interactions=8,
        max_commands_per_case=128,
        max_minimization_evaluations=32,
        reproduction_attempts=2,
        system_id=system_id,
    )


class CampaignAndEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.correct = run_research(
            configuration(),
            source_revision=FIXED_REVISION,
            unit_test_summary=UNIT_SUMMARY,
        )
        cls.defective = run_research(
            configuration("defective-replay-v1"),
            source_revision=FIXED_REVISION,
            unit_test_summary=UNIT_SUMMARY,
        )

    def test_correct_system_qualifies_with_positive_and_negative_controls(self) -> None:
        report = self.correct.report
        self.assertEqual(0, self.correct.exit_code)
        self.assertEqual("PASS", report["qualification"]["status"])
        self.assertGreater(report["summary"]["cases_passed"], 10)
        self.assertEqual(0, report["summary"]["cases_failed"])
        self.assertEqual(1, report["qualification"]["positive_controls_total"])
        self.assertEqual(1, report["qualification"]["positive_controls_passed"])
        self.assertEqual(7, report["qualification"]["negative_controls_total"])
        self.assertEqual(7, report["qualification"]["negative_controls_passed"])
        self.assertEqual(3, report["qualification"]["mixed_threat_controls_total"])
        self.assertEqual(3, report["qualification"]["mixed_threat_controls_passed"])
        self.assertEqual(10, report["qualification"]["threat_baselines_total"])
        self.assertEqual(10, report["qualification"]["threat_baselines_passed"])
        self.assertEqual(37, report["unit_tests"]["tests_run"])
        self.assertEqual(0, report["unit_tests"]["skipped"])
        self.assertEqual([], report["findings"])

    def test_deny_all_fails_positive_control(self) -> None:
        result = run_research(
            configuration("deny-all-v1"), source_revision=FIXED_REVISION
        )
        self.assertEqual(1, result.exit_code)
        self.assertEqual("FAIL", result.report["qualification"]["status"])
        self.assertEqual(0, result.report["qualification"]["positive_controls_passed"])
        self.assertGreater(result.report["summary"]["findings"], 0)

    def test_defect_findings_have_complete_independently_reproduced_evidence(self) -> None:
        self.assertEqual(1, self.defective.exit_code)
        self.assertGreater(len(self.defective.report["findings"]), 0)
        required = {
            "finding_id",
            "classification",
            "severity",
            "confidence",
            "synthetic_only",
            "threat_sources",
            "attack_references",
            "source_revision",
            "random_seed",
            "test_configuration",
            "expected_behavior",
            "observed_behavior",
            "independent_effect_state_evidence",
            "reproduction",
        }
        for finding in self.defective.report["findings"]:
            self.assertTrue(required.issubset(finding))
            self.assertIn(finding["classification"], {"CONFIRMED", "DUPLICATE"})
            self.assertTrue(finding["synthetic_only"])
            self.assertFalse(finding["real_world_vulnerability_claim"])
            attempts = finding["reproduction"]["attempts"]
            self.assertGreaterEqual(len(attempts), 2)
            self.assertTrue(all(attempt["reproduced"] for attempt in attempts))
            self.assertEqual(
                FIXED_REVISION.commit_sha,
                finding["source_revision"]["commit_sha"],
            )

    def test_saved_minimized_case_replays_the_same_oracle_fingerprint(self) -> None:
        finding = self.defective.report["findings"][0]
        config = finding["test_configuration"]
        case = ExperimentCase.from_dict(config["minimized_case"])
        self.assertEqual(config["minimized_case_digest"], case.digest)
        execution = execute_case(case, SYSTEMS[config["system_id"]])
        self.assertFalse(execution.assessment.passed)
        self.assertEqual(
            finding["independent_effect_state_evidence"]["oracle_fingerprint"],
            execution.assessment.fingerprint,
        )

    def test_report_pair_round_trips_and_markdown_preserves_safety_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            json_path, markdown_path = write_report_pair(
                self.defective.report, temporary
            )
            loaded = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")
            self.assertEqual(self.defective.report["run_id"], loaded["run_id"])
            self.assertEqual(
                self.defective.report["summary"], loaded["summary"]
            )
            self.assertEqual(
                [item["finding_id"] for item in self.defective.report["findings"]],
                [item["finding_id"] for item in loaded["findings"]],
            )
            self.assertIn("Synthetic defensive research only", markdown)
            self.assertIn(self.defective.report["run_id"], markdown)
            manifest = json.loads(
                (Path(temporary) / REPORT_MANIFEST_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual("COMPLETE", manifest["state"])
            self.assertEqual(loaded, validate_report_pair(json_path))
            self.assertFalse(any(Path(temporary).glob("*.tmp")))

    def test_interrupted_report_pair_publication_is_not_authoritative(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            write_report_pair(self.correct.report, temporary)
            from wolftrap import report as report_module

            original_atomic_write = report_module._atomic_write

            def fail_json_write(path: Path, payload: str) -> None:
                if path.name == "wolftrap-report.json":
                    raise OSError("injected report publication failure")
                original_atomic_write(path, payload)

            with patch("wolftrap.report._atomic_write", side_effect=fail_json_write):
                with self.assertRaises(OSError):
                    write_report_pair(self.defective.report, temporary)
            manifest = json.loads(
                (Path(temporary) / REPORT_MANIFEST_NAME).read_text(encoding="utf-8")
            )
            self.assertEqual("INCOMPLETE", manifest["state"])
            with self.assertRaises(ReportIntegrityError):
                validate_report_pair(Path(temporary) / "wolftrap-report.json")

    def test_report_pair_hash_mismatch_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            json_path, markdown_path = write_report_pair(
                self.correct.report, temporary
            )
            markdown_path.write_text(
                markdown_path.read_text(encoding="utf-8") + "tampered\n",
                encoding="utf-8",
            )
            with self.assertRaises(ReportIntegrityError):
                validate_report_pair(json_path)

    def test_unexpected_execution_error_stops_remaining_cases_fail_closed(self) -> None:
        with patch("wolftrap.runner.execute_case", side_effect=RuntimeError("boom")):
            result = run_research(
                configuration(), source_revision=FIXED_REVISION
            )
        report = result.report
        self.assertEqual(2, result.exit_code)
        self.assertEqual("ERROR", report["qualification"]["status"])
        self.assertEqual(1, report["summary"]["internal_errors"])
        self.assertEqual(0, report["summary"]["cases_executed"])
        self.assertGreater(report["summary"]["cases_skipped"], 0)
        self.assertEqual([], report["findings"])
        self.assertTrue(report["errors"][0]["fail_closed"])


if __name__ == "__main__":
    unittest.main()

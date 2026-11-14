from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from wolftrap.cli import main
from wolftrap.revision import capture_source_revision


class CommandLineTests(unittest.TestCase):
    def invoke(self, arguments: list[str]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = main(arguments)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_help_and_local_scenario_listing(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as raised:
            main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("no external targets", stdout.getvalue())

        code, output, error = self.invoke(["list-scenarios", "--json"])
        self.assertEqual((code, error), (0, ""))
        scenarios = json.loads(output)
        self.assertEqual(len(scenarios), 11)
        self.assertTrue(
            any(
                item["scenario_id"] == "fbi-artex-positive-authorized-operation"
                for item in scenarios
            )
        )

    def test_invalid_campaign_bound_fails_before_writing_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "evidence"
            code, _, error = self.invoke(
                [
                    "run",
                    "--max-mutations",
                    "9",
                    "--output-dir",
                    str(destination),
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("max_mutations", error)
            self.assertFalse(destination.exists())

    def test_successful_run_embeds_validated_unit_test_counts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unit_summary = root / "unit-tests.json"
            unit_summary.write_text(
                json.dumps(
                    {
                        "tests_run": 37,
                        "skipped": 0,
                        "failures": 0,
                        "errors": 0,
                        "successful": True,
                        "run_by_research_engine": True,
                        "source_revision": capture_source_revision().to_dict(),
                        "source_revision_end": capture_source_revision().to_dict(),
                        "source_stable": True,
                    }
                ),
                encoding="utf-8",
            )
            output = root / "correct"
            code, stdout, error = self.invoke(
                [
                    "run",
                    "--seed",
                    "7",
                    "--max-mutations",
                    "32",
                    "--max-interactions",
                    "8",
                    "--unit-test-summary",
                    str(unit_summary),
                    "--output-dir",
                    str(output),
                    "--sut",
                    "correct-v1",
                ]
            )
            self.assertEqual((code, error), (0, ""))
            self.assertIn("PASS:", stdout)
            report = json.loads((output / "wolftrap-report.json").read_text())
            self.assertEqual(report["qualification"]["status"], "PASS")
            self.assertEqual(report["unit_tests"]["tests_run"], 37)
            self.assertEqual(report["summary"]["cases_skipped"], 0)
            self.assertTrue((output / "wolftrap-report.md").is_file())

    def test_failed_unit_summary_stops_research_safely(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            unit_summary = root / "failed.json"
            unit_summary.write_text(
                json.dumps(
                    {
                        "tests_run": 3,
                        "skipped": 0,
                        "failures": 1,
                        "errors": 0,
                        "successful": False,
                    }
                ),
                encoding="utf-8",
            )
            destination = root / "must-not-exist"
            code, _, error = self.invoke(
                [
                    "run",
                    "--max-mutations",
                    "32",
                    "--unit-test-summary",
                    str(unit_summary),
                    "--output-dir",
                    str(destination),
                ]
            )
            self.assertEqual(code, 2)
            self.assertIn("unit tests did not pass", error)
            self.assertFalse(destination.exists())

    def test_stale_unit_summary_and_unsafe_finding_id_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stale = capture_source_revision().to_dict()
            stale["tree_sha"] = "0" * 40
            summary = root / "stale.json"
            summary.write_text(
                json.dumps(
                    {
                        "tests_run": 1,
                        "skipped": 0,
                        "failures": 0,
                        "errors": 0,
                        "successful": True,
                        "source_revision": stale,
                        "source_revision_end": stale,
                        "source_stable": True,
                    }
                ),
                encoding="utf-8",
            )
            code, _, error = self.invoke(
                ["run", "--unit-test-summary", str(summary), "--output-dir", str(root / "out")]
            )
            self.assertEqual(2, code)
            self.assertIn("source revision", error)

            report = root / "report.json"
            report.write_text('{"findings": []}', encoding="utf-8")
            code, _, error = self.invoke(
                [
                    "reproduce",
                    "--report",
                    str(report),
                    "--finding-id",
                    "../../escape",
                    "--output-dir",
                    str(root / "reproduction"),
                ]
            )
            self.assertEqual(2, code)
            self.assertIn("invalid format", error)
            self.assertFalse((root / "escape.json").exists())

    def test_defective_finding_reproduces_from_saved_minimized_case(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "defective"
            code, stdout, error = self.invoke(
                [
                    "run",
                    "--seed",
                    "11",
                    "--max-mutations",
                    "32",
                    "--max-interactions",
                    "8",
                    "--max-minimization-evaluations",
                    "8",
                    "--output-dir",
                    str(output),
                    "--sut",
                    "defective-replay-v1",
                ]
            )
            self.assertEqual((code, error), (1, ""))
            self.assertIn("FAIL:", stdout)
            report_path = output / "wolftrap-report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            confirmed = [
                item
                for item in report["findings"]
                if item["classification"] == "CONFIRMED"
            ]
            self.assertTrue(confirmed)
            finding_id = confirmed[0]["finding_id"]

            reproduction_dir = root / "reproduction"
            code, stdout, error = self.invoke(
                [
                    "reproduce",
                    "--report",
                    str(report_path),
                    "--finding-id",
                    finding_id,
                    "--output-dir",
                    str(reproduction_dir),
                ]
            )
            self.assertEqual((code, error), (1, ""))
            self.assertIn("REPRODUCED", stdout)
            evidence = json.loads(
                (
                    reproduction_dir
                    / f"wolftrap-reproduction-{finding_id}.json"
                ).read_text(encoding="utf-8")
            )
            self.assertTrue(evidence["violation_reproduced"])
            self.assertTrue(evidence["source_revision_matches"])


if __name__ == "__main__":
    unittest.main()

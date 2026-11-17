"""Independent hostile checks for authored cloud-C2 camouflage research."""

from __future__ import annotations

import json
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from wolftrap.cli import main
from wolftrap.cloud_camouflage import (
    LABEL, MANIFEST_NAME, REPORT_NAME, _cases,
    evaluate_camouflage_challenge, run_camouflage_challenge,
    verify_camouflage_evidence,
)
from wolftrap.cloud_trace import SCHEMA as TRACE_SCHEMA, parse_trace


class CloudCamouflageHostileTests(unittest.TestCase):
    def test_all_160_independently_labeled_controls_match_expectations(self) -> None:
        result = evaluate_camouflage_challenge()
        self.assertEqual(result["qualification"]["status"], "PASSED_BOUNDED")
        self.assertFalse(result["qualification"]["production_error_rates_measured"])
        self.assertFalse(result["qualification"]["real_world_infection_detected"])
        self.assertEqual(result["summary"], {
            "cases": 160, "mismatches": 0,
            "pattern_positive": 40, "benign_negative": 40,
            "benign_lookalike": 40, "evasion_variant": 40,
            "benign_lookalikes_flagged": 40, "evasion_variants_unflagged": 40,
        })
        self.assertTrue(all(case["matched"] and case["input_sha256"]
                            for case in result["cases"]))

    def test_lookalikes_and_evasions_expose_both_limits(self) -> None:
        for case in evaluate_camouflage_challenge()["cases"]:
            if case["group"] == "benign_lookalike":
                self.assertTrue(case["observed_rule_ids"], case["case_id"])
            if case["group"] == "evasion_variant":
                self.assertEqual(case["observed_rule_ids"], [], case["case_id"])
            if case["group"] == "benign_negative":
                self.assertEqual(case["observed_rule_ids"], [], case["case_id"])

    def test_all_inputs_fit_the_strict_sanitized_schema(self) -> None:
        cases = _cases()
        self.assertEqual(len({case["case_id"] for case in cases}), len(cases))
        for case in cases:
            trace = json.dumps({"schema": TRACE_SCHEMA, "events": case["events"]}).encode()
            self.assertEqual(parse_trace(trace), case["events"])
            self.assertTrue(all(set(event) == {
                "at", "session", "repository", "issue", "kind"} for event in case["events"]))
            self.assertNotIn("https://", trace.decode())

    def test_all_denying_detector_fails_positive_controls(self) -> None:
        with patch("wolftrap.cloud_camouflage.inspect_trace", return_value=[]):
            result = evaluate_camouflage_challenge()
        self.assertEqual(result["qualification"]["status"], "DETECTION_GAP")
        self.assertGreater(result["summary"]["mismatches"], 0)

    def test_all_flagging_detector_fails_negative_controls(self) -> None:
        with patch("wolftrap.cloud_camouflage.inspect_trace", return_value=[{
                "rule_id": LABEL}]):
            result = evaluate_camouflage_challenge()
        self.assertEqual(result["qualification"]["status"], "DETECTION_GAP")
        self.assertGreater(result["summary"]["mismatches"], 0)

    def test_no_network_cli_and_reproducible_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-cloud-camouflage-") as temp:
            evidence = Path(temp) / "output"
            with patch.object(socket, "socket", side_effect=AssertionError("network attempted")):
                with redirect_stdout(StringIO()):
                    self.assertEqual(main(["challenge-cloud-camouflage", "--output-dir",
                                           str(evidence)]), 0)
                    self.assertEqual(main(["verify-cloud-camouflage", "--evidence-dir",
                                           str(evidence)]), 0)
                saved = verify_camouflage_evidence(evidence)
            self.assertEqual(saved["summary"]["cases"], 160)
            self.assertFalse(saved["network_contacted"])
            self.assertFalse(saved["target_code_executed"])
            manifest = json.loads((evidence / MANIFEST_NAME).read_text())
            self.assertEqual(manifest["state"], "COMPLETE")
            with self.assertRaises(ValueError):
                run_camouflage_challenge(evidence)

    def test_changed_report_or_manifest_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-cloud-camouflage-") as temp:
            evidence = Path(temp) / "output"
            run_camouflage_challenge(evidence)
            report = (evidence / REPORT_NAME).read_bytes()
            (evidence / REPORT_NAME).write_bytes(report + b"\n")
            with self.assertRaises(ValueError):
                verify_camouflage_evidence(evidence)
            (evidence / REPORT_NAME).write_bytes(report)
            (evidence / MANIFEST_NAME).write_text('{"state":"COMPLETE"}')
            with self.assertRaises(ValueError):
                verify_camouflage_evidence(evidence)

    def test_symlink_destination_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-cloud-camouflage-") as temp:
            target = Path(temp) / "target"
            target.mkdir()
            link = Path(temp) / "evidence-link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises((OSError, ValueError)):
                run_camouflage_challenge(link)


if __name__ == "__main__":
    unittest.main()

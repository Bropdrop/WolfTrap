"""Bounded, payload-free cloud C2 signatures and authority-boundary controls."""

from __future__ import annotations

import json
import socket
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from tests.helpers import base_case
from wolftrap.cli import main
from wolftrap.cloud_c2 import (MANIFEST_NAME, MAX_EVENTS, REPORT_NAME,
                              detect_cloud_c2, evaluate_challenge,
                              run_cloud_c2_challenge, verify_cloud_c2_evidence)
from wolftrap.execution import execute_case
from wolftrap.system import CorrectSyntheticSystem


A = "synthetic-host://vehicle-a"


def e(at: int, kind: str, actor: str = A) -> dict[str, object]:
    return {"at": at, "actor": actor, "kind": kind}


class CloudC2ChallengeTests(unittest.TestCase):
    def test_bounded_positive_and_negative_controls(self) -> None:
        result = evaluate_challenge()
        self.assertEqual(result["qualification"]["status"], "PASSED_BOUNDED")
        self.assertEqual(result["summary"], {
            "cases": 8, "mismatches": 0, "positive_controls": 3, "negative_controls": 5})
        self.assertTrue(all(item["matched"] for item in result["cases"]))
        self.assertTrue(all(item["input_sha256"] for item in result["cases"]))
        self.assertFalse(result["qualification"]["real_world_exploit_confirmed"])

    def test_repeated_label_polls_and_source_map_match_conditionally(self) -> None:
        trace = [e(1, "issue_create"), e(2, "label_add"), e(3, "repo_poll"),
                 e(4, "label_remove"), e(5, "repo_poll"), e(6, "source_map_write")]
        result = detect_cloud_c2(trace)
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertEqual({item["rule_id"] for item in result["findings"]},
                         {"WT-CLOUD-C2-001", "WT-CLOUD-C2-002"})
        self.assertTrue(all(item["classification"] == "REVIEW_REQUIRED"
                            for item in result["findings"]))
        self.assertNotIn("vehicle-a", json.dumps(result))

    def test_unrelated_actors_and_benign_build_are_not_spliced(self) -> None:
        trace = [e(1, "issue_create"),
                 e(2, "label_add", "synthetic-host://vehicle-b"),
                 e(3, "repo_poll", "synthetic-host://vehicle-b"),
                 e(4, "label_remove", "synthetic-host://vehicle-b"),
                 e(5, "repo_poll", "synthetic-host://vehicle-b"),
                 e(6, "source_map_write", "synthetic-host://vehicle-b")]
        self.assertEqual(detect_cloud_c2(trace)["findings"], [])
        self.assertEqual(detect_cloud_c2([e(1, "source_map_write")])["findings"], [])

    def test_no_wildcard_targets_payloads_or_unbounded_input(self) -> None:
        invalid = ([e(1, "repo_poll", "https://api.github.com")],
                   [dict(e(1, "repo_poll"), token="credential")],
                   [e(1, "shell_execute")],
                   [e(2, "issue_create"), e(1, "repo_poll")],
                   [dict(e(1, "issue_create"), at=True)],
                   [e(i, "other") for i in range(MAX_EVENTS + 1)])
        for case in invalid:
            with self.subTest(case=str(case)[:45]), self.assertRaises(ValueError):
                detect_cloud_c2(case)

    def test_independent_authority_rejects_trusted_cloud_origin(self) -> None:
        original = base_case().requests[0]
        poisoned = replace(original, origin="synthetic-origin://github-issue")
        execution = execute_case(
            base_case(request=poisoned, control="NEGATIVE"), CorrectSyntheticSystem)
        self.assertTrue(execution.assessment.passed, execution.assessment.to_dict())
        self.assertEqual(execution.final_state["effects"], [])
        self.assertEqual(execution.final_state["tasks"][0]["denial_reason"],
                         "ORIGIN_MISMATCH")
        legitimate = execute_case(base_case(), CorrectSyntheticSystem)
        self.assertTrue(legitimate.assessment.passed)
        self.assertEqual(len(legitimate.final_state["effects"]), 1)

    def test_evidence_manifest_replay_and_tamper(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "evidence"
            with patch.object(socket, "socket", side_effect=AssertionError("network attempted")):
                report, code = run_cloud_c2_challenge(output)
                self.assertEqual(code, 0)
                self.assertEqual(verify_cloud_c2_evidence(output), report)
            self.assertEqual(main(["verify-cloud-c2", "--evidence-dir", str(output)]), 0)
            saved = json.loads((output / MANIFEST_NAME).read_text())
            self.assertEqual(saved["state"], "COMPLETE")
            with self.assertRaises(ValueError):
                run_cloud_c2_challenge(output)  # Must be a fresh evidence directory.
            (output / REPORT_NAME).write_text("tampered\n")
            with self.assertRaises(ValueError):
                verify_cloud_c2_evidence(output)

    def test_crushed_detector_fails_positive_controls(self) -> None:
        with patch("wolftrap.cloud_c2.detect_cloud_c2", return_value={
                "status": "NO_PATTERN_MATCH", "event_count": 6,
                "actor_count": 1, "findings": []}):
            result = evaluate_challenge()
        self.assertEqual(result["qualification"]["status"], "DETECTION_GAP")
        self.assertGreater(result["summary"]["mismatches"], 0)

    def test_cli_challenge_without_a_repository_or_live_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            out = Path(temp) / "reports"
            self.assertEqual(main(["challenge-cloud-c2", "--output-dir", str(out)]), 0)
            self.assertEqual(main(["verify-cloud-c2", "--evidence-dir", str(out)]), 0)
            saved = json.loads((out / REPORT_NAME).read_text())
            self.assertEqual(saved["summary"]["positive_controls"], 3)


if __name__ == "__main__":
    unittest.main()

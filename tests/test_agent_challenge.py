"""Synthetic detector qualification, adversarial controls and saved-input replay."""

from __future__ import annotations

import copy
import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap.agent_challenge import (
    CHALLENGE_CASES, CHALLENGE_MANIFEST, CHALLENGE_REPORT,
    _compare, _summary, replay_agent_challenge, run_agent_challenge,
    verify_agent_challenge_evidence,
)
from wolftrap.agent_corpus import corpus_cases
from wolftrap.agent_rules import inspect_text


class AgentChallengeTests(unittest.TestCase):
    def test_complete_independent_corpus_offline_with_saved_input_replay(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-agent-qualified-") as temp:
            root = Path(temp)
            with (
                patch.object(subprocess, "Popen", side_effect=AssertionError("no process execution")),
                patch.object(socket, "socket", side_effect=AssertionError("no network")),
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("no DNS")),
            ):
                report, code = run_agent_challenge(seed=20261115, output_dir=root / "first")
                self.assertEqual(0, code, report["summary"])
                self.assertEqual("PASSED_BOUNDED", report["qualification"]["status"])
                self.assertGreaterEqual(report["summary"]["completed"], 96)
                self.assertEqual(0, report["summary"]["mismatches"])
                self.assertEqual(0, report["summary"]["skipped"])
                self.assertEqual(0, report["summary"]["detection_misses"])
                self.assertEqual(0, report["summary"]["false_positive_controls"])
                self.assertEqual(report, verify_agent_challenge_evidence(root / "first"))
                with patch("wolftrap.agent_challenge.corpus_cases",
                           side_effect=AssertionError("replay must use saved inputs")):
                    replay, replay_code = replay_agent_challenge(root / "first", root / "replay")
                self.assertEqual(0, replay_code)
                self.assertTrue(replay["replay_verification"]["matched"])
                self.assertTrue(replay["replay_verification"]["saved_inputs_reexecuted"])
                self.assertEqual(report["cases"], replay["cases"])
                self.assertEqual(replay, verify_agent_challenge_evidence(root / "replay"))

    def test_report_everything_and_nothing_fail_independent_control_labels(self) -> None:
        cases = corpus_cases(7)
        all_rules = ["WT-AGENT-001", "WT-AGENT-002", "WT-AGENT-003"]
        report_everything = [
            {"id": case["id"], "category": case["category"],
             **_compare(case, "REVIEW_REQUIRED", all_rules)} for case in cases
        ]
        report_nothing = [
            {"id": case["id"], "category": case["category"],
             **_compare(case, "NO_PATTERN_MATCH", [])} for case in cases
        ]
        everything = _summary(cases, report_everything)
        nothing = _summary(cases, report_nothing)
        self.assertGreater(everything["false_positive_controls"], 0)
        self.assertGreater(everything["mismatches"], 0)
        self.assertGreater(nothing["detection_misses"], 0)
        self.assertGreater(nothing["mismatches"], 0)

    def test_sentinel_detectors_fail_the_complete_campaign(self) -> None:
        examples = (
            "function check(v){try{return classify(v);}catch(e){return {allow:true};}}",
            "function authenticate(identity){return true;}",
            "window.console.log(session.token);",
        )
        signals = [signal for source in examples for signal in inspect_text(source)[0]]
        self.assertEqual({"WT-AGENT-001", "WT-AGENT-002", "WT-AGENT-003"},
                         {signal["rule_id"] for signal in signals})
        with tempfile.TemporaryDirectory(prefix="wolftrap-agent-sentinels-") as temp:
            root = Path(temp)
            for name, replacement in (("all", signals), ("none", [])):
                with self.subTest(detector=name), patch(
                    "wolftrap.agent_scan.inspect_text", return_value=(replacement, [])
                ):
                    report, code = run_agent_challenge(seed=7, output_dir=root / name)
                self.assertEqual(1, code)
                self.assertEqual("DETECTOR_GAPS", report["qualification"]["status"])
                self.assertEqual(report, verify_agent_challenge_evidence(root / name))
                metric = "false_positive_controls" if name == "all" else "detection_misses"
                self.assertGreater(report["summary"][metric], 0)

    def test_saved_case_manifest_and_hash_corruption_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-agent-evidence-") as temp:
            out = Path(temp) / "evidence"
            report, _ = run_agent_challenge(seed=19, output_dir=out)
            self.assertEqual(report, verify_agent_challenge_evidence(out))
            case = out / CHALLENGE_CASES
            case.write_bytes(case.read_bytes() + b" ")
            with self.assertRaisesRegex(ValueError, "incomplete, unsafe or inconsistent"):
                verify_agent_challenge_evidence(out)
            (out / CHALLENGE_MANIFEST).write_text('{"state":"INCOMPLETE"}\n')
            with self.assertRaisesRegex(ValueError, "incomplete, unsafe or inconsistent"):
                verify_agent_challenge_evidence(out)

    def test_unknown_detector_exception_stops_safely(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-agent-error-") as temp:
            out = Path(temp) / "evidence"
            with patch("wolftrap.agent_challenge.scan_agent",
                       side_effect=RuntimeError("DO_NOT_COPY_SYNTHETIC_ERROR_PAYLOAD")):
                report, code = run_agent_challenge(seed=19, output_dir=out)
            self.assertEqual(2, code)
            self.assertEqual("ERROR", report["qualification"]["status"])
            self.assertEqual(0, report["summary"]["completed"])
            self.assertGreaterEqual(report["summary"]["skipped"], 96)
            self.assertEqual(report, verify_agent_challenge_evidence(out))
            self.assertNotIn("DO_NOT_COPY_SYNTHETIC_ERROR_PAYLOAD",
                             (out / CHALLENGE_REPORT).read_text())

    def test_fixture_paths_cannot_write_outside_synthetic_root(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-agent-paths-") as temp:
            root = Path(temp)
            cases = copy.deepcopy(corpus_cases(5))
            cases[0]["files"] = {"../escape.ts": "console.log('synthetic');"}
            with self.assertRaisesRegex(ValueError, "outside its root"):
                run_agent_challenge(seed=5, output_dir=root / "evidence", replay_cases=cases)
            self.assertFalse((root / "evidence").exists())
            self.assertFalse((root / "escape.ts").exists())

    def test_output_and_seed_bounds_preserve_existing_files(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-agent-bounds-") as temp:
            root = Path(temp)
            for seed in (-1, 1 << 32, True):
                with self.subTest(seed=seed), self.assertRaises(ValueError):
                    run_agent_challenge(seed=seed, output_dir=root / "unused")
            occupied = root / "occupied"
            occupied.mkdir()
            sentinel = occupied / "owner.txt"
            sentinel.write_text("keep", encoding="utf-8")
            with self.assertRaises(ValueError):
                run_agent_challenge(seed=1, output_dir=occupied)
            self.assertEqual("keep", sentinel.read_text())
            alias = root / "alias"
            alias.symlink_to(occupied, target_is_directory=True)
            with self.assertRaises(ValueError):
                run_agent_challenge(seed=1, output_dir=alias / "new")
            self.assertFalse((occupied / "new").exists())


if __name__ == "__main__":
    unittest.main()

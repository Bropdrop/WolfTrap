"""Offline differential detection-evasion tournament and evidence controls."""

from __future__ import annotations

import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap.build_scan import BuildScanOutcome, scan_build
from wolftrap.challenge import (
    CHALLENGE_CASES, CHALLENGE_MANIFEST, CHALLENGE_REPORT,
    run_challenge, verify_challenge_evidence,
)
from wolftrap.cli import main


class ChallengeTests(unittest.TestCase):
    def test_128_synthetic_cases_and_independent_balanced_oracle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-stage5-full-") as temp:
            out = Path(temp) / "run"
            with (
                patch.object(subprocess, "Popen", side_effect=AssertionError("no execution")),
                patch.object(socket, "socket", side_effect=AssertionError("no network")),
            ):
                report, status = run_challenge(seed=20261115, count=128, output_dir=out)
            self.assertEqual(status, 0)
            self.assertEqual(report["qualification"]["status"], "PASSED_BOUNDED")
            self.assertEqual(report["summary"]["mismatches"], 0)
            self.assertEqual(
                report["summary"]["by_expected"],
                {name: {"total": 32, "matched": 32}
                 for name in ("HIGH", "MEDIUM", "NONE", "INCONCLUSIVE")},
            )
            saved = json.loads((out / CHALLENGE_CASES).read_text())
            self.assertEqual(len(saved["cases"]), 128)
            self.assertEqual(len({case["id"] for case in saved["cases"]}), 128)
            self.assertEqual(verify_challenge_evidence(out), report)
            self.assertEqual(main(["verify-challenge", "--evidence-dir", str(out)]), 0)
            self.assertTrue(all(x["synthetic_only"] for x in saved["cases"]))
            self.assertFalse(report["qualification"]["target_code_executed"])
            self.assertFalse(report["qualification"]["external_targets"])

    def test_replay_stable_for_same_seed_and_distinct_for_another(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-stage5-replay-") as temp:
            root = Path(temp)
            for label, seed in (("a", 99), ("b", 99), ("c", 100)):
                result, code = run_challenge(seed=seed, count=64, output_dir=root / label)
                self.assertEqual(code, 0)
                self.assertEqual(result["summary"]["cases"], 64)
            for name in (CHALLENGE_CASES, CHALLENGE_REPORT, CHALLENGE_MANIFEST, "challenge-report.md"):
                self.assertEqual((root / "a" / name).read_bytes(), (root / "b" / name).read_bytes())
            self.assertNotEqual((root / "a" / CHALLENGE_CASES).read_bytes(),
                                (root / "c" / CHALLENGE_CASES).read_bytes())

    def test_defective_detector_is_caught_by_positive_controls(self) -> None:
        def deny_path_signal(root: Path, output: Path) -> BuildScanOutcome:
            original = scan_build(root, output)
            altered = dict(original.report)
            altered["findings"] = [item for item in original.report["findings"]
                                   if item["rule_id"] != "WT-GHA-006"]
            return BuildScanOutcome(report=altered, exit_code=original.exit_code)

        with tempfile.TemporaryDirectory(prefix="wolftrap-stage5-defective-") as temp:
            with patch("wolftrap.challenge.scan_build", side_effect=deny_path_signal):
                report, status = run_challenge(seed=7, count=64, output_dir=Path(temp) / "run")
            self.assertEqual(status, 1)
            self.assertEqual(report["qualification"]["status"], "DETECTOR_GAPS")
            self.assertGreaterEqual(report["summary"]["mismatches"], 16)
            self.assertGreater(report["summary"]["by_expected"]["HIGH"]["total"], 0)
            self.assertEqual(verify_challenge_evidence(Path(temp) / "run"), report)

    def test_evidence_corruption_and_incomplete_manifest_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-stage5-evidence-") as temp:
            root = Path(temp) / "run"
            run_challenge(seed=21, count=64, output_dir=root)
            (root / CHALLENGE_REPORT).write_text("corrupted", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash or byte count mismatch"):
                verify_challenge_evidence(root)
            (root / CHALLENGE_MANIFEST).write_text('{"state": "INCOMPLETE"}\n')
            with self.assertRaisesRegex(ValueError, "invalid or incomplete"):
                verify_challenge_evidence(root)

    def test_bounds_and_output_safety(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-stage5-bounds-") as temp:
            base = Path(temp)
            for seed, count in ((-1, 64), (1 << 32, 64), (True, 64), (1, 63), (1, 257), (1, 65)):
                with self.subTest(seed=seed, count=count), self.assertRaises(ValueError):
                    run_challenge(seed=seed, count=count, output_dir=base / "new")
            occupied = base / "occupied"
            occupied.mkdir()
            (occupied / "user-file").write_text("do not erase")
            with self.assertRaisesRegex(ValueError, "fresh or empty"):
                run_challenge(seed=1, count=64, output_dir=occupied)
            self.assertEqual((occupied / "user-file").read_text(), "do not erase")
            link = base / "link"
            link.symlink_to(occupied, target_is_directory=True)
            with self.assertRaises(ValueError):
                run_challenge(seed=1, count=64, output_dir=link)


if __name__ == "__main__":
    unittest.main()

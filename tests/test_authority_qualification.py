"""Effect-witness and evidence controls for the public synthetic qualification."""

from __future__ import annotations

import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap.authority_funnel import _base, enforce_funnel
from wolftrap.authority_qualification import (
    INPUTS_NAME,
    MANIFEST_NAME,
    REPORT_NAME,
    _evaluate,
    _manifest,
    run_qualification,
    verify_qualification,
)
from wolftrap.system import CorrectSyntheticSystem


SOURCE = {"commit_sha": "a" * 40, "tree_sha": "b" * 40}


class AuthorityQualificationTests(unittest.TestCase):
    def test_effect_witness_and_sentinel_gate(self) -> None:
        inputs, report = _evaluate()
        self.assertEqual(report["qualification"]["evidence_status"], "SYNTHETICALLY VERIFIED")
        self.assertEqual(report["qualification"]["live_runtime_status"], "NOT TESTED")
        self.assertEqual(report["summary"], {
            "proposals": 4019, "funnel_controls": 21, "phase_controls": 8,
            "mismatches": 0, "sentinels_caught": 5, "sentinels_total": 5,
        })
        case = report["funnel_controls"][-1]
        self.assertEqual(len(inputs["funnel_controls"][-1]["proposals"]), 1000)
        self.assertEqual(case["observed_effects"], case["expected_effects"])
        self.assertEqual(len(case["observed_effects"]), 1)
        self.assertEqual([decision["reason"] for decision in case["reported_decisions"][-4:]],
                         ["DELEGATE_MISMATCH", "ACCEPTED", "SLOT_EXHAUSTED", "REPLAY"])
        sentinels = {sentinel["name"]: sentinel["witness"] for sentinel in report["sentinels"]}
        fake = sentinels["fake-success"]
        self.assertEqual(fake["claimed_effects"], fake["expected_effects"])
        self.assertEqual(fake["reported_decisions"], fake["expected_decisions"])
        self.assertEqual(fake["observed_effects"], [])
        self.assertEqual(len(sentinels["missing-tenant-binding"]["observed_effects"]), 1)
        after_preparation = [phase for phase in report["phase_controls"]
                             if "expected_denial" in phase]
        self.assertEqual([phase["expected_denial"] for phase in after_preparation],
                         ["EXPIRED", "STALE_EPOCH", "UNKNOWN_SECURITY_STATE"])
        self.assertTrue(all(phase["oracle"]["observed_effects"] == [] for phase in after_preparation))

    def test_sentinel_that_escapes_prevents_qualification(self) -> None:
        with patch("wolftrap.authority_qualification.FinalRecheckDefectiveSyntheticSystem",
                   CorrectSyntheticSystem):
            _, report = _evaluate()
        self.assertEqual(report["qualification"]["status"], "AUTHORITY_GAP")
        self.assertEqual(report["summary"]["mismatches"], 0)
        self.assertEqual(report["summary"]["sentinels_caught"], 4)

    def test_agent_votes_priorities_and_confidence_cannot_enter_gate(self) -> None:
        grant, proposal = _base()
        for name, value in (("vote", "approved"), ("priority", 99), ("confidence", 1.0)):
            with self.subTest(name=name), self.assertRaises(ValueError):
                enforce_funnel([grant], [dict(proposal, **{name: value})],
                               current_epoch=7, security_state_known=True)

    def test_offline_replay_checks_revision_and_rejects_rehashed_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch.object(
            socket, "socket", side_effect=AssertionError("socket used in qualification"),
        ):
            root = Path(directory) / "evidence"
            with patch("wolftrap.authority_qualification._source_identity", return_value=SOURCE):
                original = run_qualification(root)
                self.assertEqual(verify_qualification(root), original)
                with self.assertRaises(ValueError):
                    run_qualification(root)
                case_file = root / INPUTS_NAME
                case_file.write_bytes(case_file.read_bytes().replace(
                    b"coordinated-thousand-proposals-one-slot", b"coordinated-tampered-one-slot",
                ))
                (root / MANIFEST_NAME).write_bytes(_manifest({
                    name: (root / name).read_bytes() for name in (INPUTS_NAME, REPORT_NAME)
                }))
                with self.assertRaisesRegex(ValueError, "replay mismatch"):
                    verify_qualification(root)
            with patch("wolftrap.authority_qualification._source_identity", return_value={
                **SOURCE, "commit_sha": "c" * 40,
            }):
                with self.assertRaisesRegex(ValueError, "exact source revision"):
                    verify_qualification(root)

    def test_evidence_rejects_symlinks_and_extra_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory, patch(
            "wolftrap.authority_qualification._source_identity", return_value=SOURCE,
        ):
            root = Path(directory) / "evidence"
            run_qualification(root)
            extra = root / "extra"
            extra.touch()
            with self.assertRaisesRegex(ValueError, "missing or extra files"):
                verify_qualification(root)
            extra.unlink()
            artifact = root / REPORT_NAME
            copy = Path(directory) / REPORT_NAME
            artifact.rename(copy)
            artifact.symlink_to(copy)
            with self.assertRaises(OSError):
                verify_qualification(root)


if __name__ == "__main__":
    unittest.main()

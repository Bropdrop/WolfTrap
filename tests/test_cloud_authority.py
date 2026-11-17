"""Hostile qualification of cloud-advisory / synthetic-authority separation."""

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
from wolftrap.cloud_authority import (
    AXES, MANIFEST_NAME, REPORT_NAME, TRUSTED_ORIGIN, _fixture,
    evaluate_cloud_authority, run_cloud_authority, verify_cloud_authority,
)
from wolftrap.cloud_camouflage import _cases as cloud_cases
from wolftrap.execution import execute_case
from wolftrap.system import (DenyAllSyntheticSystem,
                             FinalRecheckDefectiveSyntheticSystem,
                             ReplayDefectiveSyntheticSystem)


class CloudAuthorityHostileTests(unittest.TestCase):
    def test_every_cloud_class_crosses_twelve_independent_authority_axes(self) -> None:
        report = evaluate_cloud_authority()
        self.assertEqual(report["qualification"]["status"], "PASSED_BOUNDED")
        self.assertFalse(report["qualification"]["real_ground_truth_runtime_connected"])
        self.assertFalse(report["qualification"]["production_authority_proven"])
        self.assertFalse(report["qualification"]["real_world_malware_detected"])
        self.assertFalse(report["qualification"]["artex_intrusion_detected"])
        self.assertFalse(report["qualification"]["artex_intrusion_testing_performed"])
        self.assertEqual(report["summary"], {
            "cloud_traces": 160, "cloud_advisories_flagged": 80,
            "cloud_advisories_unflagged": 80, "authority_checks": 1920,
            "mismatches": 0, "oracle_failures": 0,
            "synthetic_protected_effects": 320,
        })
        self.assertEqual(len(AXES), 12)
        self.assertTrue(all(axis["cases"] == 160 and axis["mismatches"] == 0
                            for axis in report["authority_axes"]))
        effects = {axis["axis"]: axis["effects"] for axis in report["authority_axes"]}
        self.assertEqual(effects["valid-independent-grant"], 160)
        self.assertEqual(effects["replayed-grant"], 160)
        self.assertTrue(all(value == 0 for axis, value in effects.items()
                            if axis not in {"valid-independent-grant", "replayed-grant"}))

    def test_cloud_advisory_cannot_grant_or_revoke_effect_authority(self) -> None:
        with patch("wolftrap.cloud_authority.inspect_trace", return_value=[]):
            no_alert = evaluate_cloud_authority()
        with patch("wolftrap.cloud_authority.inspect_trace", return_value=[{
                "rule_id": "WT-CLOUD-C2-003"}]):
            all_alert = evaluate_cloud_authority()
        self.assertEqual(no_alert["summary"]["cloud_advisories_flagged"], 0)
        self.assertEqual(all_alert["summary"]["cloud_advisories_flagged"], 160)
        self.assertEqual(no_alert["authority_axes"], all_alert["authority_axes"])
        self.assertEqual(no_alert["summary"]["mismatches"], 0)
        self.assertEqual(all_alert["summary"]["mismatches"], 0)

    def test_trace_metadata_never_becomes_a_trusted_origin(self) -> None:
        representative = {case["group"]: case for case in cloud_cases()}
        for case in representative.values():
            approved = _fixture(case, "valid-independent-grant")
            copied = _fixture(case, "foreign-cloud-origin")
            self.assertEqual(approved.requests[0].origin, TRUSTED_ORIGIN)
            self.assertEqual(len(execute_case(approved).final_state["effects"]), 1)
            rejected = execute_case(copied)
            self.assertEqual(len(rejected.final_state["effects"]), 0)
            self.assertEqual(rejected.final_state["tasks"][0]["denial_reason"],
                             "ORIGIN_MISMATCH")

    def test_all_denying_sut_cannot_pass_the_positive_controls(self) -> None:
        with patch("wolftrap.cloud_authority.execute_case",
                   side_effect=lambda case: execute_case(case, DenyAllSyntheticSystem)):
            report = evaluate_cloud_authority()
        self.assertEqual(report["qualification"]["status"], "AUTHORITY_GAP")
        self.assertGreater(report["summary"]["oracle_failures"], 0)
        self.assertGreater(report["summary"]["mismatches"], 0)

    def test_missing_final_recheck_is_caught_by_ledger_oracle(self) -> None:
        case = _fixture(cloud_cases()[0], "revoked-after-preparation")
        correct = execute_case(case)
        self.assertTrue(correct.assessment.passed)
        self.assertEqual(correct.final_state["effects"], [])
        defective = execute_case(case, FinalRecheckDefectiveSyntheticSystem)
        self.assertFalse(defective.assessment.passed)
        self.assertEqual(len(defective.final_state["effects"]), 1)

    def test_replay_defect_is_caught_by_ledger_oracle(self) -> None:
        case = _fixture(cloud_cases()[0], "replayed-grant")
        correct = execute_case(case)
        self.assertTrue(correct.assessment.passed)
        self.assertEqual(len(correct.final_state["effects"]), 1)
        defective = execute_case(case, ReplayDefectiveSyntheticSystem)
        self.assertFalse(defective.assessment.passed)
        self.assertEqual(len(defective.final_state["effects"]), 2)

    def test_offline_cli_evidence_verification_and_no_network(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-cloud-auth-") as temp:
            evidence = Path(temp) / "evidence"
            with patch.object(socket, "socket", side_effect=AssertionError("network attempted")):
                with redirect_stdout(StringIO()):
                    self.assertEqual(main(["challenge-cloud-authority", "--output-dir",
                                           str(evidence)]), 0)
                    self.assertEqual(main(["verify-cloud-authority", "--evidence-dir",
                                           str(evidence)]), 0)
                saved = verify_cloud_authority(evidence)
            self.assertFalse(saved["network_contacted"])
            self.assertFalse(saved["external_code_executed"])
            self.assertEqual(json.loads((evidence / MANIFEST_NAME).read_text())
                             ["state"], "COMPLETE")
            with self.assertRaises(ValueError):
                run_cloud_authority(evidence)

    def test_tampered_report_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-cloud-auth-") as temp:
            evidence = Path(temp) / "evidence"
            run_cloud_authority(evidence)
            (evidence / REPORT_NAME).write_text('{"qualification":{"status":"PASSED"}}')
            with self.assertRaises(ValueError):
                verify_cloud_authority(evidence)


if __name__ == "__main__":
    unittest.main()

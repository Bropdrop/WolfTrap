import hashlib
import json
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from wolftrap.gt_vsa import DENIED
from wolftrap.gt_vsa_challenge import (
    FAULTS,
    MANIFEST_NAME,
    MARKDOWN_NAME,
    REPORT_NAME,
    _campaign,
    _run_trial,
    verify_evidence,
    write_evidence,
)
from wolftrap.gt_vsa_fixtures import scenario_steps
from wolftrap.gt_vsa_oracle import load_corpus


class VehicleChallengeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "evidence"

    def write_small_campaign(self):
        # The installed CLI requires a full fleet. Test file handling with a
        # smaller fixture while public qualification always runs 1,024.
        with patch("wolftrap.gt_vsa_challenge.MIN_VEHICLES", 1):
            return write_evidence(self.output, seed=42, vehicles=2)

    def verify_small_campaign(self):
        with patch("wolftrap.gt_vsa_challenge.MIN_VEHICLES", 1):
            return verify_evidence(self.output)

    def test_bounds_fail_before_evidence(self):
        for seed, vehicles in ((-1, 1024), (True, 1024), (2**64, 1024), (1, 999), (1, 2049)):
            with self.subTest(seed=seed, vehicles=vehicles), self.assertRaises(ValueError):
                write_evidence(self.output, seed=seed, vehicles=vehicles)
        self.assertFalse(self.output.exists())

    def test_exact_evidence_replays_and_existing_output_is_preserved(self):
        first = self.write_small_campaign()
        self.assertEqual("PASS", first["status"])
        self.assertEqual(first, self.verify_small_campaign())
        original = (self.output / MANIFEST_NAME).read_bytes()
        with self.assertRaisesRegex(ValueError, "fresh or empty"):
            self.write_small_campaign()
        self.assertEqual(original, (self.output / MANIFEST_NAME).read_bytes())

    def test_recomputed_hash_cannot_hide_evidence_edit(self):
        manifest = self.write_small_campaign()
        file = self.output / REPORT_NAME
        data = file.read_bytes().replace(b'"failed_runs": 0', b'"failed_runs": 1')
        file.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            self.verify_small_campaign()
        manifest["artifacts"][REPORT_NAME] = {
            "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
        }
        (self.output / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "disagrees with independent replay"):
            self.verify_small_campaign()

    def test_partial_evidence_and_wrong_source_are_rejected(self):
        manifest = self.write_small_campaign()
        manifest["source"]["tree_sha"] = "0" * 40
        (self.output / MANIFEST_NAME).write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "different source revision"):
            self.verify_small_campaign()
        (self.output / MARKDOWN_NAME).unlink()
        with self.assertRaisesRegex(ValueError, "incomplete"):
            self.verify_small_campaign()

    def test_campaign_reaches_all_cases_and_detects_faults(self):
        report = _campaign(42, 2, {})
        self.assertEqual("PASS", report["status"])
        self.assertEqual(2 * len(load_corpus().scenarios), report["summary"]["scenario_runs"])
        self.assertEqual(len(FAULTS), report["summary"]["defects_detected"])
        self.assertEqual([], report["unexercised_invariants"])
        for control in report["fault_controls"]:
            with self.subTest(fault=control["id"]):
                defective = control["defective_trial"]
                self.assertEqual("FAIL", defective["status"])
                self.assertIn(control["expected_violation"], defective["violations"])
                for stage in defective["stages"]:
                    self.assertEqual(stage["checkpoint"], stage["expected_checkpoint"])
        adaptive = [scenario for scenario in report["scenarios"] if scenario["kind"] == "adaptive"]
        self.assertEqual(6, len(adaptive))
        for scenario in adaptive:
            with self.subTest(scenario=scenario["id"]):
                stages = scenario["representative_trial"]["stages"]
                self.assertEqual("adapted", stages[-1]["stage"])
                self.assertFalse(any(row["domain"] == "safety" or row["operation"] == "data_export"
                                     for stage in stages for row in stage["observed_effects"]))

    def test_writes_after_generator_exhaustion_are_detected(self):
        case = next(case for case in load_corpus().scenarios if case.id == "unauthorized-steering")

        def unobserved_write(case_id, trial):
            yield from scenario_steps(case_id, trial)
            trial.vehicle._ledger.record(trial.anchor.faulty_effect())

        with (
            patch("wolftrap.gt_vsa_challenge.scenario_steps", unobserved_write),
            ThreadPoolExecutor(max_workers=2) as pool,
        ):
            trial = _run_trial(case, seed=42, index=0, pool=pool)
        self.assertEqual("FAIL", trial["status"])
        self.assertEqual(["unobserved-ledger-change-at-final-checkpoint"], trial["violations"])

    def test_deny_all_reports_failure_with_missing_positive_baselines(self):
        with patch("wolftrap.gt_vsa_fixtures.Trial.send", return_value=DENIED):
            report = _campaign(42, 1, {})
        self.assertEqual("FAIL", report["status"])
        self.assertGreater(report["summary"]["failed_runs"], 0)
        audit_trial = next(trial for trial in report["failure_samples"]
                           if trial["scenario"] == "audit-evidence-manipulation")
        self.assertIn("first:missing-expected-effects", audit_trial["violations"])
        self.assertTrue(any(control["defective_trial"] is None for control in report["fault_controls"]))

"""Fail-closed controls for sandbox envelope and authority composition."""

from __future__ import annotations

import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap.agent_scan import _json, _sha
from wolftrap.cli import main
from wolftrap.sandbox_funnel import (
    MANIFEST_NAME, MARKDOWN_NAME, REPORT_NAME, _sandbox_gate, _stages,
    _validate_stage, evaluate_challenge, run_challenge, verify_evidence,
)


class SandboxAuthorityTests(unittest.TestCase):
    def test_three_stages_cover_one_thousand_intents_each(self) -> None:
        report = evaluate_challenge()
        self.assertEqual(report["qualification"]["status"], "PASSED_BOUNDED")
        self.assertEqual(report["summary"], {"stages": 3, "intents": 3000, "mismatches": 0})
        self.assertEqual([stage["stage"] for stage in report["stages"]], [
            "1-sandbox-envelopes", "2-host-authority", "3-effect-boundary",
        ])
        self.assertEqual([len(stage["observed_effects"]) for stage in report["stages"]],
                         [1, 1, 1])
        self.assertTrue(all(len(stage["decisions"]) == 1000 for stage in report["stages"]))
        self.assertEqual(report["stages"][0]["decisions"][0]["authority_reason"], None)
        self.assertEqual(report["stages"][2]["decisions"][-1]["authority_reason"],
                         "SLOT_EXHAUSTED")
        self.assertEqual(report["stages"][0]["observed_sandbox"], {
            "UNKNOWN_SANDBOX": 250, "FILESYSTEM_DENIED": 250, "NETWORK_DENIED": 250,
            "APPROVAL_REQUIRED": 249, "ADMITTED": 1,
        })
        self.assertEqual(report["stages"][2]["observed_authority"], {
            "STALE_EPOCH": 300, "REVOKED": 300, "EXPIRED_OR_NOT_YET_VALID": 398,
            "ACCEPTED": 1, "SLOT_EXHAUSTED": 1,
        })
        self.assertFalse(report["qualification"]["real_sandbox_enforced"])
        self.assertFalse(report["qualification"]["ground_truth_runtime_tested"])
        self.assertFalse(report["qualification"]["hercules_runtime_tested"])
        self.assertFalse(report["qualification"]["live_agent_concurrency_tested"])

    def test_tool_claim_cannot_bypass_host_sandbox_or_create_a_grant(self) -> None:
        isolation, authority, _ = _stages()
        outside = isolation["intents"][250]
        self.assertEqual(outside["proposal"]["tool_claim"], "SYSTEM_OVERRIDE")
        self.assertEqual(_sandbox_gate(isolation["envelopes"], outside),
                         "FILESYSTEM_DENIED")
        untrusted = authority["intents"][0]
        self.assertEqual(untrusted["proposal"]["tool_claim"], "VENDOR_APPROVAL")
        self.assertEqual(_sandbox_gate(authority["envelopes"], untrusted), "ADMITTED")
        self.assertEqual(evaluate_challenge()["stages"][1]["observed_authority"],
                         {"DELEGATE_MISMATCH": 999, "ACCEPTED": 1})

    def test_cross_agent_envelope_substitution_and_fail_open_are_caught(self) -> None:
        _, stage, _ = _stages()
        forged = dict(stage["intents"][1],
                      environment_id=stage["intents"][0]["environment_id"])
        self.assertEqual(_sandbox_gate(stage["envelopes"], forged), "UNKNOWN_SANDBOX")
        unknown = dict(stage["envelopes"])
        unknown[stage["intents"][0]["environment_id"]] = {
            **unknown[stage["intents"][0]["environment_id"]],
            "isolation_enforced": False,
        }
        self.assertEqual(_sandbox_gate(unknown, stage["intents"][0]), "UNKNOWN_ISOLATION")
        with patch("wolftrap.sandbox_funnel._sandbox_gate", return_value="ADMITTED"):
            self.assertEqual(evaluate_challenge()["qualification"]["status"], "CONTROL_GAP")
        with patch("wolftrap.sandbox_funnel._sandbox_gate", return_value="UNKNOWN_SANDBOX"):
            self.assertEqual(evaluate_challenge()["qualification"]["status"], "CONTROL_GAP")

    def test_malformed_and_unbounded_profiles_are_rejected(self) -> None:
        stage = _stages()[1]
        cases = (
            dict(stage, intents=[dict(stage["intents"][0], file_request="../../etc")]
                 + stage["intents"][1:]),
            dict(stage, intents=[dict(stage["intents"][0], network_request="https://host")]
                 + stage["intents"][1:]),
            dict(stage, intents=stage["intents"][:-1]),
            dict(stage, intents=[dict(stage["intents"][0], shell="/bin/sh")]
                 + stage["intents"][1:]),
            dict(stage, envelopes={**stage["envelopes"],
                                   "synthetic-env://bot1000": {
                                       "agent_id": "synthetic-agent://bot1000",
                                       "isolation_enforced": True, "filesystem": "SCOPED",
                                       "network": "DENIED", "approval": True,
                                   }}),
        )
        for case in cases:
            with self.subTest(case=list(case)), self.assertRaises(ValueError):
                _validate_stage(case)

    def test_reported_effect_without_an_independent_write_does_not_qualify(self) -> None:
        from wolftrap.authority_funnel import _enforce_funnel as real_gate

        def fake_success(grants, proposals, *, record_effect, **options):
            # The gate claims success but never calls the independent sink.
            return real_gate(grants, proposals, **options)

        with patch("wolftrap.sandbox_funnel._enforce_funnel", side_effect=fake_success):
            report = evaluate_challenge()
        self.assertEqual(report["qualification"]["status"], "CONTROL_GAP")
        self.assertTrue(all(not row["observed_effects"] for row in report["stages"]))
        self.assertTrue(all(row["claimed_effects"] for row in report["stages"]))

    def test_replay_rejects_rehashed_tampering_and_extra_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            socket, "socket", side_effect=AssertionError("network attempted"),
        ):
            directory = Path(tmp) / "evidence"
            report, code = run_challenge(directory)
            self.assertEqual(code, 0)
            self.assertEqual(verify_evidence(directory), report)
            self.assertEqual(main(["verify-sandbox-authority", "--evidence-dir",
                                   str(directory)]), 0)
            with self.assertRaises(ValueError):
                run_challenge(directory)
            (directory / "extra").write_text("injected")
            with self.assertRaises(ValueError):
                verify_evidence(directory)
            (directory / "extra").unlink()
            altered = (directory / REPORT_NAME).read_bytes().replace(
                b'"mismatches": 0', b'"mismatches": 1', 1)
            (directory / REPORT_NAME).write_bytes(altered)
            manifest = json.loads((directory / MANIFEST_NAME).read_bytes())
            manifest["files"][REPORT_NAME] = {"bytes": len(altered), "sha256": _sha(altered)}
            (directory / MANIFEST_NAME).write_bytes(_json(manifest))
            with self.assertRaises(ValueError):
                verify_evidence(directory)

    def test_symlink_and_missing_evidence_cannot_be_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "evidence"
            run_challenge(directory)
            saved = Path(tmp) / "saved.md"
            (directory / MARKDOWN_NAME).rename(saved)
            (directory / MARKDOWN_NAME).symlink_to(saved)
            with self.assertRaises(ValueError):
                verify_evidence(directory)
            (directory / MARKDOWN_NAME).unlink()
            with self.assertRaises(ValueError):
                verify_evidence(directory)

    def test_cli_runs_and_replays_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            socket, "socket", side_effect=AssertionError("network attempted"),
        ):
            directory = Path(tmp) / "challenge"
            self.assertEqual(main(["challenge-sandbox-authority", "--output-dir",
                                   str(directory)]), 0)
            self.assertEqual(main(["verify-sandbox-authority", "--evidence-dir",
                                   str(directory)]), 0)


if __name__ == "__main__":
    unittest.main()

"""Synthetic controls for advisory isolation, replay and evidence tampering."""

from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from wolftrap.agent_scan import _json, _sha
from wolftrap.execution import execute_case
from wolftrap.prompt_scan import scan_prompts
from wolftrap.prompt_trust import (
    MANIFEST_NAME, REPORT_NAME, evaluate_prompt_trust, run_prompt_trust, verify_prompt_trust,
)
from wolftrap.system import DenyAllSyntheticSystem


class PromptTrustTests(unittest.TestCase):
    def test_text_controls_and_authority_effects_are_evaluated_separately(self) -> None:
        report = evaluate_prompt_trust()
        self.assertEqual(report["classification"], "SYNTHETICALLY VERIFIED")
        self.assertEqual(report["live_verification"], "NOT TESTED")
        self.assertEqual(report["summary"]["authority_checks"], 65)
        self.assertEqual(report["summary"]["synthetic_protected_effects"], 13)
        advisories = {row["fixture_id"]: row for row in report["advisories"]}
        for fixture in ("priority-literal", "priority-fullwidth", "priority-json-escape"):
            self.assertEqual(advisories[fixture]["rules"], ["WT-PROMPT-001"])
        self.assertEqual(advisories["benign-narration"]["fixture_kind"], "BENIGN_LOOKALIKE")
        self.assertEqual(advisories["benign-narration"]["classification"], "STATIC REVIEW SIGNAL")
        for fixture in ("role-spoof", "priority-quoted", "approval-laundering",
                        "cross-agent-message-substitution"):
            self.assertEqual(advisories[fixture]["fixture_kind"], "KNOWN_LEXICAL_MISS")
            self.assertEqual(advisories[fixture]["status"], "NO_PATTERN_MATCH")
        for fixture in ("unsupported-format", "invalid-utf8", "malformed-json"):
            self.assertEqual(advisories[fixture]["classification"], "INCONCLUSIVE")

        for row in report["results"]:
            self.assertTrue(row["oracle_passed"])
            self.assertEqual(len(row["observed_effects"]), len(row["reference_effects"]))
            for observed, reference in zip(row["observed_effects"], row["reference_effects"]):
                self.assertEqual({field: observed[field] for field in reference}, reference)
            self.assertEqual(row["observed_denial"], row["expected_denial"])
            if row["authority_axis"] == "current-host-grant":
                self.assertEqual(len(row["observed_effects"]), 1)
            else:
                self.assertEqual(row["observed_effects"], [])

    def test_deny_all_fails_legitimate_controls(self) -> None:
        with patch("wolftrap.prompt_trust.execute_case",
                   side_effect=lambda case: execute_case(case, DenyAllSyntheticSystem)):
            report = evaluate_prompt_trust()
        self.assertEqual(report["classification"], "INCONCLUSIVE")
        self.assertEqual(report["summary"]["synthetic_protected_effects"], 0)
        self.assertGreaterEqual(report["summary"]["authority_mismatches"], 13)

    def test_removed_lexical_findings_fail_only_the_text_controls(self) -> None:
        def drop_signals(*args, **kwargs):
            observed = scan_prompts(*args, **kwargs)
            if observed.exit_code != 1:
                return observed
            return replace(observed, report={
                **observed.report, "findings": [],
                "qualification": {"status": "NO_PATTERN_MATCH"},
            }, exit_code=0)

        with patch("wolftrap.prompt_trust.scan_prompts", side_effect=drop_signals):
            report = evaluate_prompt_trust()
        self.assertEqual(report["classification"], "INCONCLUSIVE")
        self.assertEqual(report["summary"]["text_mismatches"], 4)
        self.assertEqual(report["summary"]["authority_mismatches"], 0)
        self.assertEqual(report["summary"]["synthetic_protected_effects"], 13)

    def test_offline_replay_and_tamper_rejection(self) -> None:
        deny_socket = AssertionError("network unavailable during offline replay")
        with (tempfile.TemporaryDirectory() as scratch,
              patch("socket.socket", side_effect=deny_socket),
              patch("socket.create_connection", side_effect=deny_socket),
              patch("socket.getaddrinfo", side_effect=deny_socket)):
            output = Path(scratch) / "evidence"
            report = run_prompt_trust(output)
            report_path = output / REPORT_NAME
            manifest_path = output / MANIFEST_NAME
            self.assertEqual(report, verify_prompt_trust(output))
            self.assertNotIn(b"fictional approval record", report_path.read_bytes())
            self.assertNotIn(scratch.encode(), report_path.read_bytes())

            altered = dict(report, live_verification="LIVE VERIFIED")
            tampered = _json(altered)
            report_path.write_bytes(tampered)
            with self.assertRaisesRegex(ValueError, "differs from its manifest"):
                verify_prompt_trust(output)

            # Recomputing a manifest cannot defeat fresh replay.
            manifest = json.loads(manifest_path.read_bytes())
            manifest["files"][REPORT_NAME] = {"bytes": len(tampered), "sha256": _sha(tampered)}
            manifest_path.write_bytes(_json(manifest))
            with self.assertRaisesRegex(ValueError, "differs from replay"):
                verify_prompt_trust(output)

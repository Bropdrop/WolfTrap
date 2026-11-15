"""Adversarial evidence-integrity regressions from the implementation review."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap import agent_scan
from wolftrap.agent_scan import scan_agent, verify_agent_evidence
from wolftrap.agent_rules import inspect_text
from wolftrap.cli import main


class AgentIntegrityReviewTests(unittest.TestCase):
    def fixture(self, directory: str) -> tuple[Path, Path]:
        root = Path(directory) / "source"
        root.mkdir()
        (root / "benign.ts").write_text("const harmless = true;\n", encoding="utf-8")
        return root, Path(directory) / "evidence"

    def test_unexpected_parser_exception_is_redacted_and_inconclusive(self) -> None:
        marker = "SYNTHETIC_EXCEPTION_VALUE_MUST_NOT_APPEAR"
        with tempfile.TemporaryDirectory() as directory:
            root, output = self.fixture(directory)
            stdout, stderr = io.StringIO(), io.StringIO()
            with (patch.object(agent_scan, "inspect_text", side_effect=KeyError(marker)),
                  contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr)):
                code = main(["scan-agent", "--root", str(root), "--output-dir", str(output)])
            self.assertEqual(2, code)
            report = verify_agent_evidence(output)
            self.assertEqual("INCONCLUSIVE", report["qualification"]["status"])
            self.assertNotIn(marker, stdout.getvalue() + stderr.getvalue())
            for path in output.iterdir():
                self.assertNotIn(marker.encode(), path.read_bytes())

    def test_semantically_inconsistent_report_cannot_be_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, output = self.fixture(directory)
            report = scan_agent(root, output).report
            report["errors"] = ["inspection was incomplete"]
            report["summary"]["errors"] = 1
            # Re-hashing every artifact must not make inconsistent semantics valid.
            rendered = agent_scan._render(report)
            for name, raw in rendered.items():
                (output / name).write_bytes(raw)
            manifest = json.loads((output / agent_scan.MANIFEST_NAME).read_text())
            manifest["files"] = {
                name: {"bytes": len(raw), "sha256": agent_scan._sha(raw)}
                for name, raw in rendered.items()
            }
            (output / agent_scan.MANIFEST_NAME).write_bytes(agent_scan._json(manifest))
            with self.assertRaises(ValueError):
                verify_agent_evidence(output)

    def test_malformed_manifest_shape_is_safely_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, output = self.fixture(directory)
            scan_agent(root, output)
            (output / agent_scan.MANIFEST_NAME).write_text("[]\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "incomplete, unsafe or inconsistent"):
                verify_agent_evidence(output)

    def test_new_source_after_discovery_cannot_claim_complete_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root, output = self.fixture(directory)
            discover = agent_scan._discover
            changed = False

            def add_after_discovery(descriptor):
                nonlocal changed
                result = discover(descriptor)
                if not changed:
                    (root / "new.ts").write_text(
                        "function authenticate(identity) { return true; }\n",
                        encoding="utf-8",
                    )
                    changed = True
                return result

            with patch.object(agent_scan, "_discover", side_effect=add_after_discovery):
                outcome = scan_agent(root, output)
            self.assertEqual(2, outcome.exit_code)
            self.assertFalse(outcome.report["qualification"]["complete_input"])

    def test_inner_scope_cannot_clear_outer_credential_alias(self) -> None:
        source = ('"use client"; const token=session.token; '
                  'function render(){const token="[REDACTED]";} console.log(token);')
        signals, issues = inspect_text(source)
        self.assertTrue(issues or any(item["rule_id"] == "WT-AGENT-003" for item in signals))

    def test_parameter_shadowing_is_not_an_established_outer_credential_flow(self) -> None:
        source = ('"use client"; const token=session.token; '
                  'function render(token){console.log(token);}')
        signals, issues = inspect_text(source)
        self.assertFalse(any(item["rule_id"] == "WT-AGENT-003" for item in signals))
        self.assertTrue(issues)

    def test_explicit_redacted_object_fields_do_not_create_exposure_signals(self) -> None:
        for source in (
            '"use client"; console.log({sessionToken:"[REDACTED]"});',
            '"use client"; console.log({client_secret:"[REDACTED]"});',
            '"use client"; const metadata={ephemeralKey:"[REDACTED]"}; console.log(metadata);',
        ):
            with self.subTest(source=source):
                signals, _ = inspect_text(source)
                self.assertFalse(any(item["rule_id"] == "WT-AGENT-003" for item in signals))

    def test_input_moderation_is_not_labelled_output_moderation(self) -> None:
        signals, issues = inspect_text(
            "try { moderateInput(input); } catch { return {tripwireTriggered:false}; }"
        )
        self.assertFalse(issues)
        self.assertEqual(["INPUT_MODERATION"], [item["boundary"] for item in signals])

    def test_tautological_auth_conditions_are_not_recognized_as_meaningful_checks(self) -> None:
        for source in (
            "function authenticate(identity){if(identity){} return true;}",
            'const authenticate=identity=>identity==="admin" || true;',
        ):
            with self.subTest(source=source):
                signals, issues = inspect_text(source)
                self.assertTrue(issues or any(item["rule_id"] == "WT-AGENT-002" for item in signals))


if __name__ == "__main__":
    unittest.main()

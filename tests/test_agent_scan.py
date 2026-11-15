"""Independent containment, evidence, and compatibility checks for scan-agent."""

from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import subprocess
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Iterator
from unittest.mock import patch

from wolftrap import agent_scan
from wolftrap.agent_scan import (
    MANIFEST_NAME,
    MARKDOWN_NAME,
    REPORT_NAME,
    SARIF_NAME,
    scan_agent,
    verify_agent_evidence,
)
from wolftrap.cli import main


BENIGN = 'const message = "synthetic ordinary application text";\n'
MOCK_AUTH = 'function authenticate(identity) { return true; }\n'
ARTIFACTS = (REPORT_NAME, MARKDOWN_NAME, SARIF_NAME, MANIFEST_NAME)


@contextmanager
def fixture(source: str | None = BENIGN) -> Iterator[tuple[Path, Path]]:
    with tempfile.TemporaryDirectory(prefix="wolftrap-agent-safety-") as directory:
        root = Path(directory) / "source"
        root.mkdir()
        if source is not None:
            (root / "agent.ts").write_text(source, encoding="utf-8")
        yield root, Path(directory) / "evidence"


class AgentScanSafetyTests(unittest.TestCase):
    def assert_inconclusive(self, root: Path, output: Path, **kwargs):
        outcome = scan_agent(root, output, **kwargs)
        self.assertEqual(outcome.exit_code, 2)
        self.assertEqual(outcome.report["qualification"]["status"], "INCONCLUSIVE")
        self.assertFalse(outcome.report["qualification"]["complete_input"])
        self.assertGreater(outcome.report["summary"]["errors"], 0)
        return outcome

    def test_no_match_is_not_security_certification(self) -> None:
        with fixture() as (root, output):
            before = (root / "agent.ts").read_bytes()
            outcome = scan_agent(root, output)
            self.assertEqual(outcome.exit_code, 0)
            self.assertEqual(outcome.report["qualification"]["status"], "NO_PATTERN_MATCH")
            self.assertEqual(outcome.report["qualification"]["confirmed_vulnerabilities"], 0)
            self.assertTrue(outcome.report["qualification"]["limited_not_exhaustive"])
            self.assertEqual(outcome.report["findings"], [])
            self.assertEqual(before, (root / "agent.ts").read_bytes())
            self.assertIn("security certification", (output / MARKDOWN_NAME).read_text().lower())
            self.assertIn("No match is not a security certification.", outcome.report["limitations"])

    def test_supported_mock_success_remains_conditional_review(self) -> None:
        with fixture(MOCK_AUTH) as (root, output):
            outcome = scan_agent(root, output)
            self.assertEqual(outcome.exit_code, 1)
            self.assertEqual(outcome.report["qualification"]["status"], "REVIEW_REQUIRED")
            self.assertEqual({f["rule_id"] for f in outcome.report["findings"]}, {"WT-AGENT-002"})
            for finding in outcome.report["findings"]:
                self.assertEqual(finding["classification"], "REVIEW_REQUIRED")
                self.assertEqual(finding["confidence"], "CONDITIONAL_STATIC")
                self.assertGreaterEqual(finding["line"], 1)

    def test_complete_evidence_has_exact_hashes_and_sarif_rule_identity(self) -> None:
        with fixture(MOCK_AUTH) as (root, output):
            outcome = scan_agent(root, output)
            manifest = json.loads((output / MANIFEST_NAME).read_text())
            self.assertEqual(manifest["state"], "COMPLETE")
            self.assertEqual(set(manifest["files"]), {REPORT_NAME, MARKDOWN_NAME, SARIF_NAME})
            for name, record in manifest["files"].items():
                payload = (output / name).read_bytes()
                self.assertEqual(record, {"bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
            self.assertEqual(verify_agent_evidence(output), outcome.report)
            sarif = json.loads((output / SARIF_NAME).read_text())
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual({r["ruleId"] for r in sarif["runs"][0]["results"]}, {"WT-AGENT-002"})
            self.assertEqual(len(sarif["runs"][0]["tool"]["driver"]["rules"]), 3)

    def test_auth_context_comments_do_not_change_review_classification(self) -> None:
        for source, expected_context in (
            ("const authenticate=()=>true;", "CONTEXT_NOT_ESTABLISHED"),
            ("/* unrelated mock theme */ const authenticate=()=>true;", "CONTEXT_NOT_ESTABLISHED"),
            ("const mockAuthenticate=()=>true;", "DEMO_OR_MOCK_CONTEXT"),
            ("// unrelated theme\nconst demoApprove=()=>true;", "DEMO_OR_MOCK_CONTEXT"),
        ):
            with self.subTest(source=source), fixture(source) as (root, output):
                before = (root / "agent.ts").read_bytes()
                outcome = scan_agent(root, output)
                self.assertEqual(outcome.exit_code, 1)
                self.assertEqual(outcome.report["qualification"]["status"], "REVIEW_REQUIRED")
                self.assertEqual(len(outcome.report["findings"]), 1)
                finding = outcome.report["findings"][0]
                self.assertEqual(finding["rule_id"], "WT-AGENT-002")
                self.assertEqual(finding["classification"], "REVIEW_REQUIRED")
                self.assertEqual(finding["confidence"], "CONDITIONAL_STATIC")
                self.assertEqual(finding["context"], expected_context)
                self.assertEqual(verify_agent_evidence(output), outcome.report)
                self.assertEqual(before, (root / "agent.ts").read_bytes())

    def test_inputs_are_not_executed_and_network_is_not_used(self) -> None:
        source = MOCK_AUTH + 'const inert = "do not execute inspected source";\n'
        with fixture(source) as (root, output):
            before = (root / "agent.ts").read_bytes()
            with (
                patch.object(subprocess, "Popen", side_effect=AssertionError("execution forbidden")),
                patch.object(socket, "socket", side_effect=AssertionError("network forbidden")),
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")),
                patch.dict(os.environ, {"OPENAI_API_KEY": "SYNTHETIC_UNUSED_PROVIDER_VALUE"}),
            ):
                outcome = scan_agent(root, output)
            self.assertEqual(outcome.exit_code, 1)
            self.assertFalse(outcome.report["target_code_executed"])
            self.assertFalse(outcome.report["external_systems_contacted"])
            self.assertFalse(outcome.report["model_used"])
            self.assertEqual(before, (root / "agent.ts").read_bytes())

    def test_reports_are_byte_identical_on_reinspection(self) -> None:
        with fixture(MOCK_AUTH) as (root, output):
            first = scan_agent(root, output)
            second_output = output.parent / "second"
            second = scan_agent(root, second_output)
            self.assertEqual(first.report, second.report)
            for name in ARTIFACTS:
                self.assertEqual((output / name).read_bytes(), (second_output / name).read_bytes())

    def test_paths_literals_and_synthetic_credential_values_are_not_disclosed(self) -> None:
        marker = "SYNTHETIC_CREDENTIAL_DO_NOT_DISCLOSE_7E3A"
        source = f'"use client";\nconst sessionToken = "{marker}";\nconsole.log(sessionToken);\n'
        with fixture(None) as (root, output):
            relative = marker + ".ts"
            (root / relative).write_text(source, encoding="utf-8")
            outcome = scan_agent(root, output)
            self.assertEqual(outcome.exit_code, 1)
            self.assertEqual({f["rule_id"] for f in outcome.report["findings"]}, {"WT-AGENT-003"})
            path_digest = hashlib.sha256(relative.encode()).hexdigest()
            for name in ARTIFACTS:
                text = (output / name).read_text(encoding="utf-8")
                self.assertNotIn(marker, text)
                self.assertNotIn(source, text)
                self.assertNotIn(str(root), text)
            self.assertEqual(outcome.report["findings"][0]["path"], "source-" + path_digest + ".ts")

    def test_malformed_input_error_does_not_echo_source(self) -> None:
        marker = "SYNTHETIC_BROKEN_LITERAL_DO_NOT_DISCLOSE"
        with fixture(f'const x = "{marker}') as (root, output):
            self.assert_inconclusive(root, output)
            for name in ARTIFACTS:
                self.assertNotIn(marker, (output / name).read_text())

    def test_missing_input_and_missing_explicit_file_are_inconclusive(self) -> None:
        with fixture(None) as (root, output):
            self.assert_inconclusive(root, output)
        with fixture() as (root, output):
            self.assert_inconclusive(root, output, files=["missing.ts"])
        with fixture() as (root, output):
            self.assert_inconclusive(root / "absent-root", output)

    def test_invalid_utf8_is_inconclusive_without_replacement_decoding(self) -> None:
        with fixture(None) as (root, output):
            (root / "agent.ts").write_bytes(b"\xff\xfe\x80")
            self.assert_inconclusive(root, output)

    def test_unsupported_explicit_extension_is_inconclusive(self) -> None:
        with fixture(None) as (root, output):
            (root / "agent.txt").write_text(MOCK_AUTH, encoding="utf-8")
            self.assert_inconclusive(root, output, files=["agent.txt"])

    def test_per_file_and_aggregate_byte_bounds(self) -> None:
        with fixture(None) as (root, output):
            (root / "agent.ts").write_bytes(b" " * (256 * 1024 + 1))
            self.assert_inconclusive(root, output)
        with fixture(None) as (root, output):
            for index in range(9):
                (root / f"agent{index}.ts").write_bytes(b" " * (256 * 1024))
            self.assert_inconclusive(root, output)

    def test_file_count_bound(self) -> None:
        with fixture(None) as (root, output):
            for index in range(65):
                (root / f"agent{index}.ts").write_text(BENIGN, encoding="utf-8")
            self.assert_inconclusive(root, output)

    def test_directory_entry_and_depth_bounds(self) -> None:
        with fixture() as (root, output):
            for index in range(1025):
                (root / f"entry{index}.txt").touch()
            self.assert_inconclusive(root, output)
        with fixture(None) as (root, output):
            nested = root
            for index in range(14):
                nested = nested / f"level{index}"
                nested.mkdir()
            (nested / "agent.ts").write_text(BENIGN, encoding="utf-8")
            self.assert_inconclusive(root, output)

    def test_absolute_and_parent_escape_selectors_fail_closed(self) -> None:
        for selector in ("../outside.ts", "/outside.ts", "nested/../../outside.ts"):
            with self.subTest(selector=selector), fixture() as (root, output):
                outside = root.parent / "outside.ts"
                outside.write_text(MOCK_AUTH, encoding="utf-8")
                before = outside.read_bytes()
                self.assert_inconclusive(root, output, files=[selector])
                self.assertEqual(before, outside.read_bytes())

    def test_symlink_file_and_symlink_directory_inputs_are_inconclusive(self) -> None:
        with fixture(None) as (root, output):
            outside = root.parent / "outside.ts"
            outside.write_text(MOCK_AUTH, encoding="utf-8")
            (root / "agent.ts").symlink_to(outside)
            self.assert_inconclusive(root, output)
        with fixture(None) as (root, output):
            outside = root.parent / "outside"
            outside.mkdir()
            (outside / "agent.ts").write_text(MOCK_AUTH, encoding="utf-8")
            (root / "nested").symlink_to(outside, target_is_directory=True)
            self.assert_inconclusive(root, output, files=["nested/agent.ts"])

    def test_root_symlink_and_ancestor_symlink_are_inconclusive(self) -> None:
        with fixture() as (root, output):
            link = root.parent / "linked-root"
            link.symlink_to(root, target_is_directory=True)
            self.assert_inconclusive(link, output)
        with fixture() as (root, output):
            link = root.parent / "linked-parent"
            link.symlink_to(root.parent, target_is_directory=True)
            self.assert_inconclusive(link / root.name, output)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO support")
    def test_nonregular_fifo_is_rejected_without_reading(self) -> None:
        with fixture(None) as (root, output):
            os.mkfifo(root / "agent.ts")
            self.assert_inconclusive(root, output)

    def test_output_inside_source_is_refused_before_any_write(self) -> None:
        with fixture() as (root, _):
            destination = root / "evidence"
            with self.assertRaises(ValueError):
                scan_agent(root, destination)
            self.assertFalse(destination.exists())

    def test_output_symlink_and_ancestor_symlink_are_refused(self) -> None:
        with fixture() as (root, output):
            real = root.parent / "real-output"
            real.mkdir()
            output.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                scan_agent(root, output)
            self.assertEqual(list(real.iterdir()), [])
        with fixture() as (root, output):
            real = root.parent / "real-output"
            real.mkdir()
            output.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                scan_agent(root, output / "nested")
            self.assertEqual(list(real.iterdir()), [])

    def test_nonempty_output_is_preserved(self) -> None:
        with fixture() as (root, output):
            output.mkdir()
            marker = output / "owner-file"
            marker.write_text("retain", encoding="utf-8")
            with self.assertRaises(ValueError):
                scan_agent(root, output)
            self.assertEqual(marker.read_text(), "retain")
            self.assertEqual(list(output.iterdir()), [marker])

    def test_evidence_tampering_and_incomplete_state_are_rejected(self) -> None:
        with fixture() as (root, output):
            scan_agent(root, output)
            report_path = output / REPORT_NAME
            report_path.write_text(report_path.read_text() + " ", encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_agent_evidence(output)
            (output / MANIFEST_NAME).write_text('{"state":"INCOMPLETE"}\n', encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_agent_evidence(output)

    def test_evidence_member_symlink_is_rejected(self) -> None:
        with fixture() as (root, output):
            scan_agent(root, output)
            evidence = output / REPORT_NAME
            outside = root.parent / "copied-report.json"
            outside.write_bytes(evidence.read_bytes())
            evidence.unlink()
            evidence.symlink_to(outside)
            with self.assertRaises(ValueError):
                verify_agent_evidence(output)

    def test_interrupted_publication_cannot_complete_manifest(self) -> None:
        with fixture() as (root, output):
            original = agent_scan._publish

            def fail_sarif(directory, name, payload):
                if name == SARIF_NAME:
                    raise OSError("injected evidence write failure")
                return original(directory, name, payload)

            with patch.object(agent_scan, "_publish", side_effect=fail_sarif):
                with self.assertRaises(OSError):
                    scan_agent(root, output)
            manifest = json.loads((output / MANIFEST_NAME).read_text())
            self.assertEqual(manifest["state"], "INCOMPLETE")
            with self.assertRaises(ValueError):
                verify_agent_evidence(output)

    def test_cli_preserves_scan_agent_status_and_sanitizes_input_errors(self) -> None:
        with fixture(MOCK_AUTH) as (root, output):
            stdout, stderr = io.StringIO(), io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                code = main(["scan-agent", "--root", str(root), "--output-dir", str(output)])
            self.assertEqual(code, 1)
            self.assertIn("REVIEW_REQUIRED", stdout.getvalue())
            self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()

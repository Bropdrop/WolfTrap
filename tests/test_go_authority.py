"""Hostile and benign controls for bounded, offline Go authority triage."""

from __future__ import annotations

import hashlib
import io
import json
import socket
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from wolftrap.cli import main
from wolftrap.go_rules import GoUnsupported, RULES, inspect_go_source
from wolftrap.go_scan import (
    MANIFEST_NAME, MARKDOWN_NAME, REPORT_NAME, SARIF_NAME,
    scan_go_authority, verify_go_evidence,
)


ALLOW = """package example
func tool() Tool {
    return Tool{Permissions: func(ctx Context) permission.Decision {
        return permission.Allowed()
    }}
}
"""
ENV_PROCESS = """package example
func launch(ctx context.Context) {
    child := exec.CommandContext(ctx, "python3", "worker.py")
    child.Env = append(os.Environ(), "SAFE=1")
    child.CombinedOutput()
}
"""
PROXY = """package example
func (s *Service) network(ctx context.Context) *http.Transport {
    if peer := s.httpProxyTransport(spec); peer != nil {
        return peer
    }
    direct := &http.Transport{DialContext: intercept.PinnedDialer("test", true)}
    return direct
}
"""
OPTIONAL = """package example
func (g *Guard) applyIntercept(ctx context.Context) hook.Result {
    if !rules && !gated {
        return hook.Result{}
    }
    return hook.Result{}
}
"""

POSITIVES = {
    "WT-GO-001": ALLOW,
    "WT-GO-002": ENV_PROCESS,
    "WT-GO-003": PROXY,
    "WT-GO-004": OPTIONAL,
}
NEGATIVES = (
    """package example
func safe() Tool {
    return Tool{Permissions: func(ctx Context) permission.Decision {
        if authorized(ctx) { return permission.Allowed() }
        return permission.Denied()
    }}
}
""",
    """package example
func safe(ctx context.Context) {
    child := exec.CommandContext(ctx, "python3", "worker.py")
    child.Env = []string{"PATH=/bin"}
    child.CombinedOutput()
}
""",
    """package example
func safe(ctx context.Context) {
    child := exec.CommandContext(ctx, "python3", "worker.py")
    child.CombinedOutput()
}
func unrelated() {
    x.Env = append(os.Environ(), "SAFE=1")
}
""",
    """package example
func (s *Service) safe(ctx context.Context) *http.Transport {
    direct := &http.Transport{DialContext: intercept.PinnedDialer("test", true)}
    if peer := s.httpProxyTransport(spec); peer != nil { return peer }
    return direct
}
""",
    """package example
func ordinary() hook.Result {
    if !rules && !gated { return hook.Result{} }
    return hook.Result{}
}
""",
    """package example
func (g *Guard) applyIntercept(ctx context.Context) hook.Result {
    if !rules && !gated { return hook.Result{Blocked: true} }
    return hook.Result{Blocked: true}
}
""",
)


class GoAuthorityRulesTests(unittest.TestCase):
    def test_all_rule_ids_are_unique_and_bounded(self) -> None:
        self.assertEqual(len(RULES), 4)
        self.assertEqual(len(set(RULES.values())), len(RULES))

    def test_independently_labelled_positive_controls(self) -> None:
        for rule_id, source in POSITIVES.items():
            with self.subTest(rule_id=rule_id):
                found = inspect_go_source(source)
                self.assertEqual([f["rule_id"] for f in found], [rule_id])
                self.assertGreaterEqual(found[0]["line"], 1)
                self.assertEqual(found[0]["boundary"], "GO_PROTECTED_EFFECT")

    def test_benign_lookalikes_do_not_match(self) -> None:
        for source in NEGATIVES:
            with self.subTest(source=source.splitlines()[1]):
                self.assertEqual(inspect_go_source(source), [])

    def test_comments_and_all_go_string_forms_do_not_trigger(self) -> None:
        fake = ALLOW + ENV_PROCESS + PROXY + OPTIONAL
        # Braces, quotes and apparent comments in literals must not affect parsing.
        source = (
            "package example\n"
            "// Permissions: func() { return permission.Allowed() }\n"
            "/* " + fake + " */\n"
            'var text = "' + fake.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"\n'
            "var raw = " + chr(96) + fake + chr(96) + "\n"
            "var slash = \"https://example.invalid//path{tag}\"\n"
            "func ok() { x := '}' ; _ = x }\n"
        )
        self.assertEqual(inspect_go_source(source), [])

    def test_multiline_and_reordered_cases_have_stable_line_numbers(self) -> None:
        base = "package example\n\n\n" + ENV_PROCESS.replace("package example\n", "")
        result = inspect_go_source(base)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["line"], 5)
        self.assertEqual(inspect_go_source(base), result)

    def test_malformed_source_fails_closed_with_fixed_codes(self) -> None:
        cases = {
            "package x\n/* dangling": "GO_UNTERMINATED_BLOCK_COMMENT",
            'package x\nvar secret = "dangling': "GO_UNTERMINATED_QUOTED_LITERAL",
            "package x\nfunc x() {": "GO_UNBALANCED_BRACES",
        }
        for source, expected in cases.items():
            with self.subTest(expected=expected):
                with self.assertRaises(GoUnsupported) as ctx:
                    inspect_go_source(source)
                self.assertEqual(str(ctx.exception), expected)

    def test_comment_mimic_does_not_mute_real_signal(self) -> None:
        source = "// old code returned denial\n" + ALLOW
        self.assertEqual([x["rule_id"] for x in inspect_go_source(source)], ["WT-GO-001"])


class GoAuthorityEvidenceTests(unittest.TestCase):
    def fixture(self, name: str = "fixture.go", content: str = ALLOW):
        temp = tempfile.TemporaryDirectory(prefix="wolftrap-go-review-")
        root = Path(temp.name) / "input"
        root.mkdir()
        (root / name).write_text(content, encoding="utf-8")
        return temp, root, Path(temp.name) / "evidence"

    def test_evidence_integrity_manifest_and_redaction(self) -> None:
        marker = "SYNTHETIC_SECRET_DO_NOT_COPY_1717"
        temp, root, evidence = self.fixture(
            marker + ".go", ALLOW + "// " + marker + "\n")
        with temp:
            before = next(root.iterdir()).read_bytes()
            outcome = scan_go_authority(root, evidence)
            self.assertEqual(outcome.exit_code, 1)
            self.assertEqual(outcome.report["summary"]["findings"], 1)
            self.assertEqual(outcome.report["qualification"]["confirmed_vulnerabilities"], 0)
            self.assertEqual(verify_go_evidence(evidence), outcome.report)
            self.assertEqual(before, next(root.iterdir()).read_bytes())
            manifest = json.loads((evidence / MANIFEST_NAME).read_text())
            self.assertEqual(manifest["state"], "COMPLETE")
            self.assertEqual(set(manifest["files"]), {REPORT_NAME, MARKDOWN_NAME, SARIF_NAME})
            for filename in (*manifest["files"], MANIFEST_NAME):
                raw = (evidence / filename).read_bytes()
                self.assertNotIn(marker.encode(), raw)
                self.assertNotIn(str(root).encode(), raw)
                self.assertNotIn(b"permission.Allowed", raw)
                if filename != MANIFEST_NAME:
                    self.assertEqual(manifest["files"][filename], {
                        "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()})
            sarif = json.loads((evidence / SARIF_NAME).read_text())
            self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "WT-GO-001")

    def test_rerun_is_byte_identical_and_replay_is_independent(self) -> None:
        temp, root, first = self.fixture(content=ALLOW + ENV_PROCESS)
        with temp:
            scan_go_authority(root, first)
            second = first.parent / "second"
            scan_go_authority(root, second)
            self.assertEqual(verify_go_evidence(first), verify_go_evidence(second))
            for name in (REPORT_NAME, MARKDOWN_NAME, SARIF_NAME, MANIFEST_NAME):
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())

    def test_tampered_report_and_sarif_fail_verification(self) -> None:
        for filename in (REPORT_NAME, MARKDOWN_NAME, SARIF_NAME, MANIFEST_NAME):
            with self.subTest(filename=filename):
                temp, root, evidence = self.fixture()
                with temp:
                    scan_go_authority(root, evidence)
                    (evidence / filename).write_text("modified", encoding="utf-8")
                    with self.assertRaises(ValueError):
                        verify_go_evidence(evidence)

    def test_unknown_input_is_inconclusive_not_clean(self) -> None:
        cases = {
            "fixture.go": "package x\n/* dangling",
            "missing.go": ALLOW,
            "../escape.go": ALLOW,
            "fixture.ts": ALLOW,
        }
        for selection, source in cases.items():
            with self.subTest(selection=selection):
                temp, root, evidence = self.fixture(content=source)
                with temp:
                    outcome = scan_go_authority(root, evidence, files=[selection])
                    self.assertEqual(outcome.exit_code, 2)
                    self.assertEqual(outcome.report["qualification"]["status"], "INCONCLUSIVE")
                    self.assertEqual(verify_go_evidence(evidence), outcome.report)

    def test_symlink_path_rejection_and_output_containment(self) -> None:
        temp, root, evidence = self.fixture()
        with temp:
            (root / "link.go").symlink_to(root / "fixture.go")
            self.assertEqual(scan_go_authority(root, evidence, files=["link.go"]).exit_code, 2)
            with self.assertRaises(ValueError):
                scan_go_authority(root, root / "inside")
            self.assertFalse((root / "inside").exists())

    def test_discovery_limit_fails_closed(self) -> None:
        temp, root, evidence = self.fixture()
        with temp:
            for i in range(65):
                (root / f"file_{i:02d}.go").write_text("package f\n", encoding="utf-8")
            outcome = scan_go_authority(root, evidence)
            self.assertEqual(outcome.exit_code, 2)
            self.assertEqual(outcome.report["qualification"]["status"], "INCONCLUSIVE")

    def test_source_is_never_executed_or_networked(self) -> None:
        temp, root, evidence = self.fixture(content=ENV_PROCESS)
        with (temp,
              patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess")),
              patch.object(subprocess, "run", side_effect=AssertionError("subprocess")),
              patch.object(socket, "socket", side_effect=AssertionError("network"))):
            outcome = scan_go_authority(root, evidence)
            self.assertEqual(outcome.exit_code, 1)
            self.assertFalse(outcome.report["target_code_executed"])
            self.assertFalse(outcome.report["external_systems_contacted"])

    def test_cli_and_verifier_return_contract(self) -> None:
        temp, root, evidence = self.fixture()
        with temp, redirect_stdout(io.StringIO()):
            self.assertEqual(main(["scan-go-authority", "--root", str(root),
                                   "--output-dir", str(evidence)]), 1)
            self.assertEqual(main(["verify-go-authority", "--evidence-dir", str(evidence)]), 0)

    def test_no_signal_is_not_safety_certificate(self) -> None:
        temp, root, evidence = self.fixture(content="package x\nfunc ok() {}\n")
        with temp:
            outcome = scan_go_authority(root, evidence)
            self.assertEqual(outcome.exit_code, 0)
            self.assertEqual(outcome.report["qualification"]["confirmed_vulnerabilities"], 0)
            self.assertTrue(outcome.report["qualification"]["limited_not_exhaustive"])
            self.assertEqual(verify_go_evidence(evidence), outcome.report)


if __name__ == "__main__":
    unittest.main()

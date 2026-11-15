"""Read-only GitHub Action adapter: positive, negative and fail-closed cases."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap.action_entry import ACTION_SUMMARY_NAME, run_action
from wolftrap.build_scan import MANIFEST_NAME

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "tests/fixtures/stage4_demo"


def _safe_target(root: Path) -> Path:
    workflow = root / ".github/workflows/safe.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text(
        "name: Safe CI\non: push\npermissions:\n  contents: read\n"
        "jobs:\n  validate:\n    steps:\n      - run: echo harmless\n",
        encoding="utf-8",
    )
    return root


class ActionEntryTests(unittest.TestCase):
    def test_safe_checkout_gets_a_bounded_no_pattern_match(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-action-safe-") as tmp:
            root = _safe_target(Path(tmp) / "source")
            output = Path(tmp) / "report"
            github_out = Path(tmp) / "github_output"
            with (
                patch.object(subprocess, "Popen", side_effect=AssertionError("no commands")),
                patch.object(socket, "socket", side_effect=AssertionError("no network")),
            ):
                result = run_action(root=root, output_dir=output, fail_on_findings="true", github_output=github_out)
            self.assertEqual((result.status, result.scanner_exit_code, result.exit_code),
                             ("NO_PATTERN_MATCH", 0, 0))
            self.assertEqual(result.findings, 0)
            self.assertEqual(result.unknown_inputs, 0)
            self.assertIn("status=NO_PATTERN_MATCH\n", github_out.read_text())
            self.assertIn("findings=0\n", github_out.read_text())
            self.assertEqual(json.loads((output / MANIFEST_NAME).read_text())["state"], "COMPLETE")

    def test_real_composite_contract_advisory_and_strict_modes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-action-review-") as tmp:
            for mode, expected_exit in (("false", 0), ("true", 1)):
                with self.subTest(mode=mode):
                    output = Path(tmp) / ("out-" + mode)
                    result = run_action(root=DEMO, output_dir=output, fail_on_findings=mode)
                    self.assertEqual(result.status, "REVIEW_REQUIRED")
                    self.assertEqual(result.scanner_exit_code, 1)
                    self.assertEqual(result.exit_code, expected_exit)
                    self.assertEqual(result.findings, 2)
                    saved = json.loads((output / ACTION_SUMMARY_NAME).read_text())
                    self.assertEqual(saved["status"], "REVIEW_REQUIRED")
                    self.assertFalse(saved["target_code_executed"])
                    self.assertFalse(saved["external_targets_contacted"])
                    self.assertEqual(json.loads((output / MANIFEST_NAME).read_text())["state"], "COMPLETE")

    def test_unknown_root_and_invalid_options_always_block(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-action-unknown-") as tmp:
            for option, root in (("false", Path(tmp) / "missing"), ("forgiving", DEMO)):
                with self.subTest(option=option):
                    output = Path(tmp) / ("unknown-" + option)
                    result = run_action(root=root, output_dir=output, fail_on_findings=option)
                    self.assertEqual((result.status, result.scanner_exit_code, result.exit_code),
                                     ("INCONCLUSIVE", 2, 2))
                    self.assertEqual(result.unknown_inputs, 1)
                    summary = json.loads((output / ACTION_SUMMARY_NAME).read_text())
                    self.assertEqual(summary["confirmed_vulnerabilities"], 0)
                    self.assertNotIn(str(root), (output / ACTION_SUMMARY_NAME).read_text())

    def test_existing_output_is_not_overwritten(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-action-preserve-") as tmp:
            output = Path(tmp) / "occupied"
            output.mkdir()
            (output / "important.txt").write_text("user data")
            with self.assertRaisesRegex(ValueError, "fresh, empty"):
                run_action(root=DEMO, output_dir=output, fail_on_findings="false")
            self.assertEqual((output / "important.txt").read_text(), "user data")

    def test_action_metadata_is_pinned_and_cannot_claim_live_pentest(self) -> None:
        content = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("using: 'composite'", content)
        self.assertIn("PyYAML==6.0.3", content)
        self.assertIn('"${GITHUB_ACTION_PATH}/src"', content)
        self.assertIn("python -I -c", content)
        self.assertIn("python -I -m pip", content)
        self.assertNotIn("PYTHONPATH=", content)
        self.assertIn("if: ${{ always()", content)
        self.assertNotIn("secrets.", content)
        self.assertNotIn("pull_request_target", content)
        self.assertNotIn("github.event.pull_request", content)
        import re
        uses = re.findall(r"(?m)^\s+uses: ([^\s#]+)", content)
        self.assertEqual(len(uses), 2)
        self.assertTrue(all(re.fullmatch(r"[^@]+@[a-f0-9]{40}", ref) for ref in uses))
        self.assertTrue((ROOT / "tests/fixtures/stage4_demo/.github/workflows/pr.yml").is_file())

    def test_isolated_python_bootstrap_cannot_import_target_shadow_module(self) -> None:
        # A PR can add its own wolftrap package; a naïve `python -m wolftrap`
        # would run the attacker-controlled module before any scan starts.
        with tempfile.TemporaryDirectory(prefix="wolftrap-shadow-") as tmp:
            root = _safe_target(Path(tmp) / "untrusted-project")
            malicious = root / "wolftrap"
            malicious.mkdir()
            marker = Path(tmp) / "shadow-executed"
            (malicious / "__init__.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('WRONG')\n",
                encoding="utf-8",
            )
            output = Path(tmp) / "evidence"
            proc = subprocess.run(
                [sys.executable, "-I", "-c",
                 "import sys; sys.path.insert(0, sys.argv.pop(1)); "
                 "from wolftrap.action_entry import main; raise SystemExit(main())",
                 str(ROOT / "src"), "--root", str(root), "--output-dir", str(output),
                 "--fail-on-findings", "true"],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertFalse(marker.exists(), "target Python shadow code executed")
            self.assertEqual(json.loads((output / ACTION_SUMMARY_NAME).read_text())["status"], "NO_PATTERN_MATCH")


if __name__ == "__main__":
    unittest.main()

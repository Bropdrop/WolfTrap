"""Fixture-backed, offline end-to-end checks of WolfTrap's public-main CLI.

Runs only the trusted, pinned candidate's scanner. Inspected fixture code is
never executed; every generated output stays outside the target source tree.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[3]
FIXTURES = REPO / "tests" / "fixtures"


def run_cli(*args: object) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONHASHSEED"] = "0"
    env["PYTHONNOUSERSITE"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "wolftrap", *(str(arg) for arg in args)],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def artifact_report(directory: Path, report_name: str, expected: str) -> dict:
    manifest = json.loads(
        (directory / report_name.replace(".json", ".manifest.json")).read_text(encoding="utf-8")
    )
    report = json.loads((directory / report_name).read_text(encoding="utf-8"))
    assert manifest["state"] == "COMPLETE", manifest
    assert manifest["qualification_status"] == expected, manifest
    assert report["qualification"]["status"] == expected, report
    assert set(manifest["files"]) == {
        report_name,
        report_name.replace(".json", ".md"),
        report_name.replace(".json", ".sarif"),
    }, manifest
    for name, metadata in manifest["files"].items():
        assert name == Path(name).name
        payload = (directory / name).read_bytes()
        assert metadata == {
            "bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }, name
    assert report["qualification"].get("confirmed_vulnerabilities", 0) == 0
    return report


def snapshot(target: Path) -> dict[str, str]:
    return {
        path.relative_to(target).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in target.rglob("*") if path.is_file() and not path.is_symlink()
    }


class PluginOfflineIntegration(unittest.TestCase):
    def assert_exit(self, result: subprocess.CompletedProcess[str], expected: int) -> None:
        self.assertEqual(
            result.returncode, expected,
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )

    def test_geotrace_candidate_scan_and_replay(self) -> None:
        examples = REPO / "qualification/geotrace/r01/examples"
        policy = examples / "policy/policy.json"
        pin = hashlib.sha256(policy.read_bytes()).hexdigest()
        args = ("--root", examples / "capture", "--file", "capture.json", "--policy", policy,
                "--policy-sha256", pin, "--as-of", "2026-11-22")
        before = snapshot(examples)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "evidence"
            self.assert_exit(run_cli("scan-geotrace", *args, "--output-dir", out), 0)
            self.assert_exit(run_cli("verify-geotrace", *args, "--evidence-dir", out), 0)
            report = json.loads((out / "geotrace.json").read_bytes())
            self.assertEqual(report["action_authorization"], "NOT_EVALUATED")
            self.assertEqual(report["events"][0]["geography"]["execution_region"]["countries"], ["DE"])
            (out / "geotrace.md").write_text("Unverified replacement")
            self.assert_exit(run_cli("verify-geotrace", *args, "--evidence-dir", out), 2)
        self.assertEqual(before, snapshot(examples))

    def test_existing_safe_build_fixture(self) -> None:
        target = FIXTURES / "action_safe"
        before = snapshot(target)
        with tempfile.TemporaryDirectory(prefix="wt-plugin-safe-") as tmp:
            out = Path(tmp) / "scan"
            self.assert_exit(run_cli("scan-build", "--root", target, "--output-dir", out), 0)
            report = artifact_report(out, "build-scan.json", "NO_PATTERN_MATCH")
            self.assertFalse(report["target_code_executed"])
            self.assertFalse(report["external_systems_contacted"])
            self.assertGreater(report["summary"]["files_inspected"], 0)
            self.assertEqual(report["summary"]["findings"], 0)
        self.assertEqual(snapshot(target), before)

    def test_existing_adversarial_artifact_fixture(self) -> None:
        target = FIXTURES / "stage4_demo"
        before = snapshot(target)
        with tempfile.TemporaryDirectory(prefix="wt-plugin-adverse-") as tmp:
            out = Path(tmp) / "scan"
            self.assert_exit(run_cli("scan-build", "--root", target, "--output-dir", out), 1)
            report = artifact_report(out, "build-scan.json", "REVIEW_REQUIRED")
            self.assertEqual(
                {item["rule_id"] for item in report["findings"]},
                {"WT-GHA-005", "WT-GHA-006"},
            )
            self.assertEqual(report["summary"]["findings"], 2)
            self.assertFalse(report["target_code_executed"])
        self.assertEqual(snapshot(target), before)

    def test_unknown_build_input_is_inconclusive_not_clean(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wt-plugin-unknown-") as tmp:
            source, out = Path(tmp) / "target", Path(tmp) / "evidence"
            source.mkdir()
            (source / "notes.txt").write_text("Nothing supported to inspect.\n", encoding="utf-8")
            self.assert_exit(run_cli("scan-build", "--root", source, "--output-dir", out), 2)
            report = artifact_report(out, "build-scan.json", "INCONCLUSIVE")
            self.assertTrue(report["errors"])
            self.assertEqual(report["summary"]["files_inspected"], 0)

    def test_all_four_source_modes_and_matching_verifiers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wt-plugin-modes-") as tmp:
            source = Path(tmp) / "target"
            source.mkdir()
            (source / "clean.js").write_text(
                "export function meaning() { return 42; }\n", encoding="utf-8"
            )
            (source / "notes.md").write_text(
                "Repository release procedures are reviewed manually.\n", encoding="utf-8"
            )
            (source / "main.go").write_text(
                "package main\nfunc meaning() int { return 42 }\n", encoding="utf-8"
            )
            before = snapshot(source)
            modes = (
                ("scan-agent", "agent-scan.json", None),
                ("scan-effects", "effect-scan.json", "verify-effects"),
                ("scan-prompts", "prompt-scan.json", "verify-prompts"),
                ("scan-go-authority", "go-authority-scan.json", "verify-go-authority"),
            )
            for command, report_name, verifier in modes:
                with self.subTest(command=command):
                    out = Path(tmp) / command
                    self.assert_exit(
                        run_cli(command, "--root", source, "--output-dir", out), 0
                    )
                    report = artifact_report(out, report_name, "NO_PATTERN_MATCH")
                    self.assertEqual(report["summary"]["findings"], 0)
                    self.assertGreater(report["summary"]["files_inspected"], 0)
                    if verifier:
                        self.assert_exit(run_cli(verifier, "--evidence-dir", out), 0)
            self.assertEqual(snapshot(source), before)

    def test_existing_prompt_injection_fixture_is_advisory(self) -> None:
        target = FIXTURES / "prompt_docs"
        before = snapshot(target)
        with tempfile.TemporaryDirectory(prefix="wt-plugin-prompt-") as tmp:
            out = Path(tmp) / "scan"
            self.assert_exit(run_cli("scan-prompts", "--root", target, "--output-dir", out), 1)
            report = artifact_report(out, "prompt-scan.json", "REVIEW_REQUIRED")
            self.assertGreater(report["summary"]["findings"], 0)
            self.assert_exit(run_cli("verify-prompts", "--evidence-dir", out), 0)
        self.assertEqual(snapshot(target), before)

    def test_tampered_effect_evidence_fails_verification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wt-plugin-tamper-") as tmp:
            source, out = Path(tmp) / "target", Path(tmp) / "evidence"
            source.mkdir()
            (source / "safe.js").write_text("export const ok = 1;\n", encoding="utf-8")
            self.assert_exit(run_cli("scan-effects", "--root", source, "--output-dir", out), 0)
            artifact_report(out, "effect-scan.json", "NO_PATTERN_MATCH")
            self.assert_exit(run_cli("verify-effects", "--evidence-dir", out), 0)
            with (out / "effect-scan.md").open("a", encoding="utf-8") as handle:
                handle.write("TAMPERED\n")
            self.assertNotEqual(run_cli("verify-effects", "--evidence-dir", out).returncode, 0)

    def test_unsafe_selection_and_output_are_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wt-plugin-paths-") as tmp:
            source = Path(tmp) / "target"
            source.mkdir()
            (source / "notes.md").write_text("Normal text.\n", encoding="utf-8")
            outside = Path(tmp) / "outside.md"
            outside.write_text("Private file: NO_READ_MARKER\n", encoding="utf-8")
            traversal = Path(tmp) / "traversal"
            self.assert_exit(
                run_cli(
                    "scan-prompts", "--root", source, "--file", "../outside.md",
                    "--output-dir", traversal,
                ),
                2,
            )
            report = artifact_report(traversal, "prompt-scan.json", "INCONCLUSIVE")
            self.assertFalse(report["findings"])
            self.assertNotIn("NO_READ_MARKER", (traversal / "prompt-scan.json").read_text())

            (source / "link.md").symlink_to(outside)
            linked = Path(tmp) / "symlink"
            self.assert_exit(
                run_cli(
                    "scan-prompts", "--root", source, "--file", "link.md",
                    "--output-dir", linked,
                ),
                2,
            )
            artifact_report(linked, "prompt-scan.json", "INCONCLUSIVE")
            self.assertNotIn("NO_READ_MARKER", (linked / "prompt-scan.json").read_text())
            in_tree = source / "evidence"
            self.assert_exit(
                run_cli("scan-build", "--root", source, "--output-dir", in_tree), 2
            )
            self.assertFalse(in_tree.exists())


if __name__ == "__main__":
    unittest.main()

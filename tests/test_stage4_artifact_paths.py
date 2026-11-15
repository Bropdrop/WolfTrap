"""Finite differential corpus for cross-workflow artifact-boundary triage."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap.build_scan import MANIFEST_NAME, REPORT_NAME, SARIF_NAME, scan_build


ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests/fixtures/stage4_artifact_path_corpus.json"
PIN = "11bd71901bbe5b1630ceea73d27597364c9af683"
RUN_ID = "$" + "{{ github.event.workflow_run.id }}"
CURRENT_RUN = "$" + "{{ github.run_id }}"
GITHUB_TOKEN = "$" + "{{ github.token }}"


def _producer(changes: dict[str, object]) -> str:
    event = changes.get("producer_event", "pull_request")
    if event == "push_and_pr":
        trigger = "on: [push, pull_request]"
    else:
        trigger = f"on: {event}"
    name = "PR Build"
    parts = [f"name: {name}", trigger, "permissions:", "  contents: read", "jobs:", "  pack:", "    steps:"]
    if changes.get("upload", True):
        parts.extend([f"      - uses: actions/upload-artifact@{PIN}"])
        name = changes.get("upload_name", "handoff")
        path = changes.get("upload_path", "build-output")
        if name or path:
            parts.append("        with:")
            if name:
                parts.append(f"          name: '{name}'")
            if path:
                parts.append(f"          path: {path}")
    else:
        parts.append("      - run: echo no-artifact")
    if changes.get("producer_extra_job"):
        parts.extend(["  lint:", "    steps:", "      - run: echo safe"])
    return "\n".join(parts) + "\n"


def _consumer(changes: dict[str, object]) -> str:
    upstream = changes.get("consumer_producer_name", "PR Build")
    permission = changes.get("permission", "write")
    parts = [
        "name: Privileged Report", "on:", "  workflow_run:",
        f"    workflows: [{upstream}]", "    types: [completed]",
    ]
    if permission == "write-all":
        parts.append("permissions: write-all")
    elif permission != "unknown":
        parts.extend(["permissions:", f"  contents: {permission}"])
    parts.extend(["jobs:", "  review:"])
    if changes.get("job_guard"):
        parts.append(f"    if: {changes['job_guard']}")
    parts.append("    steps:")
    run = str(changes.get("run", "bash drop/install.sh"))
    if run and changes.get("run_before_download"):
        parts.append(f"      - run: {run}")
    if changes.get("download", True):
        parts.append(f"      - uses: {changes.get('download_action', f'actions/download-artifact@{PIN}')}")
        if changes.get("step_guard"):
            parts.append(f"        if: {changes['step_guard']}")
        parts.append("        with:")
        run_id = changes.get("run_id", "event")
        if run_id:
            resolved_id = RUN_ID if run_id == "event" else CURRENT_RUN if run_id == "current" else run_id
            parts.append(f"          run-id: {resolved_id}")
        if changes.get("download_token", True):
            parts.append(f"          github-token: {GITHUB_TOKEN}")
        name = changes.get("download_name", "handoff")
        if name:
            parts.append(f"          name: '{name}'")
        path = changes.get("download_path", "drop")
        if path:
            parts.append(f"          path: {path}")
        if changes.get("download_repository"):
            parts.append(f"          repository: {changes['download_repository']}")
    if run and not changes.get("run_before_download"):
        parts.append(f"      - run: {run}")
    if not changes.get("download", True) and not run:
        parts.append("      - run: echo nothing")
    return "\n".join(parts) + "\n"


class ArtifactPathCorpusTests(unittest.TestCase):
    def test_existing_stage3_hosted_finding_ids_remain_stable(self) -> None:
        # Historical exact-head Stage 3 CI output: synthetic legacy fixture.
        old_ids = {
            "WT-DOCKER-001": "WT-BUILD-FC381358B637207118EA",
            "WT-DOCKER-002": "WT-BUILD-895210F70FE3CDE84E5A",
            "WT-GHA-001": "WT-BUILD-3C61A7B7A4F444389F29",
            "WT-GHA-002": "WT-BUILD-6879E3FE228222320508",
            "WT-GHA-003": "WT-BUILD-6DD9A7AEAA86F73282E8",
            "WT-GHA-005": "WT-BUILD-9DB0B4CD8F9E172EB5AB",
        }
        with tempfile.TemporaryDirectory(prefix="wolftrap-legacy-identities-") as temp:
            result = scan_build(ROOT / "tests/fixtures/build_scan/adversarial", Path(temp) / "out")
            self.assertEqual(result.exit_code, 1)
            self.assertEqual({item["rule_id"]: item["id"] for item in result.report["findings"]}, old_ids)

    def test_scan_never_executes_target_or_copies_source_code(self) -> None:
        with tempfile.TemporaryDirectory(prefix="wolftrap-fail-closed-") as temp:
            root = Path(temp) / "target"
            workflows = root / ".github/workflows"
            workflows.mkdir(parents=True)
            raw = _producer({"upload_name": "FAKE-SECRET-DO-NOT-COPY-123"})
            (workflows / "pr.yml").write_text(raw, encoding="utf-8")
            (workflows / "privileged.yml").write_text(
                _consumer({"download_name": "FAKE-SECRET-DO-NOT-COPY-123"}), encoding="utf-8"
            )
            out = Path(temp) / "evidence"
            with (
                patch("subprocess.Popen", side_effect=AssertionError("target execution prohibited")),
                patch("socket.socket", side_effect=AssertionError("network access prohibited")),
            ):
                result = scan_build(root, out)
            self.assertEqual(result.exit_code, 1)
            self.assertFalse(result.report["external_systems_contacted"])
            self.assertFalse(result.report["target_code_executed"])
            for filename in ("build-scan.json", "build-scan.md", "build-scan.sarif"):
                self.assertNotIn("FAKE-SECRET-DO-NOT-COPY-123", (out / filename).read_text())

            second = Path(temp) / "evidence-replay"
            replay = scan_build(root, second)
            self.assertEqual(replay.report, result.report)
            for filename in ("build-scan.json", "build-scan.md", "build-scan.sarif", MANIFEST_NAME):
                self.assertEqual((out / filename).read_bytes(), (second / filename).read_bytes())

    def test_corpus_has_unique_cases_and_balanced_controls(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        self.assertEqual(corpus["schema"], "wolftrap.stage4.artifact-path-corpus/v1")
        cases = corpus["cases"]
        self.assertGreaterEqual(len(cases), 32)
        self.assertEqual(len({case["id"] for case in cases}), len(cases))
        self.assertGreaterEqual(sum(case["expected"] == "HIGH" for case in cases), 10)
        self.assertGreaterEqual(sum(case["expected"] == "NONE" for case in cases), 10)
        self.assertGreaterEqual(sum(case["expected"] == "INCONCLUSIVE" for case in cases), 3)

    def test_all_saved_mutations_and_deterministic_evidence(self) -> None:
        corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
        for case in corpus["cases"]:
            with self.subTest(case=case["id"]):
                changes = case.get("changes", {})
                with tempfile.TemporaryDirectory(prefix="wolftrap-stage4-") as tmp:
                    root = Path(tmp) / "target"
                    workflow_dir = root / ".github" / "workflows"
                    workflow_dir.mkdir(parents=True)
                    producer = workflow_dir / "pr.yml"
                    producer.write_text(_producer(changes), encoding="utf-8")
                    consumer = workflow_dir / "privileged.yml"
                    consumer.write_text(_consumer(changes), encoding="utf-8")
                    if changes.get("duplicate_producer"):
                        (workflow_dir / "duplicate.yml").write_bytes(producer.read_bytes())
                    snapshot = {file.name: file.read_bytes() for file in workflow_dir.iterdir()}
                    evidence = Path(tmp) / "evidence"
                    result = scan_build(root, evidence)
                    self.assertEqual(snapshot, {file.name: file.read_bytes() for file in workflow_dir.iterdir()})
                    signals = [item for item in result.report["findings"] if item["rule_id"] == "WT-GHA-006"]
                    expected = case["expected"]
                    if expected == "INCONCLUSIVE":
                        self.assertEqual(result.exit_code, 2)
                        self.assertFalse(result.report["qualification"]["complete_input"])
                        self.assertFalse(signals)
                    elif expected == "NONE":
                        self.assertFalse(signals)
                    else:
                        self.assertEqual(len(signals), 1)
                        self.assertEqual(signals[0]["severity"], expected)
                        self.assertEqual(signals[0]["classification"], "REVIEW_REQUIRED")
                        self.assertEqual(signals[0]["trace"]["producer_workflow"], ".github/workflows/pr.yml")
                        self.assertEqual(signals[0]["trace"]["consumer_workflow"], ".github/workflows/privileged.yml")
                        self.assertEqual(len(signals[0]["trace"]["artifact_name_sha256"]), 64)
                        self.assertEqual(
                            signals[0]["trace"]["direct_script_execution_detected"], expected == "HIGH",
                        )
                        self.assertEqual(len(signals[0]["counterfactuals"]), len(signals[0]["factors"]))
                        self.assertNotIn("CONFIRMED_EXPLOIT", json.dumps(signals[0]))
                    manifest = json.loads((evidence / MANIFEST_NAME).read_text(encoding="utf-8"))
                    self.assertEqual(manifest["state"], "COMPLETE")
                    for name, metadata in manifest["files"].items():
                        raw = (evidence / name).read_bytes()
                        self.assertEqual(hashlib.sha256(raw).hexdigest(), metadata["sha256"])
                        self.assertEqual(len(raw), metadata["bytes"])
                    sarif = json.loads((evidence / SARIF_NAME).read_text(encoding="utf-8"))
                    self.assertEqual(len([x for x in sarif["runs"][0]["results"] if x["ruleId"] == "WT-GHA-006"]), len(signals))
                    self.assertEqual(result.report, json.loads((evidence / REPORT_NAME).read_text(encoding="utf-8")))
                    self.assertFalse(result.report["target_code_executed"])
                    self.assertFalse(result.report["external_systems_contacted"])


if __name__ == "__main__":
    unittest.main()

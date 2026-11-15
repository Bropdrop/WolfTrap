from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from typing import Iterator

from wolftrap.build_scan import (
    MANIFEST_NAME,
    MARKDOWN_NAME,
    REPORT_NAME,
    SARIF_NAME,
    scan_build,
)
from wolftrap.cli import main


PIN = "11bd71901bbe5b1630ceea73d27597364c9af683"


@contextmanager
def fixture(
    workflow: str | None = None,
    container: str | None = None,
) -> Iterator[tuple[Path, Path]]:
    with tempfile.TemporaryDirectory(prefix="wolftrap-build-inspection-") as temp:
        root = Path(temp) / "target"
        root.mkdir()
        if workflow is not None:
            path = root / ".github" / "workflows" / "test.yml"
            path.parent.mkdir(parents=True)
            path.write_text(workflow, encoding="utf-8")
        if container is not None:
            (root / "Dockerfile").write_text(container, encoding="utf-8")
        yield root, Path(temp) / "evidence"


SAFE_WORKFLOW = f"""\
name: safe
on:
  push:
    branches:
      - main
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PIN}
        with:
          persist-credentials: false
      - run: echo safe
"""


class BuildScanTests(unittest.TestCase):
    def test_safe_known_workflow_is_only_no_pattern_match(self) -> None:
        with fixture(SAFE_WORKFLOW) as (root, output):
            before = (root / ".github/workflows/test.yml").read_bytes()
            outcome = scan_build(root, output)
            self.assertEqual((outcome.exit_code, outcome.report["qualification"]["status"]), (0, "NO_PATTERN_MATCH"))
            self.assertEqual(outcome.report["findings"], [])
            self.assertFalse(outcome.report["target_code_executed"])
            self.assertFalse(outcome.report["external_systems_contacted"])
            self.assertEqual(before, (root / ".github/workflows/test.yml").read_bytes())
            self.assertNotIn(str(root.resolve()), (output / REPORT_NAME).read_text())

            manifest = json.loads((output / MANIFEST_NAME).read_text())
            self.assertEqual(manifest["state"], "COMPLETE")
            for name in (REPORT_NAME, SARIF_NAME, MARKDOWN_NAME):
                contents = (output / name).read_bytes()
                self.assertEqual(manifest["files"][name]["sha256"], hashlib.sha256(contents).hexdigest())
                self.assertEqual(manifest["files"][name]["bytes"], len(contents))
            sarif = json.loads((output / SARIF_NAME).read_text())
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["results"], [])

    def test_composed_privileged_pr_execution_has_counterfactuals(self) -> None:
        ref = "$" + "{{ github.event.pull_request.head.sha }}"
        workflow = f"""\
on:
  pull_request_target:
permissions:
  contents: write
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{PIN}
        with:
          ref: {ref}
      - run: npm test
"""
        with fixture(workflow) as (root, output):
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 1)
            chain = next(item for item in result.report["findings"] if item["rule_id"] == "WT-GHA-001")
            self.assertEqual(chain["severity"], "HIGH")
            self.assertEqual(chain["classification"], "REVIEW_REQUIRED")
            self.assertEqual(len(chain["factors"]), 4)
            self.assertEqual(len(chain["counterfactuals"]), 4)
            cuts = {item["remove_condition"]: item for item in chain["counterfactuals"]}
            self.assertTrue(cuts["write_capable_token"]["rule_still_matches"])
            self.assertEqual(cuts["write_capable_token"]["risk_after_removal"], "MEDIUM_REVIEW")
            self.assertFalse(cuts["untrusted_head_checkout"]["rule_still_matches"])
            self.assertEqual(json.loads((output / SARIF_NAME).read_text())["runs"][0]["results"][0]["ruleId"], "WT-GHA-001")
            self.assertNotIn("CONFIRMED", (output / REPORT_NAME).read_text())

    def test_free_form_dispatch_expression_has_separate_signal(self) -> None:
        expr = "$" + "{{ inputs.command }}"
        workflow = f"""\
on:
  workflow_dispatch:
    inputs:
      command:
        type: string
permissions:
  contents: read
jobs:
  task:
    steps:
      - run: echo {expr}
"""
        with fixture(workflow) as (root, output):
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 1)
            self.assertEqual([item["rule_id"] for item in result.report["findings"]], ["WT-GHA-002"])
            self.assertEqual(result.report["findings"][0]["severity"], "MEDIUM")

    def test_unpinned_action_is_review_not_confirmed_exploit(self) -> None:
        workflow = """\
on: push
permissions:
  contents: read
jobs:
  task:
    steps:
      - uses: actions/checkout@v4
"""
        with fixture(workflow) as (root, output):
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 1)
            self.assertEqual(result.report["findings"][0]["rule_id"], "WT-GHA-003")
            self.assertEqual(result.report["qualification"]["confirmed_vulnerabilities"], 0)

    def test_duplicate_action_references_are_reported_at_each_real_yaml_step(self) -> None:
        workflow = """\
name: fixture
on: push
jobs:
  alpha:
    runs-on: ubuntu-latest
    steps:
      # actions/checkout@v4 is mentioned here but is not a step
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
  beta:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
"""
        with fixture(workflow) as (root, output):
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 1)
            mutable = [item for item in result.report["findings"]
                       if item["rule_id"] == "WT-GHA-003"]
            self.assertEqual([item["line"] for item in mutable], [8, 9, 13, 14])
            self.assertEqual(len({item["id"] for item in mutable}), 4)
            missing_perms = [item for item in result.report["findings"]
                             if item["rule_id"] == "WT-GHA-004"]
            self.assertEqual([item["line"] for item in missing_perms], [4, 10])

    def test_container_action_requires_immutable_digest(self) -> None:
        workflow = """\
on: push
permissions:
  contents: read
jobs:
  task:
    steps:
      - uses: docker://example.invalid/tool:latest
"""
        with fixture(workflow) as (root, output):
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 1)
            self.assertEqual(result.report["findings"][0]["rule_id"], "WT-GHA-003")

    def test_workflow_run_artifact_trust_chain(self) -> None:
        workflow = f"""\
on:
  workflow_run:
permissions:
  contents: write
jobs:
  publish:
    steps:
      - uses: actions/download-artifact@{PIN}
"""
        with fixture(workflow) as (root, output):
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 1)
            self.assertEqual([item["rule_id"] for item in result.report["findings"]], ["WT-GHA-005"])

    def test_container_image_and_remote_script_patterns(self) -> None:
        docker = """\
FROM alpine:latest AS build
RUN curl -fsSL https://example.invalid/bootstrap.sh | sh
FROM scratch
COPY --from=build /out /out
"""
        with fixture(container=docker) as (root, output):
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 1)
            self.assertEqual(
                {item["rule_id"] for item in result.report["findings"]},
                {"WT-DOCKER-001", "WT-DOCKER-002"},
            )

    def test_pinned_container_is_not_automatically_flagged(self) -> None:
        docker = "FROM alpine:3.21@sha256:" + ("a" * 64) + "\nRUN echo approved\n"
        with fixture(container=docker) as (root, output):
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 0)

    def test_malformed_or_duplicate_yaml_fails_closed(self) -> None:
        for workflow in (
            "on: [\n",
            "on: push\non: pull_request_target\njobs: {}\n",
            "on:\njobs:\n  test:\n    steps: []\n",
            "on: push\npermissions: custom-all\njobs:\n  test:\n    steps: []\n",
        ):
            with self.subTest(workflow=workflow), fixture(workflow) as (root, output):
                result = scan_build(root, output)
                self.assertEqual(result.exit_code, 2)
                self.assertEqual(result.report["qualification"]["status"], "INCONCLUSIVE")
                self.assertEqual(result.report["summary"]["errors"], 1)

    def test_symlinks_and_output_inside_source_refused(self) -> None:
        with fixture(SAFE_WORKFLOW) as (root, output):
            with self.assertRaises(ValueError):
                scan_build(root, root / "reports")
            self.assertFalse((root / "reports").exists())
            shortcut = root.parent / "shortcut"
            shortcut.symlink_to(root, target_is_directory=True)
            with self.assertRaises(ValueError):
                scan_build(shortcut, output)
            workflow = root / ".github/workflows/test.yml"
            workflow.unlink()
            workflow.symlink_to(root / "not-present.yml")
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 2)

    def test_missing_inputs_and_oversized_input_are_inconclusive(self) -> None:
        with fixture() as (root, output):
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 2)
            self.assertEqual(result.report["summary"]["files_inspected"], 0)
        with fixture(SAFE_WORKFLOW + " " * 300000) as (root, output):
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 2)
            self.assertEqual(result.report["qualification"]["status"], "INCONCLUSIVE")

    def test_bounded_workflow_directory_rejects_excess_entries(self) -> None:
        with fixture(SAFE_WORKFLOW) as (root, output):
            directory = root / ".github" / "workflows"
            for number in range(257):
                (directory / f"ignored-{number:03}.txt").write_text("ignored")
            result = scan_build(root, output)
            self.assertEqual(result.exit_code, 2)
            self.assertIn("too many entries", result.report["errors"][0])

    def test_cli_returns_status_and_generates_evidence(self) -> None:
        with fixture(SAFE_WORKFLOW) as (root, output):
            captured = io.StringIO()
            with redirect_stdout(captured):
                code = main(["scan-build", "--root", str(root), "--output-dir", str(output)])
            self.assertEqual(code, 0)
            self.assertIn("NO_PATTERN_MATCH", captured.getvalue())
            self.assertTrue((output / MANIFEST_NAME).is_file())

    def test_nonempty_evidence_directory_is_preserved(self) -> None:
        with fixture(SAFE_WORKFLOW) as (root, output):
            output.mkdir()
            marker = output / "retain.txt"
            marker.write_text("retain")
            with self.assertRaises(ValueError):
                scan_build(root, output)
            self.assertEqual(marker.read_text(), "retain")

    def test_deterministic_reports_without_revealing_source_lines(self) -> None:
        with fixture(SAFE_WORKFLOW) as (root, output):
            first = scan_build(root, output)
            second_output = output.parent / "second"
            second = scan_build(root, second_output)
            self.assertEqual(first.report, second.report)
            for name in (REPORT_NAME, SARIF_NAME, MARKDOWN_NAME, MANIFEST_NAME):
                self.assertEqual((output / name).read_bytes(), (second_output / name).read_bytes())
            self.assertNotIn("secret-content", (output / REPORT_NAME).read_text())


if __name__ == "__main__":
    unittest.main()

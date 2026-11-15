"""Bounded synthetic positive/negative/unknown controls for WT-GHA-007."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from wolftrap.build_scan import scan_build


class SelfHostedPullRequestTests(unittest.TestCase):
    def test_runner_exposure_corpus(self) -> None:
        # Deliberately vary events, label types, known versus unresolved
        # selectors and the token permission boundary. No target code runs.
        cases = [
            ("pr_plain", "pull_request", "self-hosted", "contents: read", "REVIEW_REQUIRED"),
            ("pr_list", "pull_request", "[self-hosted, linux]", "contents: read", "REVIEW_REQUIRED"),
            ("pr_list_last", "pull_request", "[linux, x64, self-hosted]", "contents: read", "REVIEW_REQUIRED"),
            ("pr_mapping", "pull_request", "{labels: [self-hosted, linux]}", "contents: read", "REVIEW_REQUIRED"),
            ("pr_mapping_single", "pull_request", "{labels: self-hosted}", "contents: read", "REVIEW_REQUIRED"),
            ("target_list", "pull_request_target", "[self-hosted, linux]", "contents: read", "REVIEW_REQUIRED"),
            ("target_mapping", "pull_request_target", "{group: isolated, labels: [self-hosted]}", "contents: read", "REVIEW_REQUIRED"),
            ("pr_write", "pull_request", "self-hosted", "contents: write", "REVIEW_REQUIRED"),
            ("pr_dynamic_other_label", "pull_request", '[self-hosted, "${{ matrix.arch }}"]', "contents: read", "REVIEW_REQUIRED"),
            ("push_self_hosted", "push", "self-hosted", "contents: read", "NO_PATTERN_MATCH"),
            ("dispatch_self_hosted", "workflow_dispatch", "[self-hosted, linux]", "contents: read", "NO_PATTERN_MATCH"),
            ("release_self_hosted", "release", "self-hosted", "contents: read", "NO_PATTERN_MATCH"),
            ("pr_ubuntu", "pull_request", "ubuntu-24.04", "contents: read", "NO_PATTERN_MATCH"),
            ("pr_list_hosted", "pull_request", "[ubuntu-latest, linux]", "contents: read", "NO_PATTERN_MATCH"),
            ("target_ubuntu", "pull_request_target", "ubuntu-latest", "contents: read", "NO_PATTERN_MATCH"),
            ("pr_custom_unknown", "pull_request", "my-runner", "contents: read", "NO_PATTERN_MATCH"),
            ("pr_group_unknown", "pull_request", "{group: shared}", "contents: read", "NO_PATTERN_MATCH"),
            ("pr_dynamic", "pull_request", '"${{ matrix.os }}"', "contents: read", "INCONCLUSIVE"),
            ("pr_dynamic_list", "pull_request", '[linux, "${{ inputs.runner }}"]', "contents: read", "INCONCLUSIVE"),
            ("pr_dynamic_mapping", "pull_request", '{labels: "${{ matrix.runner }}"}', "contents: read", "INCONCLUSIVE"),
            ("target_unsupported", "pull_request_target", '{labels: {unresolved: label}}', "contents: read", "INCONCLUSIVE"),
        ]
        with tempfile.TemporaryDirectory(prefix="wolftrap-runners-") as tmp:
            temp = Path(tmp)
            for index, (name, trigger, runner, permission, expected) in enumerate(cases):
                with self.subTest(name=name):
                    root = temp / f"source-{index}"
                    workflow = root / ".github/workflows/ci.yml"
                    workflow.parent.mkdir(parents=True)
                    workflow.write_text(
                        f"name: test-{name}\non:\n  {trigger}:\n"
                        f"permissions:\n  {permission}\njobs:\n  ci:\n    runs-on: {runner}\n"
                        "    steps:\n      - run: echo safe\n",
                        encoding="utf-8",
                    )
                    before = workflow.read_bytes()
                    outcome = scan_build(root, temp / f"evidence-{index}")
                    self.assertEqual(outcome.report["qualification"]["status"], expected)
                    signals = [finding for finding in outcome.report["findings"] if finding["rule_id"] == "WT-GHA-007"]
                    if expected == "REVIEW_REQUIRED":
                        self.assertEqual(len(signals), 1)
                        self.assertEqual(signals[0]["severity"], "HIGH")
                        self.assertEqual(len(signals[0]["factors"]), 2)
                        self.assertEqual(len(signals[0]["counterfactuals"]), 2)
                    else:
                        self.assertEqual(signals, [])
                    if expected == "INCONCLUSIVE":
                        self.assertEqual(outcome.exit_code, 2)
                        self.assertGreater(outcome.report["summary"]["errors"], 0)
                    self.assertEqual(workflow.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()

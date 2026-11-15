"""Ensure Stage 4 hosted qualification cannot become an external scan job."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "artifact-path-qualification.yml"
DEMO = ROOT / "tests" / "fixtures" / "stage4_demo"


class Stage4WorkflowPolicyTests(unittest.TestCase):
    def test_exact_feature_branch_and_manual_only(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^on:\s*$\n  push:\s*$\n    branches:\s*$"
                               r"\n      - feat/wolftrap-stage4-artifact-bridge-v0_4\s*$"
                               r"\n  workflow_dispatch:\s*$")
        for trigger in ("schedule", "pull_request", "pull_request_target", "workflow_run"):
            self.assertNotRegex(text, rf"(?m)^  {trigger}:\s*$")
        self.assertIn("retention-days: 14", text)

    def test_jobs_have_no_protected_permissions(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^permissions:\s*$\n  contents: read\s*$")
        self.assertNotRegex(text, r"(?m)^\s+(?:contents|actions|id-token|packages): write\s*$")
        self.assertIn("persist-credentials: false", text)
        self.assertIn("timeout-minutes: 15", text)
        self.assertNotIn("secrets.", text)
        self.assertNotIn("docker run", text)
        self.assertNotIn("deploy", text.lower())

    def test_pinned_actions_and_finite_local_targets_only(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        uses = re.findall(r"(?m)^\s+uses:\s*([^\s#]+)", text)
        self.assertEqual(len(uses), 3)
        for ref in uses:
            self.assertRegex(ref, r"^[^@]+@[a-f0-9]{40}$")
        self.assertIn("PyYAML==6.0.3", text)
        self.assertIn("--root .", text)
        self.assertIn("--root tests/fixtures/stage4_demo", text)
        self.assertIn("--root tests/fixtures/build_scan/adversarial", text)
        self.assertIn("'WT-GHA-006'".replace("'", '"'), text)
        self.assertIn('assert len(cases) == 39', text)
        self.assertIn('metadata["sha256"]', text)
        self.assertIn('report["target_code_executed"] is False', text)
        self.assertTrue((DEMO / ".github/workflows/pr.yml").is_file())
        self.assertTrue((DEMO / ".github/workflows/privileged.yml").is_file())


if __name__ == "__main__":
    unittest.main()

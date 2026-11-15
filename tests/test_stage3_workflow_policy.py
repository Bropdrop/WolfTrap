from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "build-inspection.yml"
FIXTURE = ROOT / "tests" / "fixtures" / "build_scan" / "adversarial"


class Stage3WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_explicit_feature_branch_and_manual_only(self) -> None:
        self.assertRegex(
            self.text,
            r"(?m)^on:\s*$\n  push:\s*$\n    branches:\s*$"
            r"\n      - feat/wolftrap-stage3-build-inspector-v0_3\s*$"
            r"\n  workflow_dispatch:\s*$",
        )
        for trigger in ("schedule", "pull_request", "pull_request_target", "workflow_run"):
            self.assertNotRegex(self.text, rf"(?m)^\s{{2}}{trigger}:\s*")
        self.assertNotIn("branches-ignore", self.text)

    def test_read_only_no_secrets_and_bounded(self) -> None:
        self.assertRegex(
            self.text,
            r"(?m)^permissions:\s*$\n  contents:\s*read\s*$",
        )
        self.assertNotRegex(self.text, r"(?m)^\s+[a-z-]+:\s*write\s*$")
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn("timeout-minutes: 15", self.text)
        for forbidden in ("secrets.", "id-token", "pull_request_target", "docker run", "deploy"):
            self.assertNotIn(forbidden, self.text.lower())

    def test_pinned_actions_and_optional_parser(self) -> None:
        uses = re.findall(r"(?m)^\s+uses:\s*([^\s#]+)", self.text)
        self.assertEqual(len(uses), 3)
        for action in uses:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        self.assertIn("PyYAML==6.0.3", self.text)
        self.assertIn("python -m wolftrap.test_runner", self.text)

    def test_inspections_have_local_targets_and_verified_artifacts(self) -> None:
        self.assertIn('--root .', self.text)
        self.assertIn('--root tests/fixtures/build_scan/adversarial', self.text)
        self.assertIn('--output-dir "$RUNNER_TEMP/wolftrap-stage3-self"', self.text)
        self.assertIn('--output-dir "$RUNNER_TEMP/wolftrap-stage3-adversarial"', self.text)
        self.assertIn('manifest["state"] == "COMPLETE"', self.text)
        self.assertIn('metadata["sha256"]', self.text)
        self.assertIn('report["target_code_executed"] is False', self.text)
        self.assertRegex(self.text, r"(?m)^\s+if:\s*always\(\)\s*$")
        self.assertIn("retention-days: 14", self.text)

    def test_synthetic_fixtures_are_not_active_workflows(self) -> None:
        self.assertTrue((FIXTURE / ".github" / "workflows" / "unsafe-pr.yml").is_file())
        self.assertTrue((FIXTURE / ".github" / "workflows" / "artifacts.yml").is_file())
        self.assertTrue((FIXTURE / "Dockerfile").is_file())
        for path in FIXTURE.rglob("*.yml"):
            self.assertTrue(path.is_relative_to(ROOT / "tests" / "fixtures"))


if __name__ == "__main__":
    unittest.main()

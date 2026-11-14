from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "research.yml"


class WorkflowPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_only_approved_stage2_branch_push_and_manual_dispatch(self) -> None:
        self.assertRegex(
            self.text,
            r"(?m)^on:\s*$\n  push:\s*$\n    branches:\s*$"
            r"\n      - feat/wolftrap-autonomous-stage2-v0_2\s*$"
            r"\n  workflow_dispatch:\s*$",
        )
        for trigger in ("schedule", "pull_request", "pull_request_target"):
            self.assertNotRegex(self.text, rf"(?m)^\s{{2}}{trigger}:\s*")
        self.assertEqual(len(re.findall(r"(?m)^\s{2}push:\s*$", self.text)), 1)
        self.assertNotIn("branches-ignore", self.text)

    def test_permissions_are_read_only_and_credentials_are_not_persisted(self) -> None:
        self.assertRegex(
            self.text,
            r"(?m)^permissions:\s*$\n\s{2}contents:\s*read\s*$",
        )
        self.assertNotRegex(self.text, r"(?m)^\s+[a-z-]+:\s*write\s*$")
        self.assertRegex(self.text, r"persist-credentials:\s*false")
        self.assertRegex(self.text, r"timeout-minutes:\s*15")

    def test_workflow_has_no_secret_deployment_or_external_target_surface(self) -> None:
        lowered = self.text.lower()
        self.assertNotIn("secrets.", lowered)
        self.assertNotIn("id-token", lowered)
        self.assertNotIn("openai", lowered)
        self.assertNotIn("deploy", lowered)
        self.assertNotRegex(lowered, r"(?m)^\s+(target|url|hostname|command):")
        inputs = set(
            re.findall(r"(?m)^\s{6}([a-z_]+):\s*$", self.text.split("permissions:", 1)[0])
        )
        self.assertEqual(inputs, {"seed"})

    def test_stage2_has_fixed_full_pair_three_seed_gate(self) -> None:
        self.assertIn("python -m wolftrap sweep", self.text)
        self.assertIn("--seed-count 3", self.text)
        self.assertIn("--mutation-budget 128", self.text)
        self.assertIn("--sut correct-v1", self.text)
        self.assertIn("--unit-test-summary reports/unit-tests.json", self.text)
        self.assertIn("--output-dir reports/stage2", self.text)
        self.assertIn('inputs.seed || \'20261113\'', self.text)
        self.assertIn('manifest["state"] == "COMPLETE"', self.text)
        self.assertIn('summary["qualification"]["all_55_pairs_per_seed"] is True', self.text)
        self.assertIn('summary["summary"]["findings"] == 0', self.text)
        self.assertNotIn("python -m wolftrap run\n", self.text)

    def test_actions_are_sha_pinned_and_artifacts_upload_even_on_failure(self) -> None:
        uses = re.findall(r"(?m)^\s+uses:\s*([^\s#]+)", self.text)
        self.assertEqual(len(uses), 3)
        for action in uses:
            self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
        upload_position = self.text.index("actions/upload-artifact@")
        preceding_step = self.text.rfind("- name:", 0, upload_position)
        upload_block = self.text[preceding_step:]
        self.assertRegex(upload_block, r"(?m)^\s+if:\s*always\(\)\s*$")
        self.assertIn("path: reports/", upload_block)
        self.assertIn("if-no-files-found: error", upload_block)
        self.assertIn("retention-days: 14", upload_block)


if __name__ == "__main__":
    unittest.main()

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

    def test_only_manual_dispatch_is_configured(self) -> None:
        self.assertRegex(self.text, r"(?m)^on:\s*$\n\s{2}workflow_dispatch:\s*$")
        for trigger in ("schedule", "push", "pull_request", "pull_request_target"):
            self.assertNotRegex(self.text, rf"(?m)^\s{{2}}{trigger}:\s*")

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
        self.assertEqual(inputs, {"seed", "mutation_budget"})

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


if __name__ == "__main__":
    unittest.main()

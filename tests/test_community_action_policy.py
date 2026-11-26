"""Prevent the public Action and starter workflow drifting into unsafe scope."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
BRANCH = "feat/wolftrap-community-onramp-v0_6"
PUBLISHED_ACTION_SHA = "343bd56f04a35f37de183d42d82a33b6454765b0"
PINNED = re.compile(r"^[^@]+@[0-9a-f]{40}$")


class CommunityPolicyTests(unittest.TestCase):
    def test_starter_is_pull_request_scoped_read_only_and_immutable_pinned(self) -> None:
        source = (ROOT / "examples/wolftrap-scan.yml").read_text()
        workflow = yaml.load(source, Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow["on"]), {"pull_request", "workflow_dispatch"})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertIn("paths", workflow["on"]["pull_request"])
        steps = workflow["jobs"]["wolftrap"]["steps"]
        self.assertEqual(steps[0]["with"]["persist-credentials"], "false")
        self.assertTrue(PINNED.fullmatch(steps[0]["uses"]))
        self.assertTrue(PINNED.fullmatch(steps[1]["uses"]))
        self.assertEqual(steps[1]["uses"], f"Bropdrop/WolfTrap@{PUBLISHED_ACTION_SHA}")
        self.assertEqual(steps[1]["with"]["fail-on-findings"], "false")
        self.assertNotIn("secrets.", source)
        self.assertNotIn("pull_request_target", source)
        self.assertIn("full commit SHA", source)

    def test_dogfood_runs_four_modes_with_expected_read_only_boundaries(self) -> None:
        source = (ROOT / ".github/workflows/community-action-qualification.yml").read_text()
        workflow = yaml.load(source, Loader=yaml.BaseLoader)
        self.assertEqual(workflow["on"]["push"]["branches"], ["main", BRANCH])
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        steps = workflow["jobs"]["qualify"]["steps"]
        self.assertEqual(steps[0]["with"]["persist-credentials"], "false")
        for step in steps:
            if "uses" in step and step["uses"] != "./":
                self.assertTrue(PINNED.fullmatch(step["uses"]))
        cases = {step.get("id"): step for step in steps if step.get("id")}
        self.assertEqual(set(cases), {"safe", "advisory", "strict", "unknown"})
        self.assertEqual(cases["strict"]["continue-on-error"], "true")
        self.assertEqual(cases["unknown"]["continue-on-error"], "true")
        self.assertEqual(cases["unknown"]["with"]["fail-on-findings"], "false")
        self.assertIn("test \"$WT_OUTCOME\" = failure", source)
        self.assertNotIn("secrets.", source)
        self.assertNotIn("pull_request_target", source)

    def test_action_only_runs_trusted_local_scanner_and_uploads_evidence(self) -> None:
        source = (ROOT / "action.yml").read_text()
        action = yaml.load(source, Loader=yaml.BaseLoader)
        self.assertEqual(action["runs"]["using"], "composite")
        self.assertEqual(len(action["runs"]["steps"]), 4)
        self.assertIn("always()", action["runs"]["steps"][-1]["if"])
        self.assertIn("GITHUB_ACTION_PATH", action["runs"]["steps"][-2]["run"])
        self.assertIn("python -I -c", action["runs"]["steps"][-2]["run"])
        self.assertIn("python -I -m pip", action["runs"]["steps"][-3]["run"])
        self.assertEqual(action["inputs"]["fail-on-findings"]["default"], "false")
        self.assertIn("INCONCLUSIVE", action["outputs"]["status"]["description"])
        self.assertEqual(action["runs"]["steps"][-1]["with"]["retention-days"], "14")
        self.assertNotIn("secrets.", source)
        self.assertNotIn("curl ", source)
        self.assertNotIn("git clone", source)


if __name__ == "__main__":
    unittest.main()

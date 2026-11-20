"""Governed PR qualifications must have no release authority."""

import copy
import importlib.util
from pathlib import Path
import re
import sys
import unittest
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/governed-release-qualification.yml"
HEAD, TREE = "a" * 40, "b" * 40


class GovernedWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        spec = importlib.util.spec_from_file_location(
            "governed_qualification", ROOT / "release/governed_qualification.py"
        )
        cls.runner = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", sys.path.copy()):
            spec.loader.exec_module(cls.runner)

    def test_pr_event_and_jobs_have_no_signing_or_deployment_authority(self):
        self.assertEqual(self.workflow["on"], {"pull_request": {"branches": ["feat/release-trust-chain-v1"]}})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        for job in self.workflow["jobs"].values():
            self.assertFalse({"environment", "permissions", "secrets", "uses"} & job.keys())
            self.assertEqual(job["env"], {"SOURCE": "${{ github.event.pull_request.head.sha }}"})
            for step in job["steps"]:
                self.assertNotIn("secrets.", repr(step).casefold())
                self.assertNotIn("github.token", repr(step).casefold())
                if "uses" in step:
                    self.assertRegex(
                        step["uses"], r"^actions/(checkout|setup-python|upload-artifact)@[a-f0-9]{40}$"
                    )
                if step.get("uses", "").startswith("actions/checkout@"):
                    self.assertEqual(
                        step["with"],
                        {"ref": "${{ env.SOURCE }}", "persist-credentials": "false", "fetch-depth": "0"},
                    )

    def test_native_matrix_and_isolated_replays(self):
        jobs = self.workflow["jobs"]
        self.assertEqual(
            set(jobs["subscriber"]["strategy"]["matrix"]["runner"]), {"ubuntu-24.04", "ubuntu-24.04-arm"}
        )
        for job, commands in (
            (
                jobs["subscriber"],
                (
                    "scripts/qualify-product.py",
                    "release/qualification",
                    "release/governed_qualification.py",
                    "release/qualify_incident_install.py",
                    "--require-install",
                ),
            ),
            (jobs["regression"], ("scripts/qualify-research.py", "--workflow-dependencies", "--report-root")),
        ):
            scripts = [s["run"] for s in job["steps"] if "run" in s and "sudo unshare --net --" in s["run"]]
            self.assertEqual(len(scripts), 1)
            script = scripts[0]
            for required in (
                "--clear-groups",
                "--no-new-privs",
                "--bounding-set=-all",
                "env -i",
                "--expected-head",
                "--parent-netns",
                *commands,
            ):
                self.assertIn(required, script)
            self.assertNotIn("gh api", script)
            self.assertNotIn("gh auth", script)

    def test_artifact_paths_are_explicit_and_exclude_private_material(self):
        for job in self.workflow["jobs"].values():
            for step in job["steps"]:
                if not step.get("uses", "").startswith("actions/upload-artifact@"):
                    continue
                opts = step["with"]
                self.assertEqual(opts["if-no-files-found"], "error")
                self.assertNotIn("include-hidden-files", opts)
                for path in opts["path"].splitlines():
                    self.assertRegex(
                        path, re.compile(r"^\$\{\{ runner\.temp \}\}/[a-z][a-z0-9./_-]+\.(json|zip|pyz|pem)$")
                    )
                    self.assertNotIn("..", path.split("/"))
                    if path.endswith(".pem"):
                        self.assertIn(path.rsplit("/", 1)[1], {"root.pem", "signer.pem"})

    def test_unit_summary_must_bind_source_and_all_tests_must_run(self):
        revision = {"commit_sha": HEAD, "tree_sha": TREE, "dirty": False}
        clean = dict(
            successful=True,
            source_stable=True,
            tests_run=len(self.runner.TEST_FILES),
            source_revision=revision,
            source_revision_end=revision.copy(),
            errors=0,
            failures=0,
            expected_failures=0,
            unexpected_successes=0,
            skipped=0,
        )
        self.runner.check_tests(clean, HEAD, TREE)
        for key, value in (
            ("successful", False),
            ("source_stable", False),
            ("tests_run", 0),
            ("skipped", 1),
            ("unexpected_successes", 1),
            ("errors", 1),
            ("failures", 1),
            ("expected_failures", 1),
        ):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.runner.check_tests({**clean, key: value}, HEAD, TREE)
        for side in ("source_revision", "source_revision_end"):
            for key, value in (("commit_sha", TREE), ("tree_sha", HEAD), ("dirty", True)):
                altered = copy.deepcopy(clean)
                altered[side][key] = value
                with self.subTest(side=side, key=key), self.assertRaises(ValueError):
                    self.runner.check_tests(altered, HEAD, TREE)

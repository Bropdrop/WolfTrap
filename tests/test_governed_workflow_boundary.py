"""Source contract for evaluation workflows. GitHub settings require a separate live audit."""

import copy
import hashlib
from pathlib import Path
import re
import unittest

from wolftrap.build_scan import _yaml_document


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github" / "workflows"
# The protected dispatcher at the previously qualified Release Trust revision.
DISABLED_DISPATCH_SHA256 = "2f8f662626a9468f45033f7d9de55ed6df5946e53e5404895819253c48b322ff"
READ = {"contents": "read"}
RUNNERS = {"ubuntu-latest", "ubuntu-24.04", "ubuntu-24.04-arm"}


def check_evaluation_workflow(document):
    events = document.get("on")
    if (
        not isinstance(events, dict)
        or not events
        or set(events) - {"pull_request", "push", "workflow_dispatch"}
    ):
        raise ValueError("unreviewed trigger")
    if document.get("permissions") != READ:
        raise ValueError("unreviewed workflow authority")
    if re.search(r"\bsecrets\b|\bgithub\s*(?:\.\s*token\b|\[\s*['\"]token)", str(document), re.I):
        raise ValueError("explicit credential reference")
    for job in document["jobs"].values():
        if job.get("permissions", READ) not in ({}, READ):
            raise ValueError("unreviewed job authority")
        if set(job) & {"uses", "environment", "container", "services"}:
            raise ValueError("unreviewed external job boundary")
        runner = job["runs-on"]
        if runner == "${{ matrix.runner }}":
            matrix = job["strategy"]["matrix"]
            if set(matrix) != {"runner"} or not isinstance(matrix["runner"], list) or not matrix["runner"]:
                raise ValueError("unreviewed runner matrix")
            choices = matrix["runner"]
        else:
            choices = [runner]
        if any(label not in RUNNERS for label in choices):
            raise ValueError("unreviewed runner")
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                if step.get("with", {}).get("persist-credentials") != "false":
                    raise ValueError("checkout could persist credentials")


class GovernedWorkflowTests(unittest.TestCase):
    def test_repository_jobs_have_evaluation_authority_only(self):
        self.assertEqual(
            hashlib.sha256((WORKFLOWS / "protected-release.yml").read_bytes()).hexdigest(),
            DISABLED_DISPATCH_SHA256,
        )
        for path in sorted(WORKFLOWS.iterdir()):
            if path.suffix not in {".yaml", ".yml"} or path.name == "protected-release.yml":
                continue
            with self.subTest(workflow=path.name):
                check_evaluation_workflow(_yaml_document(path.read_text(encoding="utf-8")))

    def test_rejects_privilege_changes_at_the_workflow_and_job_boundaries(self):
        source = _yaml_document((WORKFLOWS / "governed-release-qualification.yml").read_text())
        cases = (
            ("trigger", {"on": {"pull_request_target": {}}}),
            ("workflow authority", {"permissions": {"contents": "write"}}),
            ("federation", {"permissions": {"id-token": "write"}}),
            ("environment", {"environment": "production"}),
            ("reusable workflow", {"uses": "./other.yml"}),
            ("credential handoff", {"env": {"EXAMPLE": "${{ secrets.EXAMPLE }}"}}),
            ("persistent runner", {"runs-on": "self-hosted"}),
        )
        for name, change in cases:
            with self.subTest(name=name):
                sample = copy.deepcopy(source)
                target = sample if name in {"trigger", "workflow authority"} else sample["jobs"]["subscriber"]
                target.update(change)
                with self.assertRaises(ValueError):
                    check_evaluation_workflow(sample)
        checkout = source["jobs"]["subscriber"]["steps"][0]
        del checkout["with"]["persist-credentials"]
        with self.assertRaisesRegex(ValueError, "credentials"):
            check_evaluation_workflow(source)

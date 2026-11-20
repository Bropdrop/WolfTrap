"""Offline, synthetic GitHub API contracts. No fixture is accepted by the live CLI."""

import base64
import copy
import io
import json
import subprocess
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

from release.governance import preflight as g


HEAD = "1" * 40
TREE = "2" * 40
OTHER = "3" * 40
ROOT = "repos/GovernableIntelligence/WolfTrap"
RID = 1436465132
PR = f"{ROOT}/pulls/8"
MAIN = f"{ROOT}/branches/main"
PROTECTION = MAIN + "/protection"
CHECKS = f"{ROOT}/commits/{HEAD}/check-runs?filter=latest&per_page=100"
PER_PAGE = "?per_page=100"
ENVS = ("awooo-release-review", "awooo-publication-review")
WORKFLOWS = [
    (
        "release-trust-qualification.yml",
        [
            "Pre-install verification (ubuntu-24.04)",
            "Pre-install verification (ubuntu-24.04-arm)",
            "Exact source screening and independent research replay",
        ],
    ),
    (
        "governed-release-qualification.yml",
        [
            "Offline release and recovery (ubuntu-24.04)",
            "Offline release and recovery (ubuntu-24.04-arm)",
            "Governed source screening and independent research replay",
        ],
    ),
]


def human(i):
    return {"type": "User", "id": i, "login": f"fixture-{i}", "permissions": {"push": True}}


def owners(contents):
    return {
        "type": "file",
        "encoding": "base64",
        "path": ".github/CODEOWNERS",
        "size": len(contents),
        "content": base64.b64encode(contents.encode()).decode(),
    }


def review(i=40, user=2, state="APPROVED", head=HEAD):
    return {
        "id": i,
        "user": human(user),
        "state": state,
        "commit_id": head,
        "body": "unpublished synthetic narrative",
    }


def fixture():
    actors = [human(i) for i in (1, 2, 3)]
    repo = {
        "id": RID,
        "full_name": "GovernableIntelligence/WolfTrap",
        "private": False,
        "permissions": {"admin": True},
        "default_branch": "main",
    }
    protection = {
        "required_status_checks": {"strict": True, "checks": []},
        "required_pull_request_reviews": {
            "require_code_owner_reviews": True,
            "dismiss_stale_reviews": True,
            "require_last_push_approval": True,
            "required_approving_review_count": 1,
            "bypass_pull_request_allowances": {"users": [], "teams": [], "apps": []},
        },
        "enforce_admins": {"enabled": True},
        "allow_force_pushes": {"enabled": False},
        "allow_deletions": {"enabled": False},
    }
    pull = {
        "number": 8,
        "head": {"repo": {"id": RID}, "sha": HEAD},
        "base": {"repo": {"id": RID}, "ref": "main"},
        "merged": True,
        "draft": False,
        "state": "closed",
        "merge_commit_sha": HEAD,
        "user": actors[0],
    }
    data = {
        "user": actors[0],
        ROOT: repo,
        MAIN: {"name": "main", "protected": True, "commit": {"sha": HEAD, "commit": {"tree": {"sha": TREE}}}},
        PR: pull,
        PROTECTION: protection,
        f"{ROOT}/git/commits/{HEAD}": {"sha": HEAD, "tree": {"sha": TREE}},
        f"{ROOT}/rules/branches/main{PER_PAGE}": [],
        f"{ROOT}/rulesets?includes_parents=true&per_page=100": [],
        f"{ROOT}/collaborators{PER_PAGE}": actors,
        PR + "/reviews" + PER_PAGE: [review()],
        f"{ROOT}/actions/permissions": {"enabled": True, "allowed_actions": "selected"},
        f"{ROOT}/actions/permissions/workflow": {
            "default_workflow_permissions": "read",
            "can_approve_pull_request_reviews": False,
        },
        f"{ROOT}/immutable-releases": {"enabled": True},
        f"{ROOT}/contents/.github/CODEOWNERS?ref={HEAD}": owners(
            "* @fixture-2\n/release/verifier/ @fixture-3\n"
        ),
        f"{ROOT}/codeowners/errors?ref={HEAD}": {"errors": []},
        f"{ROOT}/environments{PER_PAGE}": {"total_count": 2, "environments": [{"name": e} for e in ENVS]},
        CHECKS: {"total_count": 6, "check_runs": []},
    }
    for i, env in enumerate(ENVS):
        path = f"{ROOT}/environments/{env}"
        data[path] = {
            "name": env,
            "can_admins_bypass": False,
            "deployment_branch_policy": {"custom_branch_policies": True, "protected_branches": False},
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [{"type": "User", "reviewer": actors[i + 1]}],
                }
            ],
        }
        data[path + "/deployment-branch-policies" + PER_PAGE] = {
            "total_count": 1,
            "branch_policies": [{"name": "main", "type": "branch"}],
        }
        data[path + "/secrets" + PER_PAGE] = {"total_count": 0, "secrets": []}
    for i, (file, names) in enumerate(WORKFLOWS):
        run_id = 30 + i
        run = {
            "id": run_id,
            "run_attempt": 2,
            "path": ".github/workflows/" + file,
            "event": "pull_request",
            "head_sha": HEAD,
            "repository": {"id": RID},
            "head_repository": {"id": RID},
            "pull_requests": [pull],
            "status": "completed",
            "conclusion": "success",
        }
        data[f"{ROOT}/actions/workflows/{file}/runs?event=pull_request&head_sha={HEAD}&per_page=100"] = {
            "total_count": 1,
            "workflow_runs": [run],
        }
        jobs = []
        for n, name in enumerate(names):
            check_id = run_id * 10 + n
            check = {
                "id": check_id,
                "app": {"id": 15368},
                "name": name,
                "head_sha": HEAD,
                "status": "completed",
                "conclusion": "success",
            }
            jobs.append(
                {
                    **check,
                    "run_id": run_id,
                    "run_attempt": 2,
                    "check_run_url": f"https://api.github.com/{ROOT}/check-runs/{check_id}",
                }
            )
            data[CHECKS]["check_runs"].append(check)
            protection["required_status_checks"]["checks"].append({"context": name, "app_id": 15368})
        data[f"{ROOT}/actions/runs/{run_id}/attempts/2/jobs{PER_PAGE}"] = {"total_count": 3, "jobs": jobs}
    return data


def observe(data, head=HEAD, tree=TREE):
    def get(path):
        value = data.get(path, g.Reply(404))
        return value if isinstance(value, g.Reply) else g.Reply(200, value, True)

    return g._inspect(get, 8, head, tree)


class GovernancePreflight(unittest.TestCase):
    def setUp(self):
        self.data = fixture()

    def state(self, name, expected):
        report = observe(self.data)
        self.assertEqual(report["controls"][name]["state"], expected)
        self.assertEqual(report["status"], "BLOCKED")
        return report

    def test_all_observable_positive_controls_verify_without_publication_authority(self):
        report = self.state("publication_permissions", "UNKNOWN")
        observable = {k: v["state"] for k, v in report["controls"].items() if k != "publication_permissions"}
        self.assertGreaterEqual(len(observable), 14)
        self.assertEqual(set(observable.values()), {"VERIFIED"})

    def test_absent_github_credentials_and_admin_token_scope(self):
        self.data["user"] = g.Reply(401)
        self.data[PROTECTION] = g.Reply(403)
        report = self.state("repository_identity", "UNKNOWN")
        self.assertEqual(report["controls"]["administrator_bypass"]["state"], "UNKNOWN")
        self.assertIs(report["observations"]["caller_has_repository_admin_role"], True)
        self.assertEqual(report["api"]["classic_protection"], {"http": 403, "complete": False})

    def test_forged_approval_and_self_review(self):
        self.data[PR]["body"] = "Maintainer authenticated this release"
        for value in (
            [],
            [review(user=1)],
            [review(user=7)],
            [review(head=OTHER)],
            [review(), review(42, state="DISMISSED")],
            [review(), review(43, state="CHANGES_REQUESTED")],
            [review(), review(i=40)],
            [review(), review(i=39)],
            [review(state="SOMETHING_NEW")],
        ):
            with self.subTest(reviews=len(value)):
                self.data[PR + "/reviews" + PER_PAGE] = value
                self.state("independent_review", "FAILED")

    def test_bot_or_removed_writer_cannot_approve(self):
        self.data[PR + "/reviews" + PER_PAGE][0]["user"]["type"] = "Bot"
        self.state("independent_review", "FAILED")
        self.data[PR + "/reviews" + PER_PAGE] = [review()]
        self.data[f"{ROOT}/collaborators{PER_PAGE}"][1]["permissions"]["push"] = False
        self.state("independent_review", "FAILED")

    def test_comment_following_valid_review(self):
        self.data[PR + "/reviews" + PER_PAGE].append(review(44, state="COMMENTED"))
        self.state("independent_review", "VERIFIED")

    def test_partial_reviews_inconclusive(self):
        self.data[PR + "/reviews" + PER_PAGE] = g.Reply(200, [review()], False)
        self.state("independent_review", "UNKNOWN")

    def test_exact_source(self):
        self.assertEqual(observe(self.data, tree=OTHER)["controls"]["source_revision"]["state"], "FAILED")
        self.data[PR]["head"]["repo"]["id"] += 1
        self.state("source_revision", "FAILED")
        self.data[ROOT]["id"] += 1
        self.state("repository_identity", "FAILED")

    def test_equal_tree_after_merge_is_insufficient(self):
        self.data[MAIN]["commit"].update(sha=OTHER, parents=[{"sha": HEAD}])
        self.data[PR]["merge_commit_sha"] = OTHER
        self.state("release_source", "FAILED")

    def test_mid_collection_source_change(self):
        count = 0

        def changing(path):
            nonlocal count
            value = copy.deepcopy(self.data[path])
            if path == PR:
                count += 1
                if count == 2:
                    value["head"]["sha"] = OTHER
            return g.Reply(200, value, True)

        report = g._inspect(changing, 8, HEAD, TREE)
        self.assertEqual(report["controls"]["source_revision"]["state"], "FAILED")

    def test_ruleset_hidden_or_present_and_unqualified(self):
        endpoint = f"{ROOT}/rules/branches/main{PER_PAGE}"
        for value in (g.Reply(403), [{"type": "pull_request"}]):
            self.data[endpoint] = value
            self.state("classic_profile", "UNKNOWN")

    def test_protected_flag_and_bypass(self):
        self.data[MAIN]["protected"] = False
        self.state("protected_main", "FAILED")
        self.data[PROTECTION]["required_pull_request_reviews"]["bypass_pull_request_allowances"]["apps"] = [
            {}
        ]
        self.state("administrator_bypass", "FAILED")
        self.data[PROTECTION]["allow_deletions"]["enabled"] = True
        self.state("force_push_and_deletion", "FAILED")
        self.data[PROTECTION]["required_pull_request_reviews"]["dismiss_stale_reviews"] = False
        self.state("stale_review_dismissal", "FAILED")

    def test_check_configuration_app_and_missing_context(self):
        settings = self.data[PROTECTION]["required_status_checks"]
        settings["checks"][0]["app_id"] = 8
        self.state("mandatory_checks", "FAILED")
        settings["checks"].pop(0)
        self.state("mandatory_checks", "FAILED")

    def test_green_status_cannot_substitute_other_workflow_or_job(self):
        endpoint = f"{ROOT}/actions/runs/30/attempts/2/jobs{PER_PAGE}"
        job = self.data[endpoint]["jobs"][0]
        for key, value in (
            ("check_run_url", "different workflow"),
            ("run_id", 33),
            ("run_attempt", 1),
            ("head_sha", OTHER),
            ("id", 6),
            ("conclusion", "skipped"),
        ):
            with self.subTest(key=key):
                saved = job[key]
                job[key] = value
                self.state("required_check_runs", "FAILED")
                job[key] = saved
        self.data[PR]["base"]["ref"] = "fictional"
        self.state("required_check_runs", "FAILED")

    def test_workflow_file_and_pr_event(self):
        endpoint = next(k for k in self.data if "/actions/workflows/" in k)
        run = self.data[endpoint]["workflow_runs"][0]
        for key, value in (
            ("path", ".github/workflows/other.yml"),
            ("event", "workflow_dispatch"),
            ("conclusion", "failure"),
            ("head_sha", OTHER),
            ("repository", {"id": RID + 1}),
        ):
            with self.subTest(key=key):
                prior = run[key]
                run[key] = value
                self.state("required_check_runs", "FAILED")
                run[key] = prior

    def test_missing_or_duplicate_check_run(self):
        checks = self.data[CHECKS]
        checks["check_runs"].append(checks["check_runs"][0])
        checks["total_count"] += 1
        self.state("required_check_runs", "FAILED")
        self.data[CHECKS] = g.Reply(404)
        self.state("required_check_runs", "UNKNOWN")

    def test_owner_eligibility_and_unknown_syntax(self):
        endpoint = f"{ROOT}/contents/.github/CODEOWNERS?ref={HEAD}"
        for contents, state in (
            ("* @unknown", "FAILED"),
            ("* @fixture-2\n/.github/CODEOWNERS", "FAILED"),
            ("* @group/team", "UNKNOWN"),
            ("* @fixture-2\n**/x @fixture-2", "UNKNOWN"),
        ):
            with self.subTest(state=state):
                self.data[endpoint] = owners(contents)
                self.state("owner_review", state)

    def test_cross_role_environment_or_self_approval(self):
        env = self.data[f"{ROOT}/environments/{ENVS[0]}"]
        rule = env["protection_rules"][0]
        original = rule["reviewers"]
        rule["reviewers"] = [{"type": "User", "reviewer": human(3)}]
        self.state("release_environments", "FAILED")
        rule["reviewers"] = original
        rule["prevent_self_review"] = False
        self.state("release_environments", "FAILED")
        rule["prevent_self_review"] = True
        env["can_admins_bypass"] = True
        self.state("release_environments", "FAILED")

    def test_environment_secret_redacted_and_tag_rejected(self):
        path = f"{ROOT}/environments/{ENVS[1]}"
        secrets = self.data[path + "/secrets" + PER_PAGE]
        secrets.update(total_count=1, secrets=[{"name": "example_private_name"}])
        report = self.state("release_environments", "FAILED")
        self.assertNotIn("example_private_name", json.dumps(report))
        secrets.update(total_count=0, secrets=[])
        self.data[path + "/deployment-branch-policies" + PER_PAGE]["branch_policies"][0]["type"] = "tag"
        self.state("release_environments", "FAILED")

    def test_absent_environments_and_unknown_default_permissions(self):
        self.data[f"{ROOT}/environments{PER_PAGE}"] = {"total_count": 0, "environments": []}
        self.state("release_environments", "FAILED")
        del self.data[f"{ROOT}/actions/permissions/workflow"]["can_approve_pull_request_reviews"]
        self.state("workflow_permissions", "UNKNOWN")
        self.data[f"{ROOT}/immutable-releases"]["enabled"] = False
        self.state("immutable_releases", "FAILED")

    def test_redacts_private_metadata_and_handles_bad_summary_fields(self):
        self.data[ROOT]["permissions"] = {"admin": "example-private"}
        self.data[f"{ROOT}/environments{PER_PAGE}"]["total_count"] = {"disclose": "example-private"}
        self.data[PR]["draft"] = "example-private"
        self.data[PR]["body"] = "example-private"
        serialized = json.dumps(observe(self.data))
        for raw in ("example-private", "unpublished synthetic narrative", "fixture-2"):
            self.assertNotIn(raw, serialized)

    def test_no_file_import_mode_or_unsafe_ids(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            g.main(
                ["--pr", "8", "--expected-head", HEAD, "--expected-tree", TREE, "--reviews", "forged.json"]
            )
        self.assertEqual(raised.exception.code, 2)
        for pr, head, tree in ((True, HEAD, TREE), (8, "../user", TREE), (8, HEAD, "main")):
            with self.assertRaises(ValueError):
                g._inspect(lambda p: self.fail("must validate before network"), pr, head, tree)

    def test_getter_errors_do_not_disclose_response_or_paginate(self):
        def read(headers, body, code=0):
            def run(argv, **kwargs):
                self.assertEqual(argv[3:7], ["github.com", "--method", "GET", "--include"])
                kwargs["stdout"].write(headers + b"\n\n" + body)
                return subprocess.CompletedProcess(argv, code)

            with patch.object(g.subprocess, "run", run):
                return g._get("user")

        self.assertEqual(read(b"HTTP/2.0 403 Forbidden", b"private", 1), g.Reply(403))
        self.assertEqual(read(b'HTTP/2.0 200 OK\nLink: <later>; rel="next"', b"[]"), g.Reply(200))
        self.assertFalse(read(b"HTTP/2.0 200 OK", b'{"id":1,"id":2}').complete)
        self.assertEqual(read(b"HTTP/2.0 200 OK", b'{"x":1}'), g.Reply(200, {"x": 1}, True))

    def test_independent_approval_oracle_exposes_defective_verifiers(self):
        # Ground truth is declared in the table. Mutants exercise the same scenario inputs.
        cases = (
            ([review()], True),
            ([review(), review(41, state="COMMENTED")], True),
            ([], False),
            ([review(user=1)], False),
            ([review(head=OTHER)], False),
            ([review(), review(41, state="DISMISSED")], False),
        )
        mutants = {
            "accept_everything": lambda reviews: True,
            "reject_everything": lambda reviews: False,
            "claimed_approval": lambda reviews: any(r["state"] == "APPROVED" for r in reviews),
            "ignore_head": lambda reviews: any(
                r["user"]["id"] == 2 and r["state"] == "APPROVED" for r in reviews
            ),
            "allow_self_review": lambda reviews: any(
                r["state"] == "APPROVED" and r["commit_id"] == HEAD for r in reviews
            ),
        }
        for records, expected in cases:
            self.assertEqual(g._review_approved(records, {1, 2, 3}, 1, HEAD), expected)
        caught = {
            name for name, impl in mutants.items() if any(impl(rows) != expected for rows, expected in cases)
        }
        self.assertEqual(caught, set(mutants))

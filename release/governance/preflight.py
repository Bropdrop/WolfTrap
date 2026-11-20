"""Online, read-only observation of one pinned public repository. No release authority."""

import argparse
import base64
import json
import os
import re
import resource
import subprocess
import tempfile
import time
from dataclasses import dataclass

REPOSITORY = "GovernableIntelligence/WolfTrap"
REPOSITORY_ID = 1436465132
ROOT = f"repos/{REPOSITORY}"
SHA = re.compile(r"[a-f0-9]{40}")
ENVIRONMENTS = ("awooo-release-review", "awooo-publication-review")
WORKFLOWS = {
    "release-trust-qualification.yml": (
        "Pre-install verification (ubuntu-24.04)",
        "Pre-install verification (ubuntu-24.04-arm)",
        "Exact source screening and independent research replay",
    ),
    "governed-release-qualification.yml": (
        "Offline release and recovery (ubuntu-24.04)",
        "Offline release and recovery (ubuntu-24.04-arm)",
        "Governed source screening and independent research replay",
    ),
}
CHECKS = tuple(check for group in WORKFLOWS.values() for check in group)
ACTIONS_APP = 15368
MAX_REPLY = 2 * 1024 * 1024
LIMIT = "?per_page=100"


@dataclass(frozen=True)
class Reply:
    http: int | None = None
    data: object = None
    complete: bool = False


def _unique(items):
    obj = dict(items)
    if len(obj) != len(items):
        raise ValueError("duplicate field")
    return obj


def _limit_output():
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_REPLY, MAX_REPLY))


def _get(path):
    # Surface status and selected facts only. Response bodies can contain private names.
    argv = [
        "/usr/bin/gh",
        "api",
        "--hostname",
        "github.com",
        "--method",
        "GET",
        "--include",
        "-H",
        "X-GitHub-Api-Version: 2022-11-28",
        path,
    ]
    env = {
        k: v
        for k, v in os.environ.items()
        if k
        in {
            "HOME",
            "GH_CONFIG_DIR",
            "XDG_CONFIG_HOME",
            "GH_TOKEN",
            "GITHUB_TOKEN",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "https_proxy",
            "http_proxy",
            "no_proxy",
        }
    }
    env.update(PATH="/usr/bin:/bin", GH_PROMPT_DISABLED="1", GH_NO_UPDATE_NOTIFIER="1")
    try:
        with tempfile.TemporaryFile() as response:
            result = subprocess.run(
                argv,
                stdout=response,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                timeout=12,
                env=env,
                preexec_fn=_limit_output,
                check=False,
            )
            if response.tell() >= MAX_REPLY:
                return Reply()
            response.seek(0)
            header, sep, body = response.read().replace(b"\r\n", b"\n").partition(b"\n\n")
        match = re.fullmatch(rb"HTTP/[0-9.]+ ([0-9]{3})(?: .*)?", header.split(b"\n")[0])
        if not match or not sep:
            return Reply()
        status = int(match[1])
        if status != 200 or result.returncode != 0:
            return Reply(status)
        if re.search(rb'^Link:[^\n]*rel="next"', header, re.I | re.M):
            return Reply(status)
        return Reply(status, json.loads(body, object_pairs_hook=_unique), True)
    except (OSError, UnicodeError, ValueError, RecursionError, subprocess.TimeoutExpired):
        return Reply()


class Audit:
    def __init__(self, get):
        self.get = get
        self.responses = {}
        self.api = {}
        self.controls = {}

    def read(self, key, path, shape=dict):
        reply = self.get(path)
        ok = reply.complete and reply.http == 200 and isinstance(reply.data, shape)
        self.api[key] = {"http": reply.http, "complete": ok}
        self.responses[key] = reply.data if ok else None
        return self.responses[key]

    def require(self, name, inputs, predicate, basis):
        state = "UNKNOWN"
        if all(self.responses.get(key) is not None for key in inputs):
            try:
                state = "VERIFIED" if predicate() else "FAILED"
            except (KeyError, IndexError, TypeError, AttributeError, ValueError):
                pass  # Unknown API shapes never become a successful observation.
        self.controls[name] = {"state": state, "basis": basis}


def _human_id(user):
    if user["type"] != "User" or type(user["id"]) is not int or user["id"] <= 0:
        raise ValueError("unidentified user")
    return user["id"]


def _writers(collaborators):
    return {
        _human_id(person)
        for person in collaborators
        if person["type"] == "User" and person["permissions"]["push"] is True
    }


def _review_approved(reviews, writers, author, head):
    latest = {}
    # GitHub returns reviews in chronological order. Require increasing review IDs
    # to fail closed if chronology is ambiguous. Dismissals replace prior decisions.
    previous = 0
    for review in reviews:
        identifier = review["id"]
        if type(identifier) is not int or identifier <= previous:
            return False
        previous = identifier
        state = review["state"]
        if state in ("PENDING", "COMMENTED"):
            continue
        if state not in ("DISMISSED", "CHANGES_REQUESTED", "APPROVED"):
            return False
        if review["user"]["type"] == "User":
            person = _human_id(review["user"])
            if person in writers and person != author:
                latest[person] = (state, review["commit_id"])
    return ("APPROVED", head) in latest.values() and all(
        state != "CHANGES_REQUESTED" for state, _ in latest.values()
    )


def _field(obj, key, kind):
    if isinstance(obj, dict) and type(obj.get(key)) is kind:
        return obj[key]
    return None


def _positive_id(value):
    return type(value) is int and 0 < value < 2**63


def _workflow_jobs(a, pr, head, file):
    run_list = a.read(
        file, f"{ROOT}/actions/workflows/{file}/runs?event=pull_request&head_sha={head}&per_page=100"
    )
    if run_list is None:
        return None
    try:
        runs = run_list["workflow_runs"]
        if type(runs) is not list or run_list["total_count"] != len(runs):
            return None
        matches = [
            r
            for r in runs
            if r["path"] == ".github/workflows/" + file
            and r["event"] == "pull_request"
            and r["head_sha"] == head
            and r["repository"]["id"] == r["head_repository"]["id"] == REPOSITORY_ID
            and any(
                p["number"] == pr
                and p["base"]["ref"] == "main"
                and p["head"]["sha"] == head
                and p["base"]["repo"]["id"] == REPOSITORY_ID
                for p in r["pull_requests"]
            )
        ]
        if len(matches) != 1:
            return False
        run = matches[0]
        if run["status"] != "completed" or run["conclusion"] != "success":
            return False
        rid, attempt = run["id"], run["run_attempt"]
        if not _positive_id(rid) or not _positive_id(attempt):
            return False
        data = a.read(file + "_jobs", f"{ROOT}/actions/runs/{rid}/attempts/{attempt}/jobs{LIMIT}")
        if data is None:
            return None
        return (rid, attempt, data)
    except (IndexError, KeyError, TypeError, AttributeError):
        return None


def _completed_checks(groups, checks, head):
    if type(checks["check_runs"]) is not list or checks["total_count"] != len(checks["check_runs"]):
        return False
    for file, names in WORKFLOWS.items():
        if groups[file] is False:
            return False
        rid, attempt, data = groups[file]
        if data["total_count"] != len(data["jobs"]):
            return False
        for name in names:
            matches = [c for c in checks["check_runs"] if c["name"] == name]
            jobs = [j for j in data["jobs"] if j["name"] == name]
            if len(matches) != 1 or len(jobs) != 1:
                return False
            check, job = matches[0], jobs[0]
            if not (
                _positive_id(check["id"])
                and check["app"]["id"] == ACTIONS_APP
                and check["status"] == job["status"] == "completed"
                and check["conclusion"] == job["conclusion"] == "success"
                and check["head_sha"] == job["head_sha"] == head
                and job["run_id"] == rid
                and job["id"] == check["id"]
                and job["run_attempt"] == attempt
                and job["check_run_url"] == f"https://api.github.com/{ROOT}/check-runs/{check['id']}"
            ):
                return False
    return True


def _environment(env, selectors, secrets, writers):
    if env["can_admins_bypass"] is not False:
        return set()
    policy = env["deployment_branch_policy"]
    if policy != {"custom_branch_policies": True, "protected_branches": False}:
        return set()
    if selectors["total_count"] != 1 or [(p["name"], p["type"]) for p in selectors["branch_policies"]] != [
        ("main", "branch")
    ]:
        return set()
    if type(secrets["total_count"]) is not int or secrets["total_count"] != 0 or secrets["secrets"] != []:
        return set()
    rules = [rule for rule in env["protection_rules"] if rule["type"] == "required_reviewers"]
    if len(rules) != 1 or rules[0]["prevent_self_review"] is not True:
        return set()
    ids = set()
    for entry in rules[0]["reviewers"]:
        if entry["type"] != "User":
            return set()  # Team membership and nested membership are unqualified.
        ids.add(_human_id(entry["reviewer"]))
    return ids if ids <= writers else set()


OWNER_PATHS = frozenset(
    """
/.github/CODEOWNERS /.github/workflows/ /action.yml /.github/*.lock
/.github/qualification-requirements.txt /pyproject.toml /scripts/ /release/verifier/
/release/governance/ /release/qualification/ /release/records/ /release/custody/
/release/recover.py /src/wolftrap/ /tests/ /docs/ /SECURITY.md /LICENSE
""".split()
)


def _owner_file(contents, errors, collaborators):
    if errors["errors"] != [] or contents["type"] != "file" or contents["encoding"] != "base64":
        return False
    if contents["path"] != ".github/CODEOWNERS" or not 0 < contents["size"] <= 16384:
        return False
    raw = base64.b64decode("".join(contents["content"].splitlines()), validate=True)
    if len(raw) != contents["size"]:
        return False
    entries = [
        line.split()
        for line in raw.decode("utf8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not entries or entries[0][0] != "*":
        return False
    writers = {
        p["login"].casefold()
        for p in collaborators
        if p["permissions"]["push"] is True and p["type"] == "User"
    }
    seen = set()
    for fields in entries:
        pattern, *handles = fields
        if (pattern != "*" and pattern not in OWNER_PATHS) or pattern in seen:
            raise ValueError("unqualified ownership pattern")
        seen.add(pattern)
        if not handles:
            return False
        for handle in handles:
            if not re.fullmatch(r"@[A-Za-z0-9-]+", handle):
                raise ValueError("unqualified owner type")
            if handle[1:].casefold() not in writers:
                return False
    return True


def _bound(pr, head, tree):
    if (
        type(pr) is not int
        or not 0 < pr < 10**9
        or not all(type(value) is str and SHA.fullmatch(value) for value in (head, tree))
    ):
        raise ValueError("expected a positive PR number and full lowercase Git object IDs")


def _inspect(get, pr, head, tree):
    _bound(pr, head, tree)
    a = Audit(get)
    user = a.read("authenticated_user", "user")
    repo = a.read("repository", ROOT)
    branch_path = f"{ROOT}/branches/main"
    branch = a.read("main", branch_path)
    pr_path = f"{ROOT}/pulls/{pr}"
    pull = a.read("pull_request", pr_path)
    commit = a.read("git_commit", f"{ROOT}/git/commits/{head}")
    protection = a.read("classic_protection", f"{branch_path}/protection")
    rules = a.read("effective_rules", f"{ROOT}/rules/branches/main{LIMIT}", list)
    rulesets = a.read(
        "rulesets_including_parents", f"{ROOT}/rulesets?includes_parents=true&per_page=100", list
    )
    collaborators = a.read("collaborators", f"{ROOT}/collaborators{LIMIT}", list)
    reviews = a.read("reviews", f"{pr_path}/reviews{LIMIT}", list)
    workflows = a.read("workflow_token", f"{ROOT}/actions/permissions/workflow")
    actions = a.read("actions_permissions", f"{ROOT}/actions/permissions")
    immutable = a.read("immutable_releases", f"{ROOT}/immutable-releases")
    environments = a.read("environments", f"{ROOT}/environments{LIMIT}")
    settings = []
    for name in ENVIRONMENTS:
        path = f"{ROOT}/environments/{name}"
        settings.append(
            (
                a.read(name, path),
                a.read(name + "_branches", path + "/deployment-branch-policies" + LIMIT),
                a.read(name + "_secrets", path + "/secrets" + LIMIT),
            )
        )
    main_head = _field(_field(branch, "commit", dict), "sha", str)
    if isinstance(main_head, str) and SHA.fullmatch(main_head):
        owners = a.read("owner_file", f"{ROOT}/contents/.github/CODEOWNERS?ref={main_head}")
        errors = a.read("owner_errors", f"{ROOT}/codeowners/errors?ref={main_head}")
    else:
        owners = errors = None

    checks = a.read("exact_checks", f"{ROOT}/commits/{head}/check-runs?filter=latest&per_page=100")
    groups = {file: _workflow_jobs(a, pr, head, file) for file in WORKFLOWS}
    final_pull = a.read("final_pull_request", pr_path)
    final_main = a.read("final_main", branch_path)
    need = a.require
    need(
        "repository_identity",
        ["authenticated_user", "repository"],
        lambda: _human_id(user) > 0
        and repo["id"] == REPOSITORY_ID
        and repo["full_name"] == REPOSITORY
        and repo["private"] is False
        and repo["default_branch"] == "main",
        "Authenticated github.com user and pinned public repository ID, name and default branch.",
    )
    need(
        "source_revision",
        ["git_commit", "pull_request", "final_pull_request", "main", "final_main"],
        lambda: pull == final_pull
        and branch["commit"]["sha"] == final_main["commit"]["sha"]
        and pull["number"] == pr
        and pull["head"]["sha"] == commit["sha"] == head
        and commit["tree"]["sha"] == tree
        and pull["base"]["repo"]["id"] == REPOSITORY_ID
        and pull["head"]["repo"]["id"] == REPOSITORY_ID,
        "PR head, repository IDs and Git commit/tree checked at collection. Main and PR read again.",
    )
    need(
        "protected_main",
        ["main"],
        lambda: branch["name"] == "main" and branch["protected"] is True,
        "GitHub protected flag on the default branch.",
    )
    need(
        "release_source",
        ["pull_request", "main", "git_commit"],
        lambda: pull["merged"] is True
        and pull["draft"] is False
        and pull["state"] == "closed"
        and pull["base"]["ref"] == "main"
        and pull["merge_commit_sha"] == main_head
        and branch["commit"]["commit"]["tree"]["sha"] == tree
        and main_head == head,
        "Merged PR to main with identical reviewed commit, tree and current protected-branch source selection.",
    )
    need(
        "independent_review",
        ["pull_request", "reviews", "collaborators"],
        lambda: _review_approved(reviews, _writers(collaborators), _human_id(pull["user"]), head),
        "Current-head approval by a distinct human with present write access; latest decisive reviews.",
    )
    need(
        "classic_profile",
        ["effective_rules", "rulesets_including_parents"],
        lambda: rules == [] and rulesets == [],
        "This profile can interpret classic protection only. Additional rulesets require separate review.",
    )
    if a.controls["classic_profile"]["state"] == "FAILED":
        a.controls["classic_profile"]["state"] = "UNKNOWN"
    need(
        "required_check_runs",
        ["exact_checks", *WORKFLOWS],
        lambda: _completed_checks(groups, checks, head),
        "GitHub Actions app, check IDs, job IDs/attempts, workflow paths, successful PR runs, exact head and main target.",
    )
    need(
        "mandatory_checks",
        ["classic_protection"],
        lambda: protection["required_status_checks"]["strict"] is True
        and all(
            [r["app_id"] for r in protection["required_status_checks"]["checks"] if r["context"] == name]
            == [ACTIONS_APP]
            for name in CHECKS
        ),
        "Strict, up-to-date required checks bound to the GitHub Actions App and declared contexts.",
    )
    need(
        "owner_review",
        ["classic_protection", "owner_file", "owner_errors", "collaborators"],
        lambda: protection["required_pull_request_reviews"]["require_code_owner_reviews"] is True
        and _owner_file(owners, errors, collaborators),
        "Required CODEOWNERS review, catch-all ownership and bounded optional overrides assigned to current human writers on exact main.",
    )
    need(
        "stale_review_dismissal",
        ["classic_protection"],
        lambda: protection["required_pull_request_reviews"]["dismiss_stale_reviews"] is True
        and protection["required_pull_request_reviews"]["require_last_push_approval"] is True
        and type(protection["required_pull_request_reviews"]["required_approving_review_count"]) is int
        and protection["required_pull_request_reviews"]["required_approving_review_count"] >= 1,
        "Protected pull requests require an independent latest-push approval and dismiss stale reviews.",
    )
    need(
        "administrator_bypass",
        ["classic_protection"],
        lambda: protection["enforce_admins"]["enabled"] is True
        and all(
            protection["required_pull_request_reviews"]["bypass_pull_request_allowances"][k] == []
            for k in ("users", "teams", "apps")
        ),
        "Administrators subject to branch protection and no listed actor bypass allowances.",
    )
    need(
        "force_push_and_deletion",
        ["classic_protection"],
        lambda: all(protection[k]["enabled"] is False for k in ("allow_force_pushes", "allow_deletions")),
        "Classic main protection explicitly disables force pushes and branch deletion.",
    )
    env_keys = [name + suffix for name in ENVIRONMENTS for suffix in ("", "_branches", "_secrets")]

    def envs_ready():
        writers = _writers(collaborators)
        groups = [_environment(*setting, writers) for setting in settings]
        return (
            all(name in [e["name"] for e in environments["environments"]] for name in ENVIRONMENTS)
            and all(settings[i][0]["name"] == name for i, name in enumerate(ENVIRONMENTS))
            and all(groups)
            and groups[0].isdisjoint(groups[1])
        )

    if (
        environments is not None
        and environments.get("total_count") == 0
        and environments.get("environments") == []
    ):
        need(
            "release_environments",
            ["environments"],
            lambda: False,
            "GitHub returned a complete empty environment list.",
        )
    else:
        need(
            "release_environments",
            ["environments", "collaborators", *env_keys],
            envs_ready,
            "Separate main-only approval environments with distinct named human writers, no self-review, admin bypass or stored secrets.",
        )
    need(
        "workflow_permissions",
        ["workflow_token", "actions_permissions"],
        lambda: actions["enabled"] is True
        and actions["allowed_actions"] in ("all", "local_only", "selected")
        and workflows["default_workflow_permissions"] == "read"
        and workflows["can_approve_pull_request_reviews"] is False,
        "Actions enabled, workflow tokens read-only by default, workflow PR approvals disabled.",
    )
    need(
        "immutable_releases",
        ["immutable_releases"],
        lambda: immutable["enabled"] is True,
        "GitHub immutable-release policy enabled.",
    )
    a.controls["publication_permissions"] = {
        "state": "UNKNOWN",
        "basis": "Repository settings cannot establish every credential grant, direct publication bypass or authorization for this release.",
    }

    branch_summary = _field(_field(branch, "protection", dict), "required_status_checks", dict)
    contexts = _field(branch_summary, "contexts", list)
    pr_protection = _field(protection, "required_pull_request_reviews", dict)
    observations = {
        "caller_has_repository_admin_role": _field(_field(repo, "permissions", dict), "admin", bool),
        "main_protected": _field(branch, "protected", bool),
        "main_commit": main_head if isinstance(main_head, str) and SHA.fullmatch(main_head) else None,
        "review_count": len(reviews) if reviews is not None else None,
        "pull_request_draft": _field(pull, "draft", bool),
        "environment_count": _field(environments, "total_count", int),
        "branch_summary_required_check_count": len(contexts) if contexts is not None else None,
        "required_approving_reviews": _field(pr_protection, "required_approving_review_count", int),
        "dismiss_stale_reviews": _field(pr_protection, "dismiss_stale_reviews", bool),
        "require_code_owner_reviews": _field(pr_protection, "require_code_owner_reviews", bool),
        "require_last_push_approval": _field(pr_protection, "require_last_push_approval", bool),
        "enforce_admins": _field(_field(protection, "enforce_admins", dict), "enabled", bool),
        "allow_force_pushes": _field(_field(protection, "allow_force_pushes", dict), "enabled", bool),
        "allow_deletions": _field(_field(protection, "allow_deletions", dict), "enabled", bool),
        "immutable_releases_enabled": _field(immutable, "enabled", bool),
        "workflow_approves_pull_requests": _field(workflows, "can_approve_pull_request_reviews", bool),
        "effective_rule_count": len(rules) if rules is not None else None,
        "repository_and_inherited_ruleset_count": len(rulesets) if rulesets is not None else None,
        "visible_collaborator_count": len(collaborators) if collaborators is not None else None,
        "readable_environment_secret_counts": {
            name: _field(setting[2], "total_count", int) for name, setting in zip(ENVIRONMENTS, settings)
        },
        "default_token_permissions": (
            (workflows or {}).get("default_workflow_permissions")
            if (workflows or {}).get("default_workflow_permissions") in ("read", "write")
            else None
        ),
        "per_release_publication_authority": "UNVERIFIED",
    }
    return {
        "schema": "awooo.github-governance/v1",
        "repository": REPOSITORY,
        "status": (
            "GOVERNANCE_VERIFIED" if all(v["state"] == "VERIFIED" for v in a.controls.values()) else "BLOCKED"
        ),
        "source": {"commit": head, "tree": tree, "pull_request": pr},
        "controls": a.controls,
        "observations": observations,
        "api": a.api,
    }


def collect(pr: int, expected_head: str, expected_tree: str) -> dict:
    """Read the pinned GitHub API endpoints directly. No caller-supplied collection or credentials in evidence."""
    deadline = time.monotonic() + 90

    def get(path):
        return _get(path) if time.monotonic() < deadline else Reply()

    return _inspect(get, pr, expected_head, expected_tree)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    args = parser.parse_args(argv)
    try:
        report = collect(args.pr, args.expected_head, args.expected_tree)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "GOVERNANCE_VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())

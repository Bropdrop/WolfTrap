"""Report observed production gates or compare normalized release claims. No release effects."""

import argparse
from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent


def checked_module(path):
    """Load only fixed files from this reviewed checkout under python -I."""
    spec = spec_from_file_location(path.stem, path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


io = checked_module(HERE.parent / "verifier/release_io.py")

SCHEMA = "awooo.production-readiness/v1"
REPO = "GovernableIntelligence/WolfTrap"
REPO_ID = "1436465132"
WORKFLOW = ".github/workflows/protected-release.yml"
ISSUER = "https://token.actions.githubusercontent.com"
SLSA = "https://slsa.dev/provenance/v1"
HEX40 = re.compile("[0-9a-f]{40}")
HEX64 = re.compile("[0-9a-f]{64}")
VERSION = re.compile(r"(?:0|[1-9][0-9]{0,5})(?:\.(?:0|[1-9][0-9]{0,5})){2}")
DIGESTS = (
    "workflow_sha256",
    "build_inputs_sha256",
    "dependency_lock_sha256",
    "build_parameters_sha256",
    "wheel_sha256",
    "sbom_sha256",
    "manifest_sha256",
    "provenance_sha256",
)
RELEASE_FIELDS = {"commit", "tree", "sequence", "version", *DIGESTS}
PHASES = {
    "review": "source-review",
    "sign": "awooo-release-review",
    "publish": "awooo-publication-review",
}


def matches(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def positive_int(value):
    return type(value) is int and 0 < value < 2**63


def fields(obj, names):
    return type(obj) is dict and set(obj) == set(names)


def valid_release(obj):
    return (
        fields(obj, RELEASE_FIELDS)
        and matches(HEX40, obj["commit"])
        and matches(HEX40, obj["tree"])
        and positive_int(obj["sequence"])
        and matches(VERSION, obj["version"])
        and all(matches(HEX64, obj[name]) for name in DIGESTS)
    )


def valid_policy(policy):
    return (
        fields(
            policy,
            {"schema", "release", "dispatch", "approvers", "valid_from", "valid_until", "minimum_sequence"},
        )
        and policy["schema"] == "awooo.release-binding-policy/v1"
        and valid_release(policy["release"])
        and fields(policy["dispatch"], {"requester_id", "author_id", "run_id", "run_attempt"})
        and all(positive_int(value) for value in policy["dispatch"].values())
        and positive_int(policy["valid_from"])
        and positive_int(policy["valid_until"])
        and policy["valid_from"] < policy["valid_until"]
        and positive_int(policy["minimum_sequence"])
        and fields(policy["approvers"], PHASES)
        and all(
            type(ids) is list
            and 0 < len(ids) <= 32
            and all(positive_int(i) for i in ids)
            and len(set(ids)) == len(ids)
            for ids in policy["approvers"].values()
        )
        and set(policy["approvers"]["publish"]).isdisjoint(policy["approvers"]["sign"])
    )


def compare_bindings(policy, claims, as_of):
    """Compare an independently pinned policy to a projection. Neither file is a credential."""
    result = {
        "schema": "awooo.release-binding-comparison/v1",
        "status": "INCONCLUSIVE",
        "reasons": [],
        "release_authorized": False,
    }
    if not valid_policy(policy) or not positive_int(as_of):
        result["reasons"].append("invalid-policy-or-time")
        return result
    claim_fields = {"schema", "release", "builder", "requester_id", "author_id", "approvals"}
    if not (
        fields(claims, claim_fields)
        and claims["schema"] == "awooo.release-claims/v1"
        and valid_release(claims["release"])
        and fields(claims["approvals"], PHASES)
        and positive_int(claims["requester_id"])
        and positive_int(claims["author_id"])
    ):
        result["reasons"].append("incomplete-or-unsupported-claims")
        return result
    release = policy["release"]
    reasons = result["reasons"]
    dispatch = policy["dispatch"]
    for actor in ("requester_id", "author_id"):
        if claims[actor] != dispatch[actor]:
            reasons.append("unauthorized-" + actor)
    if not policy["valid_from"] <= as_of < policy["valid_until"]:
        reasons.append("expired-or-future-policy")
    if claims["release"]["sequence"] < policy["minimum_sequence"]:
        reasons.append("rollback")
    for key in sorted(RELEASE_FIELDS):
        if claims["release"][key] != release[key]:
            reasons.append("release-" + key)
    builder = {
        "issuer": ISSUER,
        "repository": REPO,
        "repository_id": REPO_ID,
        "event": "workflow_dispatch",
        "run_id": dispatch["run_id"],
        "run_attempt": dispatch["run_attempt"],
        "ref": "refs/heads/main",
        "ref_protected": True,
        "runner_environment": "github-hosted",
        "workflow_path": WORKFLOW,
        "workflow_revision": release["commit"],
        "source_revision": release["commit"],
        "identity": f"https://github.com/{REPO}/{WORKFLOW}@refs/heads/main",
        "predicate_type": SLSA,
    }
    if not fields(claims["builder"], builder):
        reasons.append("incomplete-builder")
    else:
        for key, expected in builder.items():
            actual = claims["builder"][key]
            if type(actual) is not type(expected) or actual != expected:
                reasons.append("builder-" + key)
    # Distinct review/deployment records must cover the candidate each approver saw.
    seen_records = set()
    for phase, purpose in PHASES.items():
        record = claims["approvals"][phase]
        bound = {"purpose": purpose, "commit": release["commit"], "tree": release["tree"]}
        if phase != "review":
            bound.update(
                run_id=dispatch["run_id"],
                run_attempt=dispatch["run_attempt"],
                manifest_sha256=release["manifest_sha256"],
                sequence=release["sequence"],
                version=release["version"],
            )
        if not fields(record, {*bound, "record_id", "reviewer_id"}):
            reasons.append("incomplete-" + phase)
            continue
        actor = record["reviewer_id"]
        record_id = record["record_id"]
        if (
            not positive_int(record_id)
            or (phase != "review" and record_id in seen_records)
            or not positive_int(actor)
            or actor not in policy["approvers"][phase]
            or actor in {claims["requester_id"], claims["author_id"]}
        ):
            reasons.append("unapproved-" + phase)
        if phase != "review" and positive_int(record_id):
            seen_records.add(record_id)
        if any(type(record[k]) is not type(v) or record[k] != v for k, v in bound.items()):
            reasons.append("misbound-" + phase)
    result["status"] = "MISMATCH" if reasons else "MATCHED_BINDINGS"
    return result


# Each requirement has a narrowly defined source. Future evidence types need reviewed adapters.
GITHUB = {
    "repository_identity": "repository_identity",
    "exact_source_revision": "source_revision",
    "independent_source_review": "independent_review",
    "protected_production_branch": "protected_main",
    "reviewed_production_revision": "release_source",
    "supported_protection_profile": "classic_profile",
    "required_checks": "mandatory_checks",
    "exact_head_required_checks": "required_check_runs",
    "immutable_release_configuration": "immutable_releases",
    "code_owner_review": "owner_review",
    "dismiss_stale_reviews": "stale_review_dismissal",
    "administrator_bypass_restricted": "administrator_bypass",
    "force_push_and_deletion_restricted": "force_push_and_deletion",
    "controlled_release_environments": "release_environments",
    "restricted_workflow_permissions": "workflow_permissions",
    "restricted_publication_permissions": "publication_permissions",
}
REQUIRED = {
    "authenticated_production_builder": "No independently verified protected-build attestation.",
    "authorized_release_signer": "Production signing is disabled.",
    "release_version_and_sequence": "No authenticated current version and sequence authorization.",
    "explicit_publication_approval": "No independent release-manifest-bound publication approval.",
    "subscriber_trust_roots": "No independently provisioned production subscriber root.",
    "reproducible_tested_artifacts": "Production artifact digests lack independent rebuild evidence.",
    "durable_verified_custody": "No independently controlled production custody receipt.",
    "revocation_and_rollback": "No authenticated fresh production withdrawal and rollback policy.",
    "qualified_platform_installation": "No verified production release installation on required hosts.",
    "approved_release_documentation": "No authenticated approval of candidate release documentation.",
    "naming_clearance": "No independent naming clearance decision for issue 21.",
}


def fixture_summary(directory, head, tree):
    """Read only the bounded evaluation report. A digest identifies the supplied bytes."""
    try:
        raw = io.file_bytes(directory / "qualification.json", io.DOC_LIMIT)
        q = io.parse(raw)
    except (OSError, io.Verdict):
        return {"state": "INVALID_OR_MISSING"}
    if not (
        type(q) is dict
        and q.get("schema") == "awooo.release-qualification/v1"
        and (q.get("commit"), q.get("tree")) == (head, tree)
        and q.get("status") == "VERIFIED_EVALUATION_ONLY"
        and q.get("production") == "BLOCKED"
        and q.get("two_independent_builds") is True
        and q.get("verified_before_install") is True
        and type(q.get("expectation_mismatches")) is int
        and q["expectation_mismatches"] == 0
        and all(matches(HEX64, q.get(k)) for k in ("manifest_sha256", "wheel_sha256", "sbom_sha256"))
    ):
        return {"state": "INVALID_OR_MISSING"}
    return {
        "state": "FIXTURE_REPORTED",
        "report_sha256": sha256(raw).hexdigest(),
        "wheel_sha256": q["wheel_sha256"],
        "sbom_sha256": q["sbom_sha256"],
        "manifest_sha256": q["manifest_sha256"],
    }


def assess(pr, head, tree, *, offline, qualification_dir=None):
    source = {"commit": head, "tree": tree, "pull_request": pr}
    observed = {}
    if not offline:
        # Installed checkout is the review boundary; no caller-supplied report path or adapter.
        report = checked_module(HERE / "preflight.py").collect(pr, head, tree)
        if (
            type(report) is dict
            and report.get("schema") == "awooo.github-governance/v1"
            and report.get("repository") == REPO
            and report.get("source") == source
            and type(report.get("controls")) is dict
        ):
            observed = report["controls"]
    conditions = {}
    for gate, name in GITHUB.items():
        row = observed.get(name)
        if type(row) is dict and row.get("state") in ("VERIFIED", "FAILED"):
            state = "SATISFIED" if row["state"] == "VERIFIED" else "UNSATISFIED"
            provenance = "GITHUB_API"
        else:
            state = provenance = "UNKNOWN"
        conditions[gate] = {"state": state, "provenance": provenance, "control": name}
    for gate, reason in REQUIRED.items():
        conditions[gate] = {"state": "UNSATISFIED", "provenance": "IMPLEMENTATION_LIMIT", "basis": reason}
    return {
        "schema": SCHEMA,
        "source": source,
        "status": "BLOCKED",
        "release_authorized": False,
        "production_signing_enabled": False,
        "github_observation": "OFFLINE" if offline else "LIVE_QUERY",
        "conditions": conditions,
        "unmet": sorted(k for k, v in conditions.items() if v["state"] != "SATISFIED"),
        "evaluation_evidence": (
            fixture_summary(qualification_dir, head, tree)
            if qualification_dir is not None
            else {"state": "NOT_PROVIDED"}
        ),
    }


def cli(argv):
    if argv[:1] == ["compare"]:
        arg = argparse.ArgumentParser(
            description="Compare projected claims. A match cannot authorize release."
        )
        arg.add_argument("--policy", required=True, type=Path)
        arg.add_argument("--policy-sha256", required=True)
        arg.add_argument("--claims", required=True, type=Path)
        arg.add_argument("--as-of", required=True, type=int, help="Independent UTC epoch seconds.")
        args = arg.parse_args(argv[1:])
        try:
            policy = io.file_bytes(args.policy, io.DOC_LIMIT)
            if sha256(policy).hexdigest() != args.policy_sha256:
                raise io.Verdict("REJECTED", "policy-pin")
            result = compare_bindings(
                io.parse(policy), io.parse(io.file_bytes(args.claims, io.DOC_LIMIT)), args.as_of
            )
        except (OSError, io.Verdict) as exc:
            result = {
                "schema": "awooo.release-binding-comparison/v1",
                "status": "INCONCLUSIVE",
                "release_authorized": False,
                "reasons": [getattr(exc, "reason", "unavailable-file")],
            }
        print(json.dumps(result, sort_keys=True, indent=2))
        return {"MATCHED_BINDINGS": 0, "MISMATCH": 1, "INCONCLUSIVE": 2}[result["status"]]
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument("--pr", type=int)
    arg.add_argument("--expected-head", required=True)
    arg.add_argument("--expected-tree", required=True)
    arg.add_argument(
        "--offline", action="store_true", help="Skip GitHub queries; live controls remain UNKNOWN."
    )
    arg.add_argument("--qualification-dir", type=Path, help="Optional evaluation-only report directory.")
    args = arg.parse_args(argv)
    if not (matches(HEX40, args.expected_head) and matches(HEX40, args.expected_tree)):
        arg.error("expected full lowercase Git commit and tree")
    if (args.pr is None and not args.offline) or (args.pr is not None and not 0 < args.pr < 10**9):
        arg.error("supply a positive PR number for a live query")
    result = assess(
        args.pr,
        args.expected_head,
        args.expected_tree,
        offline=args.offline,
        qualification_dir=args.qualification_dir,
    )
    print(json.dumps(result, sort_keys=True, indent=2))
    return 1


if __name__ == "__main__":
    raise SystemExit(cli(sys.argv[1:]))

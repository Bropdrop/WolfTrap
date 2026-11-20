"""Independent synthetic expectations for the production policy boundary and offline report."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "release/governance/readiness.py"
spec = importlib.util.spec_from_file_location("governed_readiness", SCRIPT)
readiness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(readiness)
HEAD = "a" * 40
TREE = "b" * 40
NOW = 200
REPO = "GovernableIntelligence/WolfTrap"


def fixture():
    artifact = {"commit": HEAD, "tree": TREE, "sequence": 5, "version": "1.2.0"}
    for name in (
        "workflow",
        "build_inputs",
        "dependency_lock",
        "build_parameters",
        "wheel",
        "sbom",
        "manifest",
        "provenance",
    ):
        artifact[name + "_sha256"] = hashlib.sha256(name.encode()).hexdigest()
    policy = {
        "schema": "awooo.release-binding-policy/v1",
        "release": artifact,
        "approvers": {"review": [15], "sign": [16], "publish": [17]},
        "dispatch": {"requester_id": 11, "author_id": 12, "run_id": 41, "run_attempt": 1},
        "valid_from": 100,
        "valid_until": 300,
        "minimum_sequence": 4,
    }
    claims = {
        "schema": "awooo.release-claims/v1",
        "requester_id": 11,
        "author_id": 12,
        "release": copy.deepcopy(artifact),
        "builder": {
            "issuer": "https://token.actions.githubusercontent.com",
            "repository": REPO,
            "repository_id": "1436465132",
            "event": "workflow_dispatch",
            "run_id": 41,
            "run_attempt": 1,
            "ref": "refs/heads/main",
            "ref_protected": True,
            "runner_environment": "github-hosted",
            "workflow_path": ".github/workflows/protected-release.yml",
            "workflow_revision": HEAD,
            "source_revision": HEAD,
            "identity": "https://github.com/GovernableIntelligence/WolfTrap/.github/workflows/protected-release.yml@refs/heads/main",
            "predicate_type": "https://slsa.dev/provenance/v1",
        },
        "approvals": {
            "review": {
                "purpose": "source-review",
                "record_id": 51,
                "reviewer_id": 15,
                "commit": HEAD,
                "tree": TREE,
            },
            "sign": {
                "purpose": "awooo-release-review",
                "record_id": 52,
                "reviewer_id": 16,
                "commit": HEAD,
                "tree": TREE,
                "version": "1.2.0",
                "sequence": 5,
                "run_id": 41,
                "run_attempt": 1,
                "manifest_sha256": artifact["manifest_sha256"],
            },
            "publish": {
                "purpose": "awooo-publication-review",
                "record_id": 53,
                "reviewer_id": 17,
                "commit": HEAD,
                "tree": TREE,
                "version": "1.2.0",
                "sequence": 5,
                "run_id": 41,
                "run_attempt": 1,
                "manifest_sha256": artifact["manifest_sha256"],
            },
        },
    }
    return policy, claims


def put(obj, path, value):
    *parents, leaf = path.split(".")
    for parent in parents:
        obj = obj[parent]
    obj[leaf] = value


# Expected outcomes are fixed before calling either the production comparator or mutants.
def cases():
    policy, claims = fixture()
    yield "reviewed binding", policy, claims, NOW, "MATCHED_BINDINGS"
    policy, claims = fixture()
    for doc in (
        policy["release"],
        claims["release"],
        claims["approvals"]["sign"],
        claims["approvals"]["publish"],
    ):
        doc.update(version="1.3.0", sequence=6)
    yield "authorized upgrade", policy, claims, NOW, "MATCHED_BINDINGS"
    for path, value in (
        ("builder.event", "pull_request_target"),
        ("builder.run_id", 99),
        ("approvals.sign.run_id", 99),
        ("builder.run_attempt", 2),
        ("approvals.publish.run_attempt", 2),
        ("requester_id", 99),
        ("author_id", 99),
        ("builder.event", "pull_request"),
        ("builder.event", "push"),
        ("builder.ref", "refs/tags/v1.2.0"),
        ("builder.ref_protected", 1),
        ("builder.ref_protected", False),
        ("builder.repository", "fictional/WolfTrap"),
        ("builder.repository_id", "22"),
        ("builder.issuer", "https://issuer.invalid"),
        ("builder.identity", "copied-display-name"),
        ("builder.workflow_path", ".github/workflows/changed.yml"),
        ("builder.workflow_revision", "c" * 40),
        ("builder.source_revision", "c" * 40),
        ("builder.predicate_type", "unverified"),
        ("builder.runner_environment", "self-hosted"),
        ("release.commit", "c" * 40),
        ("release.tree", "c" * 40),
        ("release.sequence", 3),
        ("release.version", "1.2.1"),
        ("approvals.sign.reviewer_id", 11),
        ("approvals.sign.record_id", True),
        ("approvals.publish.record_id", 52),
        ("approvals.publish.manifest_sha256", "c" * 64),
        ("approvals.sign.sequence", True),
        ("approvals.publish.version", "1.2.1"),
        ("approvals.sign.purpose", "source-review"),
        ("approvals.review.tree", "c" * 40),
        ("approvals.review.reviewer_id", 99),
        ("author_id", 15),
        ("requester_id", 17),
        *(
            (f"release.{n}_sha256", "c" * 64)
            for n in (
                "workflow",
                "dependency_lock",
                "build_inputs",
                "build_parameters",
                "manifest",
                "provenance",
                "sbom",
                "wheel",
            )
        ),
    ):
        policy, claims = fixture()
        put(claims, path, value)
        yield f"{path}={value}", policy, claims, NOW, "MISMATCH"
    for path, value in (
        ("approvals.review", None),
        ("release.tree", False),
        ("requester_id", True),
        ("release.sequence", True),
        ("release.wheel_sha256", "unavailable"),
    ):
        policy, claims = fixture()
        put(claims, path, value)
        # Missing fields inside a review record identify a mismatched approval projection.
        expected = "MISMATCH" if path == "approvals.review" else "INCONCLUSIVE"
        yield path, policy, claims, NOW, expected
    policy, claims = fixture()
    policy["minimum_sequence"] = 6
    yield "rollback floor", policy, claims, NOW, "MISMATCH"
    policy, claims = fixture()
    yield "expired policy", policy, claims, 300, "MISMATCH"
    yield "future policy", policy, claims, 99, "MISMATCH"
    policy, claims = fixture()
    policy["approvers"]["sign"] = [True]
    yield "invalid operator roster", policy, claims, NOW, "INCONCLUSIVE"
    policy, claims = fixture()
    policy["approvers"]["publish"].append(16)
    yield "overlap between release and publication approvers", policy, claims, NOW, "INCONCLUSIVE"


def canonical(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


class ProductionReadiness(unittest.TestCase):
    def test_projected_bindings(self):
        for name, policy, claims, clock, expected in cases():
            with self.subTest(name=name):
                result = readiness.compare_bindings(policy, claims, clock)
                self.assertEqual(result["status"], expected)
                self.assertIs(result["release_authorized"], False)

    def test_defective_comparators_are_detected(self):
        def ignored(path):
            def compare(policy, claims, clock):
                _, valid_claims = fixture()
                if path == "minimum_sequence":
                    policy["minimum_sequence"] = 1
                elif path == "as_of":
                    clock = NOW
                else:
                    value = valid_claims
                    for part in path.split("."):
                        value = value[part]
                    put(claims, path, value)
                return readiness.compare_bindings(policy, claims, clock)["status"]

            return compare

        comparators = {
            "always approve": lambda *_: "MATCHED_BINDINGS",
            "always reject": lambda *_: "MISMATCH",
            "ignore dispatch event": ignored("builder.event"),
            "trust unregistered repository name": ignored("builder.repository_id"),
            "ignore rollback floor": ignored("minimum_sequence"),
            "ignore policy freshness": ignored("as_of"),
            "ignore publication approver": ignored("approvals.publish.reviewer_id"),
            "ignore wheel bytes": ignored("release.wheel_sha256"),
        }
        # Include a fabricated reviewer in addition to cases where a real approver is the requester.
        mutant_cases = list(cases())
        policy, claims = fixture()
        claims["approvals"]["publish"]["reviewer_id"] = 99
        mutant_cases.append(("unregistered publisher", policy, claims, NOW, "MISMATCH"))
        for mutant, compare in comparators.items():
            with self.subTest(mutant=mutant):
                failures = [
                    name
                    for name, p, c, t, exp in mutant_cases
                    if compare(copy.deepcopy(p), copy.deepcopy(c), t) != exp
                ]
                self.assertTrue(failures)

    def test_pinned_policy_and_ambiguous_or_self_selected_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            p, c = fixture()
            approved = canonical(p)
            (root / "policy").write_bytes(approved)
            (root / "claims").write_bytes(canonical(c))
            args = [
                sys.executable,
                "-I",
                str(SCRIPT),
                "compare",
                "--policy",
                str(root / "policy"),
                "--claims",
                str(root / "claims"),
                "--as-of",
                str(NOW),
                "--policy-sha256",
            ]

            def execute(pin, code, status):
                r = subprocess.run([*args, pin], capture_output=True, check=False)
                self.assertEqual(r.returncode, code, r.stderr)
                result = json.loads(r.stdout)
                self.assertEqual(result["status"], status)
                self.assertFalse(result["release_authorized"])

            digest = hashlib.sha256(approved).hexdigest()
            execute(digest, 0, "MATCHED_BINDINGS")
            execute("0" * 64, 2, "INCONCLUSIVE")
            c["builder"]["event"] = "pull_request"
            (root / "claims").write_bytes(canonical(c))
            execute(digest, 1, "MISMATCH")
            (root / "claims").write_bytes(b'{"schema":1,"schema":2}')
            execute(digest, 2, "INCONCLUSIVE")
            (root / "claims").unlink()
            (root / "claims").symlink_to(root / "policy")
            execute(digest, 2, "INCONCLUSIVE")

    def test_offline_report_never_promotes_evaluation_artifacts(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            q = {
                "schema": "awooo.release-qualification/v1",
                "production": "BLOCKED",
                "status": "VERIFIED_EVALUATION_ONLY",
                "two_independent_builds": True,
                "commit": HEAD,
                "tree": TREE,
                "verified_before_install": True,
                "expectation_mismatches": 0,
                **{k: "d" * 64 for k in ("manifest_sha256", "wheel_sha256", "sbom_sha256")},
            }
            path = directory / "qualification.json"
            for state, contents in (
                ("FIXTURE_REPORTED", q),
                ("INVALID_OR_MISSING", dict(q, tree="e" * 40)),
                ("INVALID_OR_MISSING", dict(q, production="VERIFIED")),
                ("INVALID_OR_MISSING", {}),
            ):
                with self.subTest(expected=state):
                    path.write_bytes(canonical(contents))
                    r = readiness.assess(None, HEAD, TREE, offline=True, qualification_dir=directory)
                    self.assertEqual(r["status"], "BLOCKED")
                    self.assertEqual(r["evaluation_evidence"]["state"], state)
                    self.assertIs(r["release_authorized"], False)
                    self.assertEqual(r["conditions"]["independent_source_review"]["state"], "UNKNOWN")
                    self.assertIn("authorized_release_signer", r["unmet"])
                    self.assertIn("reproducible_tested_artifacts", r["unmet"])

    def test_live_api_scope_even_if_every_github_control_passes(self):
        source = {"commit": HEAD, "tree": TREE, "pull_request": 25}
        response = {
            "schema": "awooo.github-governance/v1",
            "source": source,
            "repository": REPO,
            "controls": {key: {"state": "VERIFIED"} for key in readiness.GITHUB.values()},
        }
        stub = types.SimpleNamespace(collect=mock.Mock(return_value=response))
        with mock.patch.object(readiness, "checked_module", return_value=stub):
            r = readiness.assess(25, HEAD, TREE, offline=False)
            stub.collect.assert_called_once_with(25, HEAD, TREE)
            self.assertEqual(r["conditions"]["independent_source_review"]["state"], "SATISFIED")
            for gate in (
                "authorized_release_signer",
                "qualified_platform_installation",
                "approved_release_documentation",
                "naming_clearance",
                "subscriber_trust_roots",
                "durable_verified_custody",
            ):
                self.assertIn(gate, r["unmet"])
            self.assertEqual(r["status"], "BLOCKED")
            self.assertFalse(r["production_signing_enabled"])
            source.update(tree="f" * 40)
            wrong = readiness.assess(25, HEAD, TREE, offline=False)
            self.assertEqual(wrong["conditions"]["independent_source_review"]["state"], "UNKNOWN")

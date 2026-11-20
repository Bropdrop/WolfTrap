"""Independent source and output expectations for the standalone hosted-evidence comparator."""

from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
import warnings
import zipfile
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("governed_replay", ROOT / "release/replay_governed.py")
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)
from release_io import DOC_LIMIT, encode, sha

HEAD, TREE = "a" * 40, "b" * 40


def fixture():
    rev = {"commit_sha": HEAD, "tree_sha": TREE, "dirty": False, "diff_digest": "sha256:" + sha(b"")}
    unit = {
        "framework": "unittest",
        "run_by_research_engine": True,
        "successful": True,
        "source_stable": True,
        "source_revision": rev,
        "source_revision_end": rev,
        "tests_run": sum(replay.MODULE_FLOORS.values()),
        "tests_per_module": replay.MODULE_FLOORS.copy(),
        "skipped": 0,
        "errors": 0,
        "failures": 0,
        "expected_failures": 0,
        "unexpected_successes": 0,
    }
    custody = {
        "schema": "awooo.custody-exercise/v1",
        "scope": "DISPOSABLE_LOCAL_FIXTURE",
        "status": "VERIFIED_DISPOSABLE_EXERCISE",
        "production_custody": "BLOCKED",
        "cases": [{"name": k, "expected": v, "observed": v} for k, v in replay.CUSTODY_ORACLE.items()],
        "mutants": {k: sorted(v) for k, v in replay.MUTANT_ORACLE.items()},
    }
    ready = {
        "schema": "awooo.production-readiness/v1",
        "status": "BLOCKED",
        "release_authorized": False,
        "production_signing_enabled": False,
        "source": {"commit": HEAD, "tree": TREE, "pull_request": None},
        "github_observation": "OFFLINE",
        "conditions": {
            k: {"state": "UNKNOWN", "provenance": "UNKNOWN", "control": k} for k in replay.REQUIRED_GATES
        },
        "unmet": sorted(replay.REQUIRED_GATES),
        "evaluation_evidence": {"state": "NOT_PROVIDED"},
    }
    summary = {
        "schema": "awooo.governed-qualification/v1",
        "status": "VERIFIED_DISPOSABLE_CONTROLS",
        "production": "BLOCKED",
        "authenticated_production_builder": False,
        "commit": HEAD,
        "tree": TREE,
        "namespace": "loopback-only",
        "qualification_workflow_sha256": sha((ROOT / replay.WORKFLOW).read_bytes()),
        "qualification_workflow": ".github/workflows/governed-release-qualification.yml",
        "legacy_capsule_fixture_workflow": ".github/workflows/release-trust-qualification.yml",
        "byte_identical_replays": ["custody.json", "readiness.json"],
        "governed_unit_tests": unit["tests_run"],
        "workflow_policy_tests": "separate full research discovery",
        "custody_cases": len(custody["cases"]),
        "defective_custody_controls_caught": len(custody["mutants"]),
    }
    return {
        "qualification.json": summary,
        "custody.json": custody,
        "readiness.json": ready,
        "unit-tests.json": unit,
    }


class Nonseekable(io.BytesIO):
    # The hosted ZIP writer emits streamed data descriptors.
    def seek(self, *args):
        raise io.UnsupportedOperation("stream")


class GovernedReplayTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.local = self.root / "local"
        self.local.mkdir()
        self.bundle = self.root / "hosted.zip"

    def create(self, docs=None, *, wrong_manifest=False, omit=None, extra=None):
        docs = fixture() if docs is None else docs
        records = {name: encode(doc) for name, doc in docs.items() if name != "qualification.json"}
        docs["qualification.json"]["sha256"] = {name: sha(raw) for name, raw in records.items()}
        if wrong_manifest:
            docs["qualification.json"]["sha256"]["readiness.json"] = "d" * 64
        records["qualification.json"] = encode(docs["qualification.json"])
        for name, raw in records.items():
            (self.local / name).write_bytes(raw)

        stream = Nonseekable()
        entries = {"governed/" + k: v for k, v in records.items()}
        entries.update({name: b"outside-replay" for name in replay.OTHER})
        if omit is not None:
            del entries[omit]
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as z:
            for name, raw in entries.items():
                z.writestr(name, raw)
            if extra:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", UserWarning)
                    z.writestr(*extra)
        self.bundle.write_bytes(stream.getvalue())
        return sha(stream.getvalue())

    def invoke(self, pin, head=HEAD, tree=TREE):
        with redirect_stdout(io.StringIO()) as out:
            code = replay.main(
                [
                    "--artifact",
                    str(self.bundle),
                    "--artifact-sha256",
                    pin,
                    "--local-dir",
                    str(self.local),
                    "--expected-head",
                    head,
                    "--expected-tree",
                    tree,
                ]
            )
        report = json.loads(out.getvalue())
        self.assertIs(report["release_authorized"], False)
        return code, report

    def test_matches_streamed_deflate_artifact_and_reports_scope(self):
        pin = self.create()
        first = self.invoke(pin)
        self.assertEqual(self.invoke(pin), first)
        code, report = first
        self.assertEqual(
            (code, report["status"], report["production"]), (0, "MATCHED_EVALUATION_REPLAY", "BLOCKED")
        )
        self.assertEqual(
            set(report["records_sha256"]),
            {"custody.json", "readiness.json", "qualification.json", "unit-tests.json"},
        )
        self.assertIn("governed/incident-install.json", report["outside_replay"])

    def test_wrong_outer_pin_stops_before_zip_parsing(self):
        self.create()
        with patch.object(replay, "hosted_records", side_effect=AssertionError("parsed before pin")):
            self.assertEqual(self.invoke("0" * 64)[1]["reason"], "artifact-digest-mismatch")
            self.assertEqual(self.invoke("")[0], 2)

    def test_independently_selected_revision_tree_and_local_bytes(self):
        pin = self.create()
        self.assertEqual(self.invoke(pin, head=TREE)[0], 1)
        self.assertEqual(self.invoke(pin, tree=HEAD)[0], 1)
        (self.local / "readiness.json").write_bytes(b"{}")
        self.assertEqual(self.invoke(pin)[1]["reason"], "hosted-local-records-differ")

    def test_equal_transports_with_invalid_outcomes_still_fail(self):
        variants = [
            ("readiness.json", "release_authorized", True),
            ("qualification.json", "production", "PASS"),
            ("unit-tests.json", "failures", 1),
            ("unit-tests.json", "tests_run", True),
            ("custody.json", "mutants", {"broken": []}),
            ("custody.json", "status", "FAILED"),
            ("qualification.json", "schema", "unsupported"),
            ("readiness.json", "unmet", []),
            ("readiness.json", "production_approved", True),
            ("qualification.json", "qualification_workflow_sha256", "0" * 64),
        ]
        for name, key, value in variants:
            with self.subTest(name=name, key=key):
                docs = fixture()
                docs[name][key] = value
                self.assertEqual(self.invoke(self.create(docs))[0], 1)
        docs = fixture()
        for row in docs["custody.json"]["cases"]:
            row.update(expected="ACCEPT", observed="ACCEPT")
        self.assertEqual(self.invoke(self.create(docs))[1]["reason"], "custody-outcome")
        docs = fixture()
        docs["unit-tests.json"]["tests_per_module"]["test_governed_subscriber.py"] = 0
        docs["unit-tests.json"]["tests_run"] -= 7
        docs["qualification.json"]["governed_unit_tests"] -= 7
        self.assertEqual(self.invoke(self.create(docs))[1]["reason"], "incomplete-test-inventory")
        self.assertEqual(self.invoke(self.create(wrong_manifest=True))[1]["reason"], "governed-manifest")

    def test_duplicate_ambiguities_and_unsafe_member_types(self):
        link = zipfile.ZipInfo("governed/readiness.json")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for extra in [(link, b"file"), ("../out", b"bad"), ("governed/unit-tests.json", b"duplicate")]:
            with self.subTest(extra=str(extra[0])):
                pin = self.create(omit="governed/readiness.json", extra=extra)
                self.assertEqual(self.invoke(pin)[0], 1)
        self.assertFalse((self.root / "out").exists())

    def test_missing_and_unsafe_local_evidence(self):
        self.assertEqual(self.invoke(self.create(omit="governed/unit-tests.json"))[0], 2)
        pin = self.create()
        local = self.local / "custody.json"
        local.unlink()
        self.assertEqual(self.invoke(pin)[0], 2)
        local.symlink_to(self.bundle)
        self.assertNotEqual(self.invoke(pin)[0], 0)

    def test_invalid_transport_and_oversized_compressed_record(self):
        pin = self.create(
            omit="governed/readiness.json", extra=("governed/readiness.json", b" " * (DOC_LIMIT + 1))
        )
        self.assertEqual(self.invoke(pin)[1]["reason"], "zip-entry-size")
        raw = b"not an archive"
        self.bundle.write_bytes(raw)
        self.assertEqual(self.invoke(sha(raw))[0], 1)

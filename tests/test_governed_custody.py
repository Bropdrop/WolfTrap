"""Independent byte-level and CLI checks for the disposable governed release archive."""

from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CUSTODY = ROOT / "release/custody"
with patch.object(
    sys,
    "path",
    [str(CUSTODY), str(ROOT / "release/verifier"), str(ROOT / "release/qualification"), *sys.path],
):
    import archive_store as archive
    from disaster_exercise import EMPTY, checkpoint
    from release_fixtures import TestIssuer, toy
    from release_io import Verdict, pack


def cli(*args):
    result = subprocess.run(
        [sys.executable, "-I", CUSTODY, *map(str, args)], capture_output=True, text=True, timeout=30
    )
    return result.returncode, json.loads(result.stdout)


class GovernedCustodyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.issuer_dir = tempfile.TemporaryDirectory()
        issuer = TestIssuer(Path(cls.issuer_dir.name) / "issuer")
        cls.now = int(time.time())
        files, record = toy(issuer, "0.1.1", 1, cls.now)
        cls.trust = issuer.trust([record], cls.now)
        cls.raw = pack(files)
        cls.policy_pin = sha256(cls.trust["policy.json"]).hexdigest()
        cls.pin = checkpoint(files, record, cls.trust["policy.json"], EMPTY)

    @classmethod
    def tearDownClass(cls):
        cls.issuer_dir.cleanup()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.vault = self.root / "vault"
        self.vault.mkdir(mode=0o700)

    def admit(self):
        return archive.admit(self.vault, self.raw, self.trust, self.policy_pin, 0, EMPTY, self.now)

    def test_cli_admission_replication_recovery_round_trip(self):
        bundle, replica, output, trust = (
            self.root / name for name in ("bundle.zip", "replica", "out", "trust")
        )
        bundle.write_bytes(self.raw)
        for directory in (trust, replica, output):
            directory.mkdir(mode=0o700)
        for key, data in self.trust.items():
            (trust / key).write_bytes(data)
        args = [
            "--vault",
            self.vault,
            "--sequence",
            0,
            "--index-sha256",
            EMPTY,
            "--bundle",
            bundle,
            "--trust-dir",
            trust,
            "--policy-sha256",
            self.policy_pin,
        ]
        status, receipt = cli("admit", *args)
        self.assertEqual((status, receipt["index_sha256"]), (0, self.pin))
        self.assertEqual(cli("reconcile", *args)[1]["index_sha256"], self.pin)
        head = ["--sequence", 1, "--index-sha256", self.pin]
        self.assertEqual(cli("replicate", "--vault", self.vault, "--replica", replica, *head)[0], 0)
        dest = output / "recover.zip"
        self.assertEqual(
            cli("restore", "--vault", replica, "--release-sequence", 1, "--output", dest, *head)[0], 0
        )
        self.assertEqual(dest.read_bytes(), self.raw)
        self.assertEqual(cli("audit", "--vault", replica, "--sequence", 1, "--index-sha256", "f" * 64)[0], 1)

    def test_custody_requires_independent_input_and_current_trust(self):
        status, receipt = cli(
            "admit",
            "--bundle",
            self.root / "trust/input.zip",
            "--trust-dir",
            self.root / "trust",
            "--policy-sha256",
            self.policy_pin,
            "--vault",
            self.vault,
            "--sequence",
            0,
            "--index-sha256",
            EMPTY,
        )
        self.assertEqual((status, receipt["reason"]), (1, "custody-path-overlap"))
        with self.assertRaises(Verdict) as err:
            archive.admit(
                self.vault, self.raw, self.trust, self.policy_pin, 0, EMPTY, self.now, minimum_generation=1
            )
        self.assertEqual(err.exception.reason, "incident-policy-downgrade")
        self.assertEqual(list(self.vault.iterdir()), [])

    def test_racing_writers_commit_once(self):
        def writer():
            try:
                return self.admit()["status"]
            except Verdict as exc:
                return exc.reason

        with ThreadPoolExecutor(max_workers=4) as workers:
            results = list(workers.map(lambda _: writer(), range(4)))
        self.assertEqual(results.count("ADMITTED_EVALUATION_BYTES"), 1)
        self.assertLessEqual(
            set(results),
            {"ADMITTED_EVALUATION_BYTES", "custody-head-sequence-mismatch", "custody-busy-retry"},
        )
        self.assertEqual(archive.audit(self.vault, 1, self.pin)["sequence"], 1)

    def test_hardlink_and_unexpected_files_stop_recovery(self):
        self.admit()
        member = self.vault / "release-00000001/capsule.zip"
        os.link(member, self.root / "linked")
        with self.assertRaisesRegex(Verdict, "unsafe-custody-member"):
            archive.audit(self.vault, 1, self.pin)
        (self.root / "linked").unlink()
        (member.parent / "unexpected").touch()
        with self.assertRaisesRegex(Verdict, "custody-directory-bound"):
            archive.audit(self.vault, 1, self.pin)

    def test_readback_catches_substitution_after_open(self):
        self.admit()
        member = self.vault / "release-00000001/capsule.zip"
        real_stat = os.stat

        def replace(name, *args, **kwargs):
            if name == "capsule.zip" and kwargs.get("dir_fd") is not None:
                copy = member.with_suffix(".other")
                copy.write_bytes(member.read_bytes())
                os.replace(copy, member)
            return real_stat(name, *args, **kwargs)

        with (
            patch("archive_store.os.stat", side_effect=replace),
            self.assertRaisesRegex(Verdict, "custody-member-changed"),
        ):
            archive.audit(self.vault, 1, self.pin)

    def test_resource_limit_and_unsafe_output_ancestors(self):
        for i in range(archive.MAX_PENDING + 1):
            (self.vault / f"pending-{i:032x}").mkdir(mode=0o700)
        with self.assertRaisesRegex(Verdict, "custody-directory-bound"):
            archive.audit(self.vault, 0, EMPTY)
        symlink = self.root / "elsewhere"
        symlink.symlink_to(self.vault)
        self.assertEqual(cli("audit", "--vault", symlink, "--sequence", 0, "--index-sha256", EMPTY)[0], 2)
        self.assertEqual(
            cli("audit", "--vault", str(self.vault) + "/../vault", "--sequence", 0, "--index-sha256", EMPTY)[
                0
            ],
            1,
        )

    def test_disaster_exercise_is_repeatable_and_kills_defective_auditors(self):
        outputs = [self.root / "one.json", self.root / "two.json"]
        for output in outputs:
            status, report = cli("exercise", "--output", output)
            self.assertEqual(status, 0)
            self.assertEqual(report["production_custody"], "BLOCKED")
            self.assertEqual(report["status"], "VERIFIED_DISPOSABLE_EXERCISE")
            self.assertTrue(all(row["expected"] == row["observed"] for row in report["cases"]))
            self.assertEqual(
                set(report["mutants"]), {"accept-all", "reject-all", "trust-local-pin", "head-only"}
            )
            self.assertTrue(all(report["mutants"].values()))
        self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())

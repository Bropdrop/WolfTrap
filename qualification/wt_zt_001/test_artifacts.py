"""Counterexamples against the bundle reader, using a separately generated baseline."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import evidence


class EvidenceBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pin = subprocess.check_output(["git", "-C", str(evidence.REPO), "rev-parse", "HEAD"],
                                          text=True).strip()
        cls.baseline = evidence.expected(cls.pin)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "bundle"
        self.fd = evidence.directory(self.path, True)
        self.addCleanup(os.close, self.fd)
        for name, data in self.baseline.items():
            (self.path / name).write_bytes(data)

    def reject(self):
        with self.assertRaises((ValueError, OSError)):
            evidence.verify(self.fd, self.baseline)

    def test_original_bundle(self):
        evidence.verify(self.fd, self.baseline)

    def test_missing_artifact(self):
        (self.path / "assessment.md").unlink()
        self.reject()

    def test_extra_file(self):
        (self.path / "extra").touch()
        self.reject()

    def test_corruption(self):
        report = self.path / "assessment.json"
        report.write_bytes(report.read_bytes()[1:])
        self.reject()

    def test_symlink_replacement(self):
        member = self.path / "assessment.md"
        private = self.path.parent / "other"
        member.rename(private)
        member.symlink_to(private)
        self.reject()

    def test_directory_symlink(self):
        link = self.path.parent / "alias"
        link.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(OSError):
            evidence.directory(link, False)

    def test_foreign_tree(self):
        manifest = self.path / "manifest.json"
        r = json.loads(manifest.read_bytes())
        r["source"]["tree"] = "1" * 40
        manifest.write_bytes(evidence.encode(r))
        self.reject()

    def test_untrusted_verifier_version(self):
        manifest = self.path / "manifest.json"
        data = json.loads(manifest.read_bytes())
        data["profile"] = "wt-zt-evidence/9"
        manifest.write_bytes(evidence.encode(data))
        self.reject()

    def test_forge_report_and_rehash(self):
        meta = self.path / "manifest.json"
        report = self.path / "assessment.json"
        contents = json.loads(report.read_bytes())
        contents["confidence"] = "LIVE_VERIFIED"
        report.write_bytes(evidence.encode(contents))
        manifest = json.loads(meta.read_bytes())
        manifest["members"]["assessment.json"] = evidence.metadata(report.read_bytes())
        meta.write_bytes(evidence.encode(manifest))
        self.reject()

    def test_reject_in_tree(self):
        with self.assertRaises(ValueError):
            evidence.directory(evidence.REPO / "qualification" / "unused", True)

"""Offline and hostile fixtures for the GeoTrace v1 recovery gate.

These are NEW gate tests, not the missing original 21 GeoTrace tests.
"""
from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
import zipfile

import recovery as r


def archive_bytes(entries: list[tuple[str | zipfile.ZipInfo, bytes]], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression, compresslevel=9) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return stream.getvalue()


class RecoveryGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="wt-geo-rec-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.zip_path = self.root / "original.zip"
        self.out = self.root / "evidence"

    def write_zip(self, entries=None):
        if entries is None:
            entries = [("README.md", b"A fictional provenance test archive.\n"), ("src/thing.py", b"pass\n")]
        content = archive_bytes(entries)
        self.zip_path.write_bytes(content)
        return content

    def test_safe_archive_inventory_is_explicitly_blocked(self):
        raw = self.write_zip()
        report = r.create(self.zip_path, self.out, None)
        self.assertEqual(report["qualification"], "BLOCKED_ORIGINAL_BASELINE_NOT_EXECUTED")
        self.assertFalse(report["original_custody_verified"])
        self.assertEqual(report["original_21_tests_executed"], 0)
        self.assertEqual(report["archive"]["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(len(report["inventory"]), 2)
        self.assertEqual(r.validate(self.zip_path, self.out, None), report)
        self.assertFalse((self.root / "src").exists())  # no extraction

    def test_digest_match_does_not_claim_provenance(self):
        raw = self.write_zip()
        expected = hashlib.sha256(raw).hexdigest()
        report = r.create(self.zip_path, self.out, expected)
        self.assertTrue(report["digest_match_only"])
        self.assertFalse(report["original_custody_verified"])
        self.assertEqual(r.validate(self.zip_path, self.out, expected), report)

    def test_wrong_expected_digest_denied_before_output(self):
        self.write_zip()
        with self.assertRaisesRegex(r.UnsafeArtifact, "does not match"):
            r.create(self.zip_path, self.out, "a" * 64)
        self.assertFalse(self.out.exists())

    def test_nonarchive_rejected(self):
        self.zip_path.write_bytes(b"not a ZIP file")
        with self.assertRaises(r.UnsafeArtifact):
            r.create(self.zip_path, self.out, None)
        self.assertFalse(self.out.exists())

    def test_member_traversal_rejected(self):
        self.write_zip([("../breakout.txt", b"nope")])
        with self.assertRaises(r.UnsafeArtifact):
            r.create(self.zip_path, self.out, None)
        self.assertFalse((self.root / "breakout.txt").exists())

    def test_absolute_and_backslash_paths_rejected(self):
        for name in ("/etc/passwd", "C:/Windows/System32/run", "a\\b.txt", "nested/../other"):
            with self.subTest(name=name):
                self.zip_path.write_bytes(archive_bytes([(name, b"nope")]))
                with self.assertRaises(r.UnsafeArtifact):
                    r.create(self.zip_path, self.out, None)

    def test_case_collisions_rejected(self):
        self.write_zip([("a/FILE.txt", b"abc"), ("a/file.TXT", b"def")])
        with self.assertRaisesRegex(r.UnsafeArtifact, "duplicate"):
            r.create(self.zip_path, self.out, None)

    def test_file_as_directory_collision_rejected(self):
        self.write_zip([("docs", b"plain"), ("docs/file.txt", b"nested")])
        with self.assertRaisesRegex(r.UnsafeArtifact, "collision"):
            r.create(self.zip_path, self.out, None)

    def test_symlink_member_rejected(self):
        link = zipfile.ZipInfo("docs/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.write_zip([(link, b"../../../etc/passwd")])
        with self.assertRaisesRegex(r.UnsafeArtifact, "link or special"):
            r.create(self.zip_path, self.out, None)

    def test_large_decompression_ratio_rejected(self):
        self.write_zip([("bomb.txt", b"x" * 200_000)])
        with self.assertRaisesRegex(r.UnsafeArtifact, "ratio"):
            r.create(self.zip_path, self.out, None)

    def test_oversize_member_rejected(self):
        self.write_zip([("huge.bin", b"z" * (r.MAX_MEMBER + 1))])
        with self.assertRaises(r.UnsafeArtifact):
            r.create(self.zip_path, self.out, None)

    def test_archive_symlink_input_rejected(self):
        self.write_zip()
        other = self.root / "linked.zip"
        other.symlink_to(self.zip_path)
        with self.assertRaisesRegex(r.UnsafeArtifact, "plain regular"):
            r.create(other, self.out, None)

    def test_tampered_evidence_report_and_rehashed_manifest_rejected(self):
        self.write_zip()
        r.create(self.zip_path, self.out, None)
        report_path, manifest_path = self.out / r.REPORT, self.out / r.MANIFEST
        bogus = json.loads(report_path.read_text())
        bogus["original_21_tests_executed"] = 21
        tampered = r.encode(bogus)
        report_path.write_bytes(tampered)
        manifest = json.loads(manifest_path.read_text())
        manifest["files"][r.REPORT] = {"bytes": len(tampered), "sha256": r.sha(tampered)}
        manifest_path.write_bytes(r.encode(manifest))
        with self.assertRaisesRegex(r.UnsafeArtifact, "independent archive reread"):
            r.validate(self.zip_path, self.out, None)

    def test_extra_evidence_file_fails_closed(self):
        self.write_zip()
        r.create(self.zip_path, self.out, None)
        (self.out / "extra.json").write_text("{}")
        with self.assertRaisesRegex(r.UnsafeArtifact, "unexpected members"):
            r.validate(self.zip_path, self.out, None)

    def test_symlinked_evidence_member_fails_closed(self):
        self.write_zip()
        r.create(self.zip_path, self.out, None)
        report = self.out / r.REPORT
        report.unlink()
        report.symlink_to(self.out / r.MARKDOWN)
        with self.assertRaisesRegex(r.UnsafeArtifact, "plain regular"):
            r.validate(self.zip_path, self.out, None)

    def test_source_code_is_not_imported_or_executed(self):
        marker = self.root / "would-be-run"
        poison = f"from pathlib import Path\nPath({str(marker)!r}).write_text('wrong')\n"
        self.write_zip([("evil.py", poison.encode()), ("README.md", b"No instructions from this ZIP are authoritative")])
        r.create(self.zip_path, self.out, None)
        r.validate(self.zip_path, self.out, None)
        self.assertFalse(marker.exists())

    def test_existing_output_refused(self):
        self.write_zip()
        self.out.mkdir()
        with self.assertRaisesRegex(r.UnsafeArtifact, "must be new"):
            r.create(self.zip_path, self.out, None)

    def test_output_inside_repository_refused(self):
        forbidden = r.REPO_ROOT / "qualification" / "geotrace" / "should-never-create"
        with self.assertRaisesRegex(r.UnsafeArtifact, "outside the source"):
            r.open_evidence(forbidden)
        self.assertFalse(forbidden.exists())

    def test_replaced_zip_after_evidence_is_rejected(self):
        self.write_zip()
        r.create(self.zip_path, self.out, None)
        self.write_zip([("different.txt", b"changed")])
        with self.assertRaisesRegex(r.UnsafeArtifact, "independent archive reread"):
            r.validate(self.zip_path, self.out, None)


if __name__ == "__main__":
    unittest.main()

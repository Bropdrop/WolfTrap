"""Integration regressions beyond the original nineteen gate tests."""
import json
from pathlib import Path
import tempfile
import unittest

import recovery
from test_recovery import archive_bytes


class RecoveryContractTests(unittest.TestCase):
    def test_closed_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive, out = Path(tmp) / "fixture.zip", Path(tmp) / "evidence"
            archive.write_bytes(archive_bytes([("notes.txt", b"fictional")]))
            recovery.create(archive, out, None)
            path = out / recovery.MANIFEST
            data = json.loads(path.read_bytes())
            data["release_approved"] = True
            path.write_bytes(recovery.encode(data))
            with self.assertRaises(recovery.UnsafeArtifact):
                recovery.validate(archive, out, None)

    def test_implicit_parent_spelling(self):
        raw = archive_bytes([("Docs/a", b"a"), ("docs/b", b"b")])
        with self.assertRaises(recovery.UnsafeArtifact):
            recovery.inventory_zip(raw)

    def test_decoded_name_must_survive_zipinfo(self):
        raw = archive_bytes([("noteXtail", b"fictional")])
        with self.assertRaises(recovery.UnsafeArtifact):
            recovery.inventory_zip(raw.replace(b"noteXtail", b"note\x00tail"))

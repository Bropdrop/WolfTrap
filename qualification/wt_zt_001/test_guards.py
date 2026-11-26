import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from contextlib import closing

from guard_profiles import capture_candidate, reset_fixture, retire_fixture


class GuardProfiles(unittest.TestCase):
    def test_database_selection(self):
        with closing(sqlite3.connect(":memory:")) as test, closing(sqlite3.connect(":memory:")) as protected:
            dbs = {"fixture-test": test, "fictional-protected": protected}
            for db in dbs.values():
                db.execute("CREATE TABLE sample(x)")
                db.execute("INSERT INTO sample VALUES (42)")
            for name in ("fictional-protected", "", "test-copy"):
                self.assertEqual(reset_fixture(name, dbs), "DENY")
                self.assertEqual(protected.execute("SELECT x FROM sample").fetchall(), [(42,)])
            self.assertEqual(reset_fixture("fixture-test", dbs), "APPLIED")
            self.assertEqual(test.execute("SELECT x FROM sample").fetchall(), [])
            self.assertEqual(protected.execute("SELECT x FROM sample").fetchall(), [(42,)])

    def test_backup_survives_limited_authority(self):
        active = {"fictional-volume": b"baseline-v1"}
        with tempfile.TemporaryDirectory() as tmp:
            witness = Path(tmp) / "fixture-snapshot"
            witness.write_bytes(active["fictional-volume"])
            self.assertFalse(retire_fixture(active, "fixture-snapshot"))
            self.assertTrue(retire_fixture(active, "fictional-volume"))
            self.assertEqual(active, {})
            self.assertEqual(witness.read_bytes(), b"baseline-v1")

    def test_selected_path_and_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "selected"
            root.mkdir()
            target = Path(tmp) / "outside"
            target.write_bytes(b"outside")
            (root / "link").symlink_to(target)
            (root / "parent").symlink_to(target.parent, target_is_directory=True)
            (root / "pending").touch()
            (root / "ok").write_bytes(b"local")
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(capture_candidate(fd, "ok"), b"local")
                for selection in ("../outside", "parent/outside", "link", "pending", "missing", ".",
                                  "*", "/outside", "C:\\outside", "//share", "ok/.."):
                    with self.subTest(selection=selection):
                        self.assertEqual(capture_candidate(fd, selection), "HOLD")
                self.assertEqual(target.read_bytes(), b"outside")
                self.assertEqual((root / "ok").read_bytes(), b"local")
            finally:
                os.close(fd)

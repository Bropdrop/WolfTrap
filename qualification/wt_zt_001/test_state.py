"""Independent observations for stale writes, interrupted transactions and restart."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
from threading import Barrier, Event
import unittest

import fixtures
import host
from recovery import reconcile


class StateQualification(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "host.sqlite"
        fixtures.provision(self.path, fixtures.BASE)
        self.roots = fixtures.roots()
        self.tokens = {role: fixtures.issue(role, fixtures.BASE) for role in fixtures.ROLES}

    def test_two_agents_update_same_revision(self):
        # Both workers read v1 before either is allowed to write. Order the two commits for replay.
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("CREATE TABLE draft(id INTEGER PRIMARY KEY, version INTEGER, content TEXT)")
            db.execute("INSERT INTO draft VALUES(1, 1, 'first')")
        read = Barrier(2)
        committed = Event()

        def edit(who):
            with closing(sqlite3.connect(self.path)) as db:
                base = db.execute("SELECT version FROM draft WHERE id=1").fetchone()[0]
                read.wait(timeout=5)
                if who == "ash" and not committed.wait(5):
                    raise RuntimeError("lost fixture synchronization")
                with db:
                    updated = db.execute("UPDATE draft SET version=version+1, content=? "
                                         "WHERE id=1 AND version=?", (who, base)).rowcount
                if who == "alder":
                    committed.set()
                return base, updated
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(edit, ("alder", "ash")))
        self.assertEqual(results, [(1, 1), (1, 0)])
        with closing(sqlite3.connect(self.path)) as observer:
            self.assertEqual(observer.execute("SELECT version,content FROM draft").fetchall(), [(2,"alder")])

    def test_rollback_on_commit_failure(self):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("CREATE TRIGGER interrupt AFTER INSERT ON effects "
                       "BEGIN SELECT RAISE(ABORT, 'fictional commit failure'); END")
            with self.assertRaises(host.Denied):
                host.dispatch(db, fixtures.BASE, self.tokens, self.roots)
        with closing(sqlite3.connect(self.path)) as observer:
            self.assertEqual(observer.execute("SELECT * FROM effects").fetchall(), [])
        self.assertEqual(reconcile(self.path, fixtures.BASE), "OBSERVED_EMPTY")

    def test_inconsistent_or_missing_observation(self):
        self.assertEqual(host.submit(self.path, fixtures.BASE, self.tokens, self.roots), "ACK")
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE effects SET binding='{'")
        self.assertEqual(reconcile(self.path, fixtures.BASE), "HOLD")
        self.path.rename(self.path.with_suffix(".lost"))
        self.assertEqual(reconcile(self.path, fixtures.BASE), "HOLD")
        self.assertFalse(self.path.exists())

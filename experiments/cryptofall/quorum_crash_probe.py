"""Qualification-only replica launcher injecting SIGKILL at real install writes."""
import os
from pathlib import Path
import runpy
import signal
import sqlite3
import sys

if __name__ == "__main__":
    boundary = sys.argv.pop(1)
    connect = sqlite3.connect

    class Observed(sqlite3.Connection):
        installing = False

        def execute(self, sql, *params):
            if sql.startswith("INSERT INTO history"):
                self.installing = True
            if self.installing and sql.startswith("UPDATE current") and boundary == "between writes":
                os.kill(os.getpid(), signal.SIGKILL)
            return super().execute(sql, *params)

        def commit(self):
            super().commit()
            if self.installing and boundary == "after commit":
                os.kill(os.getpid(), signal.SIGKILL)

    sqlite3.connect = lambda *a, **kw: connect(*a, factory=Observed, **kw)
    runpy.run_path(str(Path(__file__).with_name("quorum_node.py")), run_name="__main__")

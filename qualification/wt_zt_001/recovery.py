"""Recover a particular synthetic request by querying a separate durable host."""
import json
import sqlite3
from contextlib import closing
from hashlib import sha256


def reconcile(path, expected):
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            row = db.execute("SELECT binding,digest FROM effects WHERE slot=?",
                             (expected["slot"],)).fetchone()
    except (sqlite3.Error, OSError):
        return "HOLD"
    if row is None:
        return "OBSERVED_EMPTY"
    encoded = json.dumps(expected, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if row[1] != sha256(encoded).hexdigest():
        return "HOLD"
    try:
        return "RECOVERED" if json.loads(row[0]) == expected else "HOLD"
    except (TypeError, ValueError):
        return "HOLD"

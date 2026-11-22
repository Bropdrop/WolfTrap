"""Read-only SQLite observer. No imports from the fixture issuer, host or agent."""
import hashlib
import json
import sqlite3
from contextlib import closing

VERSION = "wt-zt-oracle/1"


def observe(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        data = db.execute("SELECT slot, binding, digest, generation, policy_version, tick "
                          "FROM effects ORDER BY slot").fetchall()
        policy = db.execute("SELECT binding,policy_version,generation,tick,credential_active,"
                            "grant_active,ceiling FROM policy WHERE singleton=1").fetchone()
    effects = [dict(slot=s, binding=json.loads(b), digest=d, generation=g, version=v, tick=t)
               for s, b, d, g, v, t in data]
    state = None if policy is None else dict(binding=json.loads(policy[0]), version=policy[1],
                    generation=policy[2], tick=policy[3], credential=policy[4],
                    grant=policy[5], limit=policy[6])
    return {"effects": effects, "policy": state}


def verdict(expected, before, after, responses):
    """Compare the complete effect window to the separately authored casebook."""
    rows = []
    for binding in expected["effects"]:
        encoded = json.dumps(binding, separators=(",", ":"), sort_keys=True).encode("ascii")
        rows.append(dict(binding=binding, slot=binding["slot"], generation=1,
                         version="fixture-policy-v1", tick=12,
                         digest=hashlib.sha256(encoded).hexdigest()))
    ledger_ok = before["effects"] == [] and after["effects"] == rows
    receipt_ok = sorted(responses) == sorted(expected["responses"])
    if not ledger_ok or not receipt_ok:
        return "CONTROL_GAP"
    return "MATCH"

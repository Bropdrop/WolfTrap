"""Loopback replica. The only effect is the QC-defined logical counter."""
import json
import socketserver
import sqlite3
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
import blackout
from quorum_rules import DOMAIN, advance, binding, certified, hash_of, initial
from severance import sign, verify
from verifier import Denied, require, wire


class Replica:
    def __init__(self, path):
        self.path = path
        config = json.loads((path / "identity").read_bytes())
        self.public, self.member = config["public"], config["member"]
        self.name = self.member
        self.keys = {k: bytes.fromhex(v) for k, v in config["links"].items()}
        self.key = MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(config["seed"]))

    def dispatch(self, role, op, obj):
        with sqlite3.connect(self.path / "store") as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            state = json.loads(db.execute("SELECT data FROM current").fetchone()[0])
            if op == "history":
                return [json.loads(row[0]) for row in db.execute("SELECT qc FROM history ORDER BY height")]
            if op == "lookup":
                exact = binding(obj)
                permit = verify(self.public["permit"], DOMAIN + "permit", obj["permit"])
                require(permit == {"ledger":hash_of(self.public), "id":exact["permit"], "operation":exact["operation"],
                                   "claim":exact["evidence"], "policy":obj["claim"]["claim"]["policy"]}, "disclosure")
                locks = []
                for raw, cert in db.execute("SELECT proposal,cert FROM locks"):
                    block = json.loads(raw)
                    if block["command"]["kind"] in ("effect","fence") and block["receipt"]["binding"] == exact:
                        locks.append([block,json.loads(cert)])
                history = [json.loads(row[0]) for row in db.execute("SELECT qc FROM history ORDER BY height")]
                return {"history":history, "locks":locks}
            if op == "locked":
                old = db.execute("SELECT digest,cert FROM locks WHERE height=?", (obj["height"],)).fetchone()
                require(old and old[0] == hash_of(obj), "no exact lock")
                return json.loads(old[1])
            if op == "vote":
                now = int(time.time())
                advance(self.public, state, obj, now)
                vote = {"ledger": hash_of(self.public), "block": hash_of(obj), "time": now}
                old = db.execute("SELECT digest,cert FROM locks WHERE height=?", (obj["height"],)).fetchone()
                if old:
                    require(old[0] == vote["block"], "locked")
                    return json.loads(old[1])
                cert = sign(self.key, DOMAIN + "vote/" + self.member, vote)
                db.execute("INSERT INTO locks VALUES(?,?,?,?)", (obj["height"], vote["block"], wire(cert), wire(obj)))
                db.commit()
                return cert
            require(op == "install", "operation")
            block = obj["block"]
            if block["height"] <= state["height"]:
                row = db.execute("SELECT qc FROM history WHERE height=?", (block["height"],)).fetchone()
                require(row and json.loads(row[0])["block"] == block, "fork")
                return "already installed"
            successor = certified(self.public, state, obj)
            db.execute("INSERT INTO history VALUES(?,?)", (successor["height"], wire(obj)))
            db.execute("UPDATE current SET data=?", (wire(successor),))
            db.commit()
            return "installed"


def initialize(path, public):
    with sqlite3.connect(path / "store") as db:
        db.executescript("""CREATE TABLE current(data BLOB NOT NULL);
            CREATE TABLE locks(height INTEGER PRIMARY KEY,digest TEXT NOT NULL,cert BLOB NOT NULL,proposal BLOB NOT NULL);
            CREATE TABLE history(height INTEGER PRIMARY KEY,qc BLOB NOT NULL);""")
        db.execute("INSERT INTO current VALUES(?)", (wire(initial(public)),))


if __name__ == "__main__":
    path = Path(sys.argv[1])
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), blackout.Handler) as server:
        server.service = Replica(path)
        blackout.ACCESS[server.service.name] = {role: ("history", "lookup", "locked", "vote", "install") for role in server.service.keys}
        print(server.server_address[1], flush=True)
        server.serve_forever()

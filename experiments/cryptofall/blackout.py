"""Local BLACKOUT II services. Provisioning is explicit and occurs only in the fixture."""
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import sqlite3
import sys
import time
from contextlib import closing, contextmanager

from counter import Checkpoint, increment_id
from verifier import Denied, digest, evaluate, parse, require, wire

LIMIT = 262144
ACCESS = {"anchor": {"witness": {"read", "advance"}, "gate": {"read", "advance"}},
          "witness": {"gate": {"snapshot"}, "operator": {"transition", "permit"}},
          "gate": {"client": {"apply", "receipt"}}}


def send(stream, obj):
    raw = wire(obj)
    require(len(raw) <= LIMIT, "frame-limit")
    stream.write(raw + b"\n")
    stream.flush()


def read(stream):
    raw = stream.readline(LIMIT + 2)
    if not raw:
        raise ConnectionError("peer closed")
    require(raw.endswith(b"\n") and len(raw) <= LIMIT + 1, "frame-limit")
    value = json.loads(raw)
    require(wire(value) == raw[:-1], "frame-encoding")
    return value


def tag(key, *fields):
    return hmac.digest(key, wire(fields), "sha256").hex()


def rpc(root, service, role, key, op, data):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(8)
        sock.connect(str(root / (service + ".sock")))
        with sock.makefile("rwb") as io:
            challenge = read(io)
            nonce = secrets.token_hex(32)
            header = [service, role, challenge, nonce, op, data]
            send(io, [role, nonce, op, data, tag(key, "request", *header)])
            reply, mac = read(io)
            require(hmac.compare_digest(mac, tag(key, "reply", *header, reply)), "reply-auth")
            if "error" in reply:
                raise Denied(reply["error"])
            return reply["ok"]


def create_store(path, state):
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)")
        db.execute("INSERT INTO state VALUES(1,?)", (wire(state),))


@contextmanager
def store(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=rw", uri=True)) as db, db:
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        raw, = db.execute("SELECT body FROM state WHERE id=1").fetchone()
        yield db, json.loads(raw)


class Service:
    def __init__(self, root, name):
        self.root, self.name = root, name
        self.directory = root / name
        config = json.loads((self.directory / "config").read_bytes())
        self.keys = {r: bytes.fromhex(k) for r, k in config["keys"].items()}
        self.setup = config.get("setup")
        self.db = self.directory / "state.db"

    def call(self, target, op, body):
        return rpc(self.root, target, self.name, self.keys[target], op, body)

    def dispatch(self, role, op, body):
        if self.name == "anchor":
            with store(self.db) as (db, state):
                if op == "advance":
                    require(state[role] == body["old"], "anchor-conflict")
                    state[role] = body["new"]
                    db.execute("UPDATE state SET body=?", (wire(state),))
                return state[role]
        # Gate holds the cross-process lock until its SQLite commit returns.
        # A snapshot is read under the calling gate's lock; it never mutates.
        if op == "snapshot":
            with store(self.db) as (_, state):
                self.check_anchor(state)
                return state
        with (self.root / "anchor" / "fence").open("rb") as fence:
            fcntl.flock(fence, fcntl.LOCK_EX)
            with store(self.db) as (db, state):
                old = self.check_anchor(state)
                if self.name == "witness":
                    self.change(state, op, body)
                    result = state["revision"]
                    deadline = body["transition"]["expires"] if op == "transition" else None
                else:
                    witness = self.call("witness", "snapshot", {})
                    result, deadline = self.counter(state, witness, op, body)
                    if op == "receipt":
                        return result
                db.execute("UPDATE state SET body=?", (wire(state),))
                self.call("anchor", "advance", {"old": old, "new": digest(wire(state))})
                if deadline is not None:
                    require(int(time.time()) < deadline, "expired-at-commit")
                # A failed or interrupted commit after anchor advancement freezes.
                db.commit()
                return result

    def check_anchor(self, state):
        head = digest(wire(state))
        require(self.call("anchor", "read", {}) == head, self.name + "-rollback")
        return head

    def change(self, state, op, body):
        if op == "transition":
            setup = self.setup
            genesis = wire(setup["genesis"])
            model = Checkpoint(genesis, setup["pin"], setup["recovery"], setup["witness"],
                               "specimen", lambda: int(time.time()))
            model.policy = wire(state["policy"])
            model.transition(wire(body))
            state["policy"] = json.loads(model.policy)
            state["permits"] = []
        else:
            raw = wire(body)
            increment_id(raw, "specimen")
            require(state["policy"]["mode"] == "active", "quarantine")
            permit = digest(raw)
            if permit not in state["permits"]:
                state["permits"].append(permit)
        state["revision"] += 1

    def counter(self, state, witness, op, body):
        request, auth = wire(body["request"]), wire(body["evidence"])
        rid = increment_id(request, "specimen")
        binding = [digest(request), digest(auth)]
        previous = state["receipts"].get(rid)
        if op == "receipt":
            require(previous and previous["binding"] == binding, "receipt-binding")
            return previous, None
        _, expires = evaluate(auth, request, witness["policy"], int(time.time()), expected_request_id=rid)
        require(digest(request) in witness["permits"], "disposable-permit")
        require(previous is None, "authorization-used")
        state["value"] += 1
        receipt = {"binding": binding, "value": state["value"], "epoch": witness["policy"]["epoch"]}
        state["receipts"][rid] = receipt
        return receipt, expires


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        svc = self.server.service
        self.connection.settimeout(8)
        challenge = secrets.token_hex(32)
        try:
            send(self.wfile, challenge)
            role, nonce, op, data, mac = read(self.rfile)
            require(op in ACCESS[svc.name].get(role, ()), "access")
            key = svc.keys[role]
            header = [svc.name, role, challenge, nonce, op, data]
            require(hmac.compare_digest(mac, tag(key, "request", *header)), "request-auth")
            try:
                reply = {"ok": svc.dispatch(role, op, data)}
            except Denied as exc:
                reply = {"error": str(exc)}
            except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
                reply = {"error": "unavailable"}
            send(self.wfile, [reply, tag(key, "reply", *header, reply)])
        except (Denied, OSError, ValueError, TypeError, KeyError):
            return


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    request_queue_size = 32


def serve(root, name):
    with (root / name / "singleton").open("a") as singleton:
        fcntl.flock(singleton, fcntl.LOCK_EX | fcntl.LOCK_NB)
        svc = Service(root, name)
        path = root / (name + ".sock")
        path.unlink(missing_ok=True)
        with Server(str(path), Handler) as server:
            server.service = svc
            print("ready", flush=True)
            server.serve_forever()


if __name__ == "__main__":
    os.umask(0o077)
    serve(Path(sys.argv[1]).resolve(), sys.argv[2])

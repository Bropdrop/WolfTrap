"""Process qualification with fresh lab credentials and externally authored expected outcomes."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

import blackout as b
from challenge import Fixture, ED, PQ, OWNER, WITNESS, POLICY_WITNESS, RECOVERY, encode, sha
from verifier import Denied

HERE = Path(__file__).resolve().parent
FAULT = """
import os, sys
from pathlib import Path
import blackout as b
role, point = sys.argv[2:]
call, dispatch = b.Service.call, b.Service.dispatch
def injected_call(self,target,op,body):
    result = call(self,target,op,body)
    if point == 'before' and target == 'anchor' and op == 'advance':
        os._exit(37)
    return result
def injected_dispatch(self,role,op,body):
    result = dispatch(self,role,op,body)
    if point == 'after' and op in ('apply','transition'):
        os._exit(38)
    return result
b.Service.call, b.Service.dispatch = injected_call, injected_dispatch
b.serve(Path(sys.argv[1]),role)
"""


class Lab:
    def __init__(self, root):
        self.root = root
        self.fixture = Fixture(root)
        f = self.fixture
        keys = {r:{} for r in b.ACCESS}
        for a, c in (("anchor","witness"),("anchor","gate"),("witness","gate"),
                     ("witness","operator"),("gate","client")):
            k = secrets.token_hex(32)
            keys[a][c] = k
            if c in keys:
                keys[c][a] = k
        self.keys = keys
        witness = {"revision":0,"policy":f.genesis,"permits":[]}
        gate = {"value":0,"receipts":{}}
        states = {"witness":witness,"gate":gate,"anchor":{"witness":sha(encode(witness)),"gate":sha(encode(gate))}}
        self.procs = {}
        for name, state in states.items():
            path = root / name
            path.mkdir(mode=0o700)
            config = {"keys":keys[name]}
            if name == "witness":
                config["setup"] = {"genesis":f.genesis,"pin":sha(encode(f.genesis)),
                                   "recovery":f.key(RECOVERY,PQ),"witness":f.key(POLICY_WITNESS,PQ)}
            (path / "config").write_bytes(encode(config))
            b.create_store(path / "state.db",state)
        (root / "anchor/fence").touch()
        for name in ("anchor","witness","gate"):
            self.start(name)

    def start(self,name,fault=None):
        if name in self.procs:
            self.stop(name)
        args = ["-c",FAULT,str(self.root),name,fault] if fault else ["blackout.py",str(self.root),name]
        proc = subprocess.Popen([sys.executable,"-B",*args],cwd=HERE,stdout=subprocess.PIPE)
        self.procs[name] = proc
        assert proc.stdout.readline() == b"ready\n"

    def stop(self,name):
        proc = self.procs.pop(name)
        proc.kill()
        proc.wait()
        proc.stdout.close()

    def invoke(self,name,op,data,wrong_key=False):
        role = "operator" if name == "witness" else "client"
        key = bytes.fromhex(self.keys[name][role])
        try:
            return b.rpc(self.root,name,role,bytes(32) if wrong_key else key,op,data)
        except Denied as exc:
            return str(exc)
        except OSError:
            return "offline"

    def observed(self,label,outcome):
        with closing(sqlite3.connect(self.root / "gate/state.db")) as db:
            state = json.loads(db.execute("SELECT body FROM state").fetchone()[0])
        print(json.dumps([label,outcome,state["value"],len(state["receipts"])]),flush=True)

    def snapshot(self,name):
        return (self.root / name / "state.db").read_bytes()

    def restore(self,name,raw):
        self.stop(name)
        (self.root / name / "state.db").write_bytes(raw)
        self.start(name)


def run(lab):
    f = lab.fixture
    f.now = int(time.time())
    req = json.loads(f.request)
    body = {"request":req,"evidence":f.claim()}
    def execute():
        result = lab.invoke("gate","apply",body)
        return result["value"] if isinstance(result,dict) else result
    def transition(action,**changes):
        f.now = int(time.time())
        doc = f.transition(action,**changes)
        result = lab.invoke("witness","transition",doc)
        if isinstance(result,int):
            f.anchor.policy = encode(doc["transition"]["next"])
        return result
    witness_initial = lab.snapshot("witness")
    gate_initial = lab.snapshot("gate")
    lab.observed("missing permit",execute())
    lab.invoke("witness","permit",dict(req, request_id="ab"*16))
    lab.observed("substituted permit",execute())
    lab.invoke("witness","permit",req)
    lab.start("gate","after")
    lab.observed("lost gate reply",execute())
    lab.start("gate")
    lab.observed("exact receipt",lab.invoke("gate","receipt",body)["value"])
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(5)
        sock.connect(str(lab.root / "gate.sock"))
        with sock.makefile("rwb") as io:
            b.read(io)
            b.send(io, ["client",secrets.token_hex(32),"receipt",body,"0"*64])
            assert io.read(1) == b"", "unauthenticated receipt bytes disclosed"
    lab.observed("unauthenticated receipt","no response bytes")
    lab.observed("different receipt evidence",lab.invoke("gate","receipt",dict(body,evidence=f.claim())))
    lab.observed("exact apply retry",execute())
    witness_good, gate_good = lab.snapshot("witness"),lab.snapshot("gate")
    lab.restore("witness",witness_initial)
    lab.observed("witness restored",execute())
    lab.restore("gate",gate_initial)
    lab.observed("both restored",execute())
    lab.restore("witness",witness_good)
    lab.observed("gate restored",execute())
    lab.restore("gate",gate_good)
    lab.stop("anchor")
    lab.observed("anchor offline",execute())
    lab.start("anchor")
    lab.stop("witness")
    lab.observed("witness offline",execute())
    lab.start("witness")
    lab.observed("independent restarts",lab.invoke("gate","receipt",body)["value"])
    lab.observed("ordinary downgrade",transition("rotate",profile="pq-only",keys=f.effect_keys("pq-only")))
    lab.start("witness","after")
    quarantine = f.transition("emergency-quarantine",mode="quarantine",revoked_algorithms=[ED])
    with ThreadPoolExecutor(8) as pool:
        attempts = [pool.submit(execute) for _ in range(12)]
        lost = lab.invoke("witness","transition",quarantine)
        blocked = [j.result() for j in attempts]
    assert all(isinstance(x,str) for x in blocked)
    lab.observed("lost witness reply",lost)
    lab.start("witness")
    f.anchor.policy = encode(quarantine["transition"]["next"])
    lab.observed("stale epoch",execute())
    lab.observed("confused recovery authority",transition("recover",mode="active",profile="pq-only",keys=f.effect_keys("pq-only"),
                 signers=((RECOVERY,OWNER,ED),(POLICY_WITNESS,POLICY_WITNESS,PQ))))
    lab.observed("revoked algorithm recovery",transition("recover",mode="active"))
    with ThreadPoolExecutor(8) as pool:
        attempts = [pool.submit(execute) for _ in range(16)]
        recovered = transition("recover",mode="active",profile="pq-only",keys=f.effect_keys("pq-only"))
        assert all(j.result()=="current-policy" for j in attempts)
    lab.observed("concurrent recovery",recovered)
    f.now=int(time.time())
    op=f.operation("24"*16)
    body={"request":json.loads(op),"evidence":f.claim(operation=op)}
    lab.invoke("witness","permit",body["request"])
    with ThreadPoolExecutor(8) as pool:
        results=list(pool.map(lambda _:execute(),range(12)))
    assert results.count(2)==1 and results.count("authorization-used")==11
    lab.observed("concurrent PQ commit",2)
    op=f.operation("25"*16)
    body={"request":json.loads(op),"evidence":f.claim(operation=op)}
    lab.invoke("witness","permit",body["request"])
    lab.start("gate","before")
    lab.observed("gate reservation crash",execute())
    lab.start("gate")
    lab.observed("gate ambiguous restart",execute())
    witness_good=lab.snapshot("witness")
    lab.restore("witness",witness_initial)
    lab.restore("gate",gate_initial)
    lab.observed("coordinated historical snapshots",execute())
    lab.restore("witness",witness_good)
    lab.start("witness","before")
    lab.observed("witness reservation crash",lab.invoke("witness","permit",req))
    lab.start("witness")
    lab.observed("witness ambiguous restart",lab.invoke("witness","permit",req))


if __name__=="__main__":
    with tempfile.TemporaryDirectory() as directory:
        lab=Lab(Path(directory))
        try:
            run(lab)
        finally:
            for service in list(lab.procs):
                lab.stop(service)

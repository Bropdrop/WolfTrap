"""BLACKBOX fault qualification. Every case uses a fresh target and disposable credentials."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

from challenge import Fixture, ED, encode, sha
from severance import rpc, binding, sign, verify
from severance_lab import Link, provision
from verifier import Denied
import blackbox as bb
from blackbox_verify import adjudicate

HERE=Path(__file__).resolve().parent
NAMES=("retainer","target","gate","recovery","witness")
PAUSE="""
import sys,time
from pathlib import Path
import blackbox as b
point=sys.argv.pop()
def pause(name):
    if name==point:
        Path('/private/hit').touch()
        limit=time.monotonic()+15
        while not Path('/private/resume').exists():
            if time.monotonic()>limit: raise RuntimeError('barrier timeout')
            time.sleep(0.005)
b.stage=pause
b.main()
"""
PACKETS={}
PINS={}


def attempt(fn):
    try:
        return fn()
    except (Denied,OSError) as exc:
        return str(exc)


class Lab:
    def __init__(self,root,label):
        self.root=root
        self.label=label
        self.f=Fixture(root)
        self.procs={}
        self.realm=secrets.token_hex(16)
        self.config={r:{"incoming":{},"peers":{},"realm":self.realm} for r in (*NAMES,"client","auditor","admin")}
        self.pins={"realm":self.realm}
        for r in NAMES:
            private=root/r
            private.mkdir(mode=0o700)
            seed=secrets.token_bytes(32)
            self.pins[r]=provision(seed)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1",0))
                port=sock.getsockname()[1]
            self.config[r].update(seed=seed.hex(),port=port)
        for target,roles in bb.ACL.items():
            for role in roles:
                key=secrets.token_hex(32)
                self.config[target]["incoming"][role]=key
                self.config[role]["peers"][target]={"port":self.config[target]["port"],"key":key}
        f=self.f
        self.config["gate"]["generation"]=1
        self.config["target"].update(retainer_pin=self.pins["retainer"],roots={r:self.pins[r] for r in ("recovery","witness")},
            setup={"genesis":f.genesis,"pin":sha(encode(f.genesis)),"recovery":f.anchor.roots["recovery-test"],
                   "witness":f.anchor.roots["policy-witness-test"]})
        head=bb.initialize(root/"target/state.db",self.realm,f.genesis,self.pins["gate"])
        bb.blackout.create_store(root/"retainer/state.db",{"revision":0,"realm":self.realm,"hash":head})
        for r in NAMES:
            self.start(r)
        PINS[label]=dict(self.pins)

    def start(self,r,point=None):
        self.stop(r)
        d=self.root/r
        for name in ("hit","resume"):
            (d/name).unlink(missing_ok=True)
        (d/"config").write_bytes(encode(self.config[r]))
        uid=str(12101+NAMES.index(r))
        runtime=Path(sys.executable).resolve().parents[1]
        cmd=["bwrap","--die-with-parent","--unshare-user","--unshare-pid","--unshare-ipc","--unshare-uts",
             "--uid",uid,"--gid",uid,"--cap-drop","ALL","--clearenv","--ro-bind","/usr","/usr",
             "--symlink","usr/bin","/bin","--symlink","usr/lib","/lib","--symlink","usr/lib64","/lib64",
             "--ro-bind",str(runtime),str(runtime),"--ro-bind",str(HERE),"/code","--bind",str(d),"/private",
             "--tmpfs","/tmp","--dev","/dev","--proc","/proc","--chdir","/code",sys.executable,"-B"]
        cmd+=["-c",PAUSE,r,point] if point else ["blackbox.py",r]
        p=subprocess.Popen(cmd,stdout=subprocess.PIPE)
        self.procs[r]=p
        if p.stdout.readline()!=b"ready\n":
            raise RuntimeError(f"{r} failed to start")

    def stop(self,r):
        p=self.procs.pop(r,None)
        if p:
            p.kill()
            p.wait()
            p.stdout.close()

    def close(self):
        for r in list(self.procs):
            self.stop(r)

    def call(self,role,name,op,b):
        return rpc(self.config[role],name,role,op,b)

    def admin(self,op,b):
        return self.call("admin","target",op,b)

    def grant(self,num=1):
        f=self.f
        f.now=int(time.time())
        raw=f.operation(f"{num:032x}")
        req=json.loads(raw)
        permit=self.admin("permit",{"request":req})["permit"]
        return {"request":req,"evidence":f.claim(operation=raw),"permit":permit}

    def submit(self,b):
        return self.call("client","gate","submit",b)

    def proposal(self,op,subject):
        meta=self.admin("view",{})["state"]["meta"][0]
        scope={"realm":self.realm,"revision":meta[2],"action":op,"subject":subject}
        return {"subject":subject,"votes":{r:self.call("admin",r,"approve",scope) for r in ("witness","recovery")}}

    def destroy_gate(self):
        self.stop("gate")
        shutil.rmtree(self.root/"gate")
        (self.root/"gate").mkdir(mode=0o700)
        seed=secrets.token_bytes(32)
        self.config["gate"]["seed"]=seed.hex()
        self.config["gate"]["generation"]+=1
        self.start("gate")
        return provision(seed)

    def capture(self,b):
        nonce=secrets.token_hex(32)
        query={"challenge":nonce}
        audit=attempt(lambda:self.call("auditor","target","audit",query))
        head=attempt(lambda:self.call("auditor","retainer","head",query))
        return {"challenge":nonce,"audit":audit,"head":head,"permit":b["permit"],"binding":binding(b)}

    def row(self,name,b,inputs=None):
        data=self.capture(b) if inputs is None else inputs
        outcome=adjudicate(self.pins,**data)
        with closing(sqlite3.connect(self.root/"target/state.db")) as db:
            value=db.execute("SELECT counter FROM meta").fetchone()[0]
            observation={
                "value":value,
                "spent":sorted(x[0] for x in db.execute("SELECT id FROM permits WHERE spent=1")),
                "decisions":db.execute("SELECT r.permit,d.status,d.rid,r.binding FROM decisions d "
                                       "JOIN reservations r USING(token) ORDER BY r.permit").fetchall(),
            }
        PACKETS[name]={"fixture":self.label,"inputs":data,"sql_observation":observation}
        print(json.dumps([name,outcome,value]),flush=True)
        return outcome

    def transition(self,action,**changes):
        self.f.now=int(time.time())
        doc=self.f.transition(action,**changes)
        self.admin("transition",doc)
        self.f.anchor.policy=encode(doc["transition"]["next"])


@contextmanager
def fixture(label):
    with tempfile.TemporaryDirectory() as d:
        lab=Lab(Path(d),label)
        try:
            yield lab
        finally:
            lab.close()


def boundary(point,kill_target=False):
    label=("both lost at " if kill_target else "gate lost at ")+point
    with fixture(label) as lab:
        b=lab.grant()
        actor="gate" if point in ("before-prepare","after-prepare","before-client-reply") else "target"
        lab.start(actor,point)
        with ThreadPoolExecutor(1) as pool:
            reply=pool.submit(lambda:attempt(lambda:lab.submit(b)))
            limit=time.monotonic()+5
            while not (lab.root/actor/"hit").exists():
                if time.monotonic()>limit:
                    raise RuntimeError("missed "+label)
                time.sleep(0.005)
            pin=lab.destroy_gate()
            if actor=="target":
                if kill_target:
                    lab.start("target")
                else:
                    (lab.root/"target/resume").touch()
            reply.result()
        replacement=attempt(lambda:lab.admin("replace",lab.proposal("replace",pin)))
        state=attempt(lambda:lab.admin("view",{}))
        if isinstance(state,dict):
            assert isinstance(replacement,dict)
            if state["state"]["reservations"] and not state["state"]["decisions"]:
                lab.admin("fence",lab.proposal("fence",b["permit"]))
        else:
            assert replacement=="UNRESOLVED-head-mismatch"
        lab.row(label,b)


def pending(lab,b):
    req=dict(b,generation=lab.config["gate"]["generation"],gate=provision(bytes.fromhex(lab.config["gate"]["seed"])))
    intent={"realm":lab.realm,"generation":req["generation"],"permit":b["permit"],"binding":binding(b)}
    key=bb.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(lab.config["gate"]["seed"]))
    req["auth"]=sign(key,"blackbox-prepare",intent)
    ticket=lab.call("gate","target","prepare",req)
    req.update(ticket)
    req["auth"]=sign(key,"blackbox-execute",dict(intent,token=ticket["token"]))
    return req


def extra():
    with fixture("race") as lab:
        b=lab.grant()
        packet=pending(lab,b)
        peer=lab.config["gate"]["peers"]["target"]
        link=Link(peer["port"])
        link.forward.clear()
        transport={"peers":{"target":dict(peer,port=link.server_address[1])}}
        try:
            with ThreadPoolExecutor(7) as pool:
                delayed=pool.submit(lambda:attempt(lambda:rpc(transport,"target","gate","execute",packet)))
                assert link.arrived.wait(3)
                pin=lab.destroy_gate()
                proposal=lab.proposal("replace",pin)
                outcomes=list(pool.map(lambda _:attempt(lambda:lab.admin("replace",proposal)),range(6)))
                assert sum(isinstance(x,dict) for x in outcomes)==1
                link.forward.set()
                assert delayed.result()=="retired-gate"
        finally:
            link.forward.set()
            link.shutdown()
            link.server_close()
        lab.admin("fence",lab.proposal("fence",b["permit"]))
        lab.row("delayed execution after six replacement attempts",b)
        b=lab.grant(2)
        with ThreadPoolExecutor(8) as pool:
            replies=list(pool.map(lambda _:attempt(lambda:lab.submit(b)),range(8)))
        assert sum(isinstance(x,dict) for x in replies)==1
        lab.row("eight concurrent executions",b)
        inputs=lab.capture(b)
        fake=dict(inputs,replicated_logs=[{"status":"NOT_COMMITTED","replicas":7}])
        lab.row("contradictory ordinary replicas",b,fake)
        terminal=next(r for r in replies if isinstance(r,dict))
        signing=bb.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(lab.config["target"]["seed"]))
        conflict=sign(signing,"blackbox-target-decision",dict(terminal["body"],status="NOT_COMMITTED"))
        lab.row("contradictory authenticated target decisions",b,dict(inputs,target_claims=[conflict]))
        lab.stop("target")
        lab.row("replicas only during target loss",b,dict(lab.capture(b),replicated_logs=[terminal]))
    with fixture("revocation") as lab:
        b=lab.grant()
        packet=pending(lab,b)
        lab.row("reserved before revocation",b)
        lab.transition("emergency-quarantine",mode="quarantine",revoked_algorithms=[ED])
        assert attempt(lambda:lab.call("gate","target","execute",packet))=="current-policy"
        lab.row("revoked unresolved execution",b)
        lab.admin("fence",lab.proposal("fence",b["permit"]))
        lab.row("target cancellation after revocation",b)
        lab.transition("recover",mode="active",profile="pq-only",keys=lab.f.effect_keys("pq-only"))
        fresh=lab.grant(2)
        lab.submit(fresh)
        lab.row("explicit PQ recovery and new permit",fresh)
    with fixture("rollback") as lab:
        b=lab.grant()
        old=(lab.root/"target/state.db").read_bytes()
        receipt=lab.submit(b)
        lab.row("before coordinated restoration",b)
        lab.destroy_gate()
        lab.stop("target")
        (lab.root/"target/state.db").write_bytes(old)
        lab.start("target")
        data=lab.capture(b)
        lab.row("restored gate and target with retained head",b,dict(data,replicated_logs=[receipt]))


def main(out):
    points=("before-prepare","before-prepare-cas","after-prepare-cas","after-prepare-commit","after-prepare",
            "before-target-write","after-counter-write","after-permit-write","after-receipt-write",
            "before-witness-cas","after-witness-cas","after-target-commit","before-client-reply")
    for point in points:
        boundary(point)
    for point in points:
        if point not in ("before-prepare","after-prepare","before-client-reply"):
            boundary(point,True)
    extra()
    (out/"audit.json").write_bytes(encode(PACKETS))
    (out/"pins.json").write_bytes(encode(PINS))


if __name__=="__main__":
    main(Path(sys.argv[1]))

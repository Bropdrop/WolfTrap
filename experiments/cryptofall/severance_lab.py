"""Disposable process/transport fault qualification. Private mount and PID namespace per service."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
import os
from pathlib import Path
import secrets
import socketserver
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time

from challenge import Fixture, ED, PQ, OWNER, RECOVERY, POLICY_WITNESS, encode, sha
import severance as v

NAMES=("retainer","anchor","gate","recovery","witness")
HERE=Path(__file__).resolve().parent
FAULT="""
import os,sys
import severance as v
point=sys.argv.pop()
original=v.Node.anchor
def call(self,op,body):
    if point=='after-db' and op=='finish':
        os._exit(43)
    result=original(self,op,body)
    if point=='after-arm' and op=='arm':
        os._exit(44)
    return result
v.Node.anchor=call
v.serve()
"""


def read_state(path):
    with closing(sqlite3.connect(path)) as db:
        return json.loads(db.execute("SELECT body FROM state").fetchone()[0])


def provision(seed):
    key=v.MLDSA65PrivateKey.from_seed_bytes(seed)
    return key.public_key().public_bytes_raw().hex()


class Link(socketserver.ThreadingMixIn,socketserver.TCPServer):
    """TCP forwarding proxy with deterministic partition and in-flight delay."""
    daemon_threads=True
    def __init__(self,port):
        self.drop=False
        self.arrived=threading.Event()
        self.forward=threading.Event()
        self.forward.set()
        class Forward(socketserver.StreamRequestHandler):
            def handle(inner):
                if self.drop:
                    return
                with socket.create_connection(("127.0.0.1",port),timeout=5) as upstream, upstream.makefile("rwb") as io:
                    v.send(inner.wfile,v.read(io))
                    request=v.read(inner.rfile)
                    self.arrived.set()
                    if self.forward.wait(5):
                        v.send(io,request)
                        try:
                            v.send(inner.wfile,v.read(io))
                        except ConnectionError:
                            return
        super().__init__(("127.0.0.1",0),Forward)
        threading.Thread(target=self.serve_forever,daemon=True).start()


class Lab:
    def __init__(self, root):
        self.root=root
        self.f=Fixture(root)
        self.realm=secrets.token_hex(16)
        self.cfg={r:{"peers":{},"incoming":{}} for r in (*NAMES,"client","admin")}
        self.pins={}
        self.procs={}
        self.isolation={}
        self.certs=[]
        for r in NAMES:
            seed=secrets.token_bytes(32)
            self.pins[r]=provision(seed)
            with socket.socket() as sock:
                sock.bind(("127.0.0.1",0))
                port=sock.getsockname()[1]
            self.cfg[r].update(seed=seed.hex(),port=port,realm=self.realm)
        for target,roles in v.ACCESS.items():
            for role in roles:
                k=secrets.token_hex(32)
                self.cfg[role]["peers"][target]={"key":k,"port":self.cfg[target]["port"]}
                self.cfg[target]["incoming"][role]=k
        self.links={}
        for role,target in (("anchor","retainer"),("client","gate")):
            peer=self.cfg[role]["peers"][target]
            link=Link(peer["port"])
            peer["port"]=link.server_address[1]
            self.links[role]=link
        f=self.f
        self.cfg["gate"]["anchor_pin"]=self.pins["anchor"]
        self.cfg["anchor"].update(retainer_pin=self.pins["retainer"],
            roots={r:self.pins[r] for r in ("recovery","witness")},
            setup={"genesis":f.genesis,"pin":sha(encode(f.genesis)),"recovery":f.key(RECOVERY,PQ),
                   "witness":f.key(POLICY_WITNESS,PQ)})
        state={"revision":0,"lineage":[],"policy":f.genesis,"pending":None,"used":[],"permits":[],"journal":[],
               "terminal":{},"generation":1,"gate_pin":self.pins["gate"]}
        for r in NAMES:
            d=root/r
            d.mkdir(mode=0o700)
            self.config(r)
            if r in ("anchor","retainer","gate"):
                v.create_store(d/"state.db",state if r!="gate" else {"generation":1,"journal":[]})
        for r in NAMES:
            self.start(r)

    def config(self,r):
        (self.root/r/"config").write_bytes(encode(self.cfg[r]))

    def start(self,r,fault=None):
        self.stop(r)
        uid=str(12001+NAMES.index(r))
        cmd=["bwrap","--die-with-parent","--unshare-user","--unshare-pid","--unshare-ipc","--unshare-uts",
             "--uid",uid,"--gid",uid,"--cap-drop","ALL","--clearenv","--ro-bind","/usr","/usr",
             "--symlink","usr/lib","/lib","--symlink","usr/lib64","/lib64","--symlink","usr/bin","/bin",
             "--ro-bind","/opt/codex/runtimes/codex-primary-runtime/dependencies/python",
             "/opt/codex/runtimes/codex-primary-runtime/dependencies/python",
             "--ro-bind",str(HERE),"/code","--bind",str(self.root/r),"/private","--proc","/proc",
             "--dev","/dev","--tmpfs","/tmp","--chdir","/code",sys.executable,"-B"]
        cmd+=["-c",FAULT,r,fault] if fault else ["severance.py",r]
        proc=subprocess.Popen(cmd,stdout=subprocess.PIPE)
        self.procs[r]=proc
        info=json.loads(proc.stdout.readline())
        assert info["ready"]==r and info["uid"]==int(uid) and "workspace" not in info["visible_roots"]
        self.isolation[r]=info

    def stop(self,r):
        proc=self.procs.pop(r,None)
        if proc:
            proc.kill(); proc.wait(); proc.stdout.close()

    def rpc(self,r,op,body,role="admin"):
        return v.rpc(self.cfg[role],r,role,op,body)

    def view(self):
        return v.verify(self.pins["anchor"],"anchor",self.rpc("anchor","view",{}))

    def approvals(self,op,target,revision=None):
        revision=self.view()["revision"] if revision is None else revision
        body={"realm":self.realm,"revision":revision,"action":op,"target":target}
        return {"target":target,"votes":{r:self.rpc(r,"approve",body) for r in ("recovery","witness")}}

    def reservation(self,n):
        f=self.f
        f.now=int(time.time())
        raw=f.operation(f"{n:032x}")
        req=json.loads(raw)
        self.rpc("anchor","permit",req)
        body={"request":req,"evidence":f.claim(operation=raw)}
        result=v.verify(self.pins["anchor"],"anchor",self.rpc("anchor","reserve",body,"client"))
        return dict(body,token=result["token"])

    def row(self,name,status):
        n=len(read_state(self.root/"gate/state.db")["journal"])
        print(json.dumps([name,status,n]),flush=True)

    def terminal(self,body):
        cert=self.rpc("anchor","query",body,"client")
        value=v.verify(self.pins["anchor"],"anchor",cert)
        if value["status"]!="UNRESOLVED":
            self.certs.append(cert)
        return value["status"]

    def resolve(self,body):
        return self.rpc("anchor","resolve",self.approvals("resolve",body["token"]))

    def lose_gate(self):
        self.stop("gate")
        shutil.rmtree(self.root/"gate")
        (self.root/"gate").mkdir(mode=0o700)
        seed=secrets.token_bytes(32)
        self.cfg["gate"]["seed"]=seed.hex()
        pin=provision(seed)
        self.config("gate")
        v.create_store(self.root/"gate/state.db",{"generation":None,"journal":[]})
        self.start("gate")
        return pin


def result(fn):
    try:
        value=fn()
        return value.get("status",value.get("body",{}).get("status","OK"))
    except v.Denied as exc:
        return str(exc)
    except OSError:
        return "partition-or-lost-response"


def main(l):
    f=l.f
    f.now=int(time.time())
    req=json.loads(f.request)
    l.rpc("anchor","permit",req)
    claim=f.claim()
    partial=dict(claim,signatures=claim["signatures"][::2])
    l.row("partial hybrid",result(lambda:l.rpc("anchor","reserve",{"request":req,"evidence":partial},"client")))
    over=f.claim(expires=f.now+31)
    l.row("31 second grant",result(lambda:l.rpc("anchor","reserve",{"request":req,"evidence":over},"client")))
    a=l.reservation(1)
    l.row("reservation without reply evidence",l.terminal(a))
    approvals=l.approvals("resolve",a["token"])
    unilateral=dict(approvals,votes=dict(approvals["votes"],witness=approvals["votes"]["recovery"]))
    l.row("unilateral fence",result(lambda:l.rpc("anchor","resolve",unilateral)))
    link=l.links["client"]
    link.forward.clear();link.arrived.clear()
    with ThreadPoolExecutor(7) as pool:
        delayed=pool.submit(lambda:result(lambda:l.rpc("gate","execute",a,"client")))
        assert link.arrived.wait(3)
        votes=list(pool.map(lambda _:result(lambda:l.rpc("anchor","resolve",approvals)),range(6)))
        retry=l.reservation(1)
        link.forward.set()
        delivery=delayed.result()
    assert votes==["NOT_COMMITTED"]*6
    l.row("concurrent reconciliation",l.terminal(a))
    l.row("late execute after fence",delivery)
    stale_votes=dict(approvals,target=retry["token"])
    l.row("old signed recovery votes",result(lambda:l.rpc("anchor","resolve",stale_votes)))
    l.resolve(retry)
    old=(l.root/"anchor/state.db").read_bytes()
    oldgate=(l.root/"gate/state.db").read_bytes()
    b=l.reservation(2)
    l.start("gate","after-db")
    l.row("lost response after database commit",result(lambda:l.rpc("gate","execute",b,"client")))
    l.start("gate")
    l.row("absence of finalization",l.terminal(b))
    l.row("armed cancellation",result(lambda:l.resolve(b)))
    l.row("durable gate observation",result(lambda:l.rpc("gate","observe",{})))
    l.row("finalized certificate",l.terminal(b))
    l.stop("gate")
    l.stop("anchor")
    (l.root/"anchor/state.db").write_bytes(old)
    (l.root/"gate/state.db").write_bytes(oldgate)
    l.start("anchor");l.start("gate")
    l.row("coordinated DB restoration",result(lambda:l.rpc("gate","receipt",b,"client")))
    retained=read_state(l.root/"retainer/state.db")
    target=sha(encode(retained))
    l.rpc("anchor","repair",l.approvals("repair",target,retained["revision"]))
    l.row("gate-only rollback detected",result(lambda:l.rpc("gate","receipt",b,"client")))
    newpin=l.lose_gate()
    l.rpc("anchor","replace",l.approvals("replace",newpin))
    l.row("complete gate volume rebuild",result(lambda:l.rpc("gate","recover",{})))
    receipt=l.rpc("gate","receipt",b,"client")
    assert v.verify(newpin,"receipt",receipt)["token"]==b["token"]
    l.row("exact authenticated receipt","COMMITTED")
    l.row("delayed prior-generation execution",result(lambda:l.rpc("gate","execute",b,"client")))
    # An obsolete authenticated reply on a fresh TCP exchange must fail even if
    # the server challenge is replayed. Only public test input crosses the proxy.
    with socket.socket() as proxy:
        proxy.bind(("127.0.0.1",0));proxy.listen()
        peer=l.cfg["admin"]["peers"]["witness"]
        real=peer["port"]
        peer["port"]=proxy.getsockname()[1]
        def replay():
            captured=None
            for _ in range(2):
                conn,_=proxy.accept()
                with conn,conn.makefile("rwb") as io:
                    v.send(io,"fixed challenge")
                    role,nonce,op,data,_=v.read(io)
                    if captured is None:
                        reply={"ok":{"status":"OLD"}}
                        mac=v.tag(bytes.fromhex(peer["key"]),"reply","witness",role,"fixed challenge",nonce,op,data,reply)
                        captured=[reply,mac]
                    v.send(io,captured)
        thread=threading.Thread(target=replay);thread.start()
        l.rpc("witness","approve",{})
        stale=result(lambda:l.rpc("witness","approve",{}))
        thread.join();peer["port"]=real
        l.row("stale witness reply",stale)
    l.links["anchor"].drop=True
    assert l.procs["retainer"].poll() is None
    l.row("retainer partition",result(lambda:l.rpc("gate","receipt",b,"client")))
    l.links["anchor"].drop=False
    # Restore policy only through the original independently provisioned PQ roots.
    f=l.f
    for action,changes in [("emergency-quarantine",dict(mode="quarantine",revoked_algorithms=[ED])),
                           ("recover",dict(mode="active",profile="pq-only",keys=f.effect_keys("pq-only")))]:
        f.now=int(time.time())
        doc=f.transition(action,**changes)
        l.rpc("anchor","transition",doc)
        f.anchor.policy=encode(doc["transition"]["next"])
    c=l.reservation(3)
    with ThreadPoolExecutor(6) as pool:
        replies=list(pool.map(lambda _:result(lambda:l.rpc("gate","execute",c,"client")),range(6)))
    assert replies.count("COMMITTED")==1
    l.row("PQ replacement concurrent execute",l.terminal(c))
    d=l.reservation(4)
    l.start("gate","after-arm")
    l.row("death between arm and SQL",result(lambda:l.rpc("gate","execute",d,"client")))
    l.start("gate")
    l.row("empty observation",result(lambda:l.rpc("gate","observe",{})))
    pin=l.lose_gate()
    l.row("armed gate loss replacement",result(lambda:l.rpc("anchor","replace",l.approvals("replace",pin))))
    l.row("armed gate loss resolution",result(lambda:l.resolve(d)))
    l.row("no automatic retry",result(lambda:l.rpc("gate","execute",d,"client")))


if __name__=="__main__":
    with tempfile.TemporaryDirectory() as directory:
        lab=Lab(Path(directory))
        try:
            if len(sys.argv)>1:
                assert len({x["mount_ns"] for x in lab.isolation.values()})==len(NAMES)
                Path(sys.argv[1]).with_name("isolation.json").write_bytes(encode(lab.isolation))
                Path(sys.argv[1]).with_name("trust-pins.json").write_bytes(encode({"realm":lab.realm,"pins":lab.pins}))
            main(lab)
            if len(sys.argv)>1:
                Path(sys.argv[1]).write_bytes(encode({"retained":lab.rpc("retainer","read",{},role="anchor"),"certificates":lab.certs}))
        finally:
            for name in list(lab.procs):
                lab.stop(name)
            for link in lab.links.values():
                link.server_close()

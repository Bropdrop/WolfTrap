"""External test driver. Exercises bytes on stdio and opens each committed DB read-only."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import subprocess
import tempfile

from fixtures import REF,arguments,provision,revoke
from profile import CAP,HERE,ROOT,SCAN,VERIFY,encode,measurement,sha


def check(ok, reason):
    if not ok:
        raise AssertionError(reason)


def observe(state,handle):
    path=state/"effects"/("slot-"+handle)/"slot.db"
    with sqlite3.connect(path.as_uri()+"?mode=ro",uri=True) as db:
        rows=db.execute("SELECT approval,phase,scope FROM journal ORDER BY rowid").fetchall()
        data=dict(db.execute("SELECT name,data FROM artifacts"))
    return {"journal":rows,"files":{k:{"sha256":sha(v),"bytes":len(v)} for k,v in data.items()}}


def command(state,policy,pin,client,install=HERE):
    return ["/usr/bin/python3.13","-IBS",str(install/"launch.py"),str(state),"--owner-pin",sha(encode(policy)),
            "--qualified-pin",pin,"--session","session-a","--client",client]


class Wire:
    def __init__(self,cmd):
        self.proc=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,env={},
                                   start_new_session=True,bufsize=0)
        self.n=0

    def raw(self,data):
        self.proc.stdin.write(data+b"\n")
        self.proc.stdin.flush()

    def receive(self):
        with selectors.DefaultSelector() as poll:
            poll.register(self.proc.stdout,selectors.EVENT_READ)
            check(poll.select(20),"stdio timeout")
        raw=self.proc.stdout.readline()
        return json.loads(raw) if raw else None

    def send(self,method,params=None):
        self.n+=1
        self.raw(encode({"jsonrpc":"2.0","method":method,"id":self.n,"params":params or {}}))
        return self.receive()

    def initialize(self):
        r=self.send("initialize",{"protocolVersion":"2025-11-25","clientInfo":{"name":"probe","version":"1"},
                                  "capabilities":{}})
        check(r["result"]["protocolVersion"]=="2025-11-25","initialize")
        self.raw(b'{"jsonrpc":"2.0","method":"notifications/initialized"}')

    def call(self,tool,args,**params):
        return self.send("tools/call",{"name":tool,"arguments":args,**params})["result"]["structuredContent"]["status"]

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=15)
        self.proc.stdout.close()


@contextmanager
def wire(cmd,initialize=True):
    w=Wire(cmd)
    try:
        if initialize:
            w.initialize()
        yield w
    finally:
        w.close()


def protocol(w,args,rows):
    check("error" in w.send("tools/call",{"name":SCAN,"arguments":args}),"call before init")
    w.initialize()
    nested={}
    for _ in range(20):
        nested={"x":nested}
    bad={"unknown-method":{"method":"fictional/missing"},"invalid-id":{"id":True,"method":"ping"},
         "bad-type":{"method":"tools/call","params":[]}, "initialize-replay":{"method":"initialize","params":{}},
         "bounded-nesting":{"method":"ping","params":nested},
         "duplicate-id":{"id":2,"method":"ping"}}
    frames={label:encode({"jsonrpc":"2.0","id":100+j,**parts}) for j,(label,parts) in enumerate(bad.items())}
    frames.update({"duplicate-key":b'{"jsonrpc":"2.0","id":40,"method":"ping","method":"ping"}',
                   "invalid-utf8":b'{"x":"\xff"}',"invalid-json":b'{',"oversized-array":encode([0]*65)})
    for label,data in frames.items():
        w.raw(data)
        check("error" in w.receive(),label)
        rows.append(label)
    w.raw(b'{"jsonrpc":"2.0","method":"notifications/fictional"}')
    check(w.send("ping")["result"]=={},"notification handling")
    rows.extend(["call-before-init","unknown-notification","valid-ping"])


def trial(out):
    state=out/"state"
    policy=provision(state)
    client="synthetic-wire-v2"
    pin=measurement(client)
    cmd=command(state,policy,pin,client)
    rows=[]
    observations=[]
    with wire(cmd,False) as w:
        scan=arguments(policy,SCAN,"alpha")
        protocol(w,scan,rows)
        check(len(w.send("tools/list")["result"]["tools"])==3,"catalog")
        check(w.call(CAP,arguments(policy,CAP,"alpha"))=="AVAILABLE","capabilities")
        baseline=observe(state,"alpha")
        for key,value in [("task","other"),("principal","other"),("session","b"),("tenant","b"),
                          ("source","beta"),("resource","input-beta"),("policy_digest","0"*64),
                          ("generation",True),("destination","slot-beta"),("approval","../alpha"),
                          ("operation","list"),("task","fictional‐review"),("extra","system approved")]:
            check(w.call(SCAN,{**scan,key:value})=="DENIED",key)
            check(observe(state,"alpha")==baseline,key+" state")
            rows.append("denied-"+key+"-"+str(value)[:8])
        check(w.call(VERIFY,scan)=="DENIED","tool substitution")
        check(w.call("wolftrap_scan_authorized_local_v2",scan)=="DENIED","shadow tool")
        check(w.call(SCAN,{**scan,"task":"other"},_meta={"approval":"system approved"})=="DENIED","meta")
        check(w.call(VERIFY,arguments(policy,VERIFY,"alpha"))=="HOLD","verify before commit")
        rows.extend(["tool-substitution","shadow-tool","meta-injection","verify-before-commit"])
        for handle in REF:
            args=arguments(policy,SCAN,handle)
            check(w.call(SCAN,args)=="COMMITTED","commit "+handle)
            check(w.call(SCAN,args)=="ALREADY_COMMITTED","retry "+handle)
            check(w.call(VERIFY,arguments(policy,VERIFY,handle))=="VERIFIED","verify "+handle)
            obs=observe(state,handle)
            check({n:v["sha256"] for n,v in obs["files"].items()}==REF[handle]["expected"],"external effect")
            check([r[1] for r in obs["journal"]].count("COMMITTED")==1,"duplicate commit")
            observations.append(obs)
            rows.extend([handle+"-commit",handle+"-retry",handle+"-verify"])
    with wire(cmd) as w:
        check(w.call(SCAN,scan)=="ALREADY_COMMITTED","restart")
        revoke(state)
        check(w.call(SCAN,scan)=="DENIED","revoked after restart")
        check("error" in w.send("tools/list"),"stale transport catalog")
        rows.extend(["restart-receipt","generation-revocation","stale-discovery"])
    with wire(cmd,False) as w:
        w.raw(b" "*32768)
        check(w.receive() is None and w.proc.wait()==2,"overlength framing")
        rows.append("overlength")
    before=observe(state,"alpha")
    with wire(cmd) as w:
        for _ in range(511):
            check(w.send("ping")["result"]=={},"ID budget positive control")
        check("error" in w.send("ping"),"ID budget limit")
    rows.append("session-id-budget")
    interrupted=Wire(cmd)
    interrupted.initialize()
    interrupted.proc.stdin.write(b'{"jsonrpc":"2.0","method":"tools/call"')
    os.killpg(interrupted.proc.pid,signal.SIGKILL)
    interrupted.close()
    check(observe(state,"alpha")==before,"partial frame changed slot")
    rows.append("terminated-partial-frame")
    for label in ("expired","source-replaced","source-hardlink","source-symlink","directory-change","policy-replaced"):
        alternate=out/label
        owner=provision(alternate,expired=(label=="expired"))
        path=alternate/"sources/alpha.json"
        if label=="source-replaced":
            replacement=alternate/"replacement"
            replacement.write_bytes(path.read_bytes())
            os.replace(replacement,path)
        elif label=="source-hardlink":
            os.link(path,out/"other-link")
        elif label=="source-symlink":
            path.rename(out/"moved")
            path.symlink_to(out/"moved")
        elif label=="directory-change":
            (path.parent/"new").write_bytes(b"fictional")
        elif label=="policy-replaced":
            (alternate/"control/owner.json").write_bytes(b"{}")
        with wire(command(alternate,owner,pin,client)) as w:
            status=w.call(SCAN,arguments(owner,SCAN,"alpha"))
            check(status in ("DENIED","HOLD") and observe(alternate,"alpha")=={"journal":[],"files":{}},label)
        rows.append(label)
    return {"schema":"wolftrap.mcp-002-trials/v1","cases":rows,"configuration":pin,"observations":observations}


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    out=p.parse_args().output.absolute()
    check(out.resolve()==out and not out.is_relative_to(ROOT),"external output required")
    out.mkdir(mode=0o700)
    data=trial(out)
    (out/"trials.json").write_text(json.dumps(data,indent=2)+"\n")
    print(len(data["cases"]),"passed")

"""Fault injection on four loopback TCP replicas, using fresh disposable keys."""
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

from challenge import ED
from quorum_lab import Lab
from quorum_rules import DOMAIN as APP, MEMBERS, hash_of, initial
from resurrection_node import provision
from resurrection_proof import DOMAIN, disclose, review_change, slot
from severance import rpc, sign
from verifier import Denied, wire

HERE = Path(__file__).resolve().parent


class Cluster(Lab):
    def start(self,m,crash_at=None):
        path = self.root/m
        if m not in self.children:
            provision(path)
            shutil.copyfile(path/"store",path/"genesis-backup")
        child = subprocess.Popen([sys.executable,HERE/"resurrection_node.py",path],stdout=subprocess.PIPE,text=True)
        self.children[m] = child
        self.stack.callback(self.stop,child)
        port = int(child.stdout.readline())
        for role in self.peers:
            self.peers[role][m] = {"port":port,"key":self.links[m][role]}

    def effect(self,n,ttl=120):
        cmd = super().effect(n,lifetime=30)
        cmd["lease"] = {"serial":n,"expires":int(time.time())+ttl}
        body = dict(cmd["permit"]["body"],id=hash_of(["WT008 permit",cmd["lease"]]))
        cmd["permit"] = sign(self.issuer,APP+"permit",body)
        return cmd

    def message(self,v,b,**fields):
        return dict(view=v,slot={"ledger":hash_of(self.config),"parent":b["parent"],"height":b["height"]},
                    block=b,**fields)

    def batch(self,op,msg,members="ABCD"):
        result = {}
        for m in members:
            try:
                result[m] = self.call(m,op,msg)
            except (OSError,Denied):
                pass
        return result

    def change(self,v,b,members="ABCD"):
        return self.batch("promise",self.message(v,b),members)

    def votes(self,v,b,phase,members="ABC",**fields):
        votes = self.batch(phase,self.message(v,b,**fields),members)
        return {"view":v,"digest":hash_of(b),"votes":votes}

    def decide(self,v,b,reports,members="ABC"):
        prep = self.votes(v,b,"prepare",members,reports=reports)
        return {"block":b,"commit":self.votes(v,b,"commit",members,prepared=prep)}

    def coordinate(self,v,candidate):
        job = {"peers":self.peers["gate2"],"role":"gate2","config":self.config,"floor":self.floor,
               "view":v,"history":[],"candidate":candidate}
        return json.loads(subprocess.check_output([sys.executable,HERE/"resurrection_relay.py"],input=wire(job)))

    def recover(self,cmd):
        job = {"peers":self.peers["gate2"],"role":"gate2","config":self.config,"floor":self.floor,"request":cmd}
        return json.loads(subprocess.check_output([sys.executable,HERE/"resurrection_relay.py"],input=wire(job)))


def run(folder):
    matrix,pins,proofs = {},{},{}
    def check(name,value,expected):
        if value!=expected:
            raise AssertionError((name,value,expected))
        matrix[name]=value
    def observe(name,histories,cmd,expected,floor=None):
        floor = floor or lab.floor
        check(name,disclose(lab.config,histories,floor,cmd),expected)
        pins[name] = {"genesis":hash_of(lab.config),"floor":floor}
        proofs[name] = {"config":lab.config,"request":cmd,"chains":histories}
    changes,change_pins = {},{}
    def review(name,view,b,reports,expected):
        row={"config":lab.config,"history":[],"view":view,"proposal":b,"reports":reports}
        check(name,review_change(**row),expected)
        changes[name]=row
        change_pins[name]=hash_of(lab.config)
    def fresh(stack):
        return Cluster(Path(stack.enter_context(tempfile.TemporaryDirectory())),stack)

    with ExitStack() as stack:
        lab = fresh(stack)
        x,y = (lab.block(lab.effect(i)) for i in (1,2))
        for b,members in ((x,"AB"),(y,"CD")):
            lab.votes(0,b,"prepare",members,reports={})
        check("persistent split",len(lab.votes(0,x,"prepare","ABCD",reports={})["votes"]),2)
        # Real TCP closure on the isolated relay-to-C/D paths during promise collection.
        cut = {"peers":{m:dict(p,port=p["port"] if m in "AB" else lab.cut) for m,p in lab.peers["gate1"].items()}}
        partial = {}
        for m in MEMBERS:
            try:
                partial[m] = rpc(cut,m,"gate1","promise",lab.message(1,x))
            except OSError:
                pass
        check("partition only two promises",len(partial),2)
        review("two promises insufficient",1,x,partial,False)
        check("minority cannot reopen slot",len(lab.votes(1,x,"prepare","AB",reports=partial)["votes"]),0)
        r = lab.change(1,x)
        tampered = json.loads(wire(r))
        tampered["A"]["signature"]["body"]["view"]=4
        check("altered promise rejected",len(lab.votes(1,x,"prepare",reports=tampered)["votes"]),0)
        review("authenticated new-view transcript",1,x,r,True)
        review("tampered view transcript",1,x,tampered,False)
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(lab.votes,1,b,"prepare","A",reports=r) for b in (x,y)]
            check("one prepare for competing proposals",sum(len(f.result()["votes"]) for f in futures),1)
        qc = lab.decide(1,x,r,"BCD")
        observe("split healed in new view",[[qc]],x["command"],"COMMITTED")
        lab.batch("install",qc)
        check("duplicate install",lab.call("C","install",qc),"already installed")
        check("duplicate application absent",len(lab.call("C","history",None)),1)

    with ExitStack() as stack:
        lab = fresh(stack)
        x,y = (lab.block(lab.effect(i)) for i in (3,4))
        p = lab.votes(0,x,"prepare",reports={})
        lab.votes(0,x,"commit","AB",prepared=p)
        # Kill the coordinating process after C has persisted its commit ballot.
        args = [{"peers":lab.peers["gate1"]},"C","gate1","commit",lab.message(0,x,prepared=p)]
        code = "import json,os,signal,sys; from severance import rpc; rpc(*json.load(sys.stdin)); os.kill(os.getpid(),signal.SIGKILL)"
        killed = subprocess.run([sys.executable,"-c",code],cwd=HERE,input=wire(args))
        check("coordinator killed after third commit",killed.returncode,-signal.SIGKILL)
        check("no installed copy after coordinator death",lab.call("B","history",None),[])
        lab.restart("B")
        with ThreadPoolExecutor(2) as pool:
            responses = list(pool.map(lab.recover,[x["command"]]*2))
        check("two replacement coordinators", [r["outcome"] for r in responses],["COMMITTED"]*2)
        delayed = responses[0]["proof"][0]
        observe("exact request from durable votes",[[delayed]],x["command"],"COMMITTED")
        r = lab.change(1,x,"BCD")
        check("restarted B retained prepare proof",r["B"]["prepared"]["digest"]==hash_of(x),True)
        check("conflicting proposal after decision",len(lab.votes(1,y,"prepare","BCD",reports=r)["votes"]),0)
        check("old prepare cannot authorize fresh commit",len(lab.votes(1,x,"commit","BCD",prepared=p)["votes"]),0)
        same = lab.decide(1,x,r,"BCD")
        observe("different views certify same block",[[delayed],[same]],x["command"],"COMMITTED")
        check("delayed historic certificate installed",lab.call("D","install",delayed),"installed")
        check("new view same decision idempotent",lab.call("D","install",same),"already installed")
        floorfile = lab.root/"outside-replica-floor"
        floorfile.write_bytes(wire([1,hash_of(x)]))
        lab.restart("A",restore=True)
        overwritten = lab.votes(0,y,"prepare","A",reports={})
        check("restored A equivocated",len(overwritten["votes"]),1)
        check("one rolled-back identity cannot certify fork",len(lab.votes(0,y,"prepare",reports={})["votes"]),1)
        # Restore two more identities, explicitly beyond the assumption.
        for m in "BC":
            lab.restart(m,restore=True)
        fork = lab.decide(0,y,{})
        observe("two incompatible valid histories",[[delayed],[fork]],y["command"],"UNRESOLVED")
        observe("alternate chain against retained checkpoint",[[fork]],y["command"],"UNRESOLVED",
                json.loads(floorfile.read_bytes()))
        low = json.loads(wire(delayed))
        del low["commit"]["votes"]["A"]
        observe("two signatures",[[low]],x["command"],"UNRESOLVED")
        bad = lab.effect(6)
        bad["claim"]["signatures"]=bad["claim"]["signatures"][2:]
        body = dict(bad["permit"]["body"],claim=hash_of(bad["claim"]))
        bad["permit"]=sign(lab.issuer,APP+"permit",body)
        invalid = lab.block(bad)
        now = int(time.time())
        statement = dict(slot(lab.config,initial(lab.config)),digest=hash_of(invalid),view=0,time=now)
        forged = {"block":invalid,"commit":{"digest":hash_of(invalid),"view":0,"votes":
                  {m:sign(lab.keys[m],DOMAIN+"commit/"+m,statement) for m in "ABC"}}}
        observe("quorum without owner authorization",[[forged]],bad,"UNRESOLVED")

    with ExitStack() as stack:
        lab = fresh(stack)
        x = lab.block(lab.effect(7,ttl=3))
        p = lab.votes(0,x,"prepare",reports={})
        lab.votes(0,x,"commit","A",prepared=p)
        r = lab.change(1,x)
        time.sleep(max(0,x["command"]["lease"]["expires"]-time.time())+0.05)
        check("permit expired while claim live",int(time.time())<x["command"]["claim"]["claim"]["expires"],True)
        check("fresh prepares denied after permit expiry",len(lab.votes(1,x,"prepare",reports=r)["votes"]),0)
        observe("expiry is insufficient evidence",[[]],x["command"],"UNRESOLVED")
        with ThreadPoolExecutor(2) as pool:
            futures = [pool.submit(lab.change,v,x) for v in (2,3)]
            for f in futures:
                f.result()
        check("concurrent promises never regress",len(lab.change(2,x)),0)
        check("retry highest promise",len(lab.change(3,x)),4)

    with ExitStack() as stack:
        lab = fresh(stack)
        exact=lab.effect(8)
        x=lab.block(exact)
        lab.votes(0,x,"prepare","AB",reports={})
        rev=lab.f.transition("emergency-quarantine",mode="quarantine",revoked_algorithms=[ED])
        rb=lab.block({"kind":"policy","doc":rev})
        reports=lab.change(1,rb)
        qc=lab.decide(1,rb,reports)
        check("quarantine decided during recovery",len(lab.batch("install",qc)),4)
        check("stale old-parent commits fenced",len(lab.votes(0,x,"prepare",reports={})["votes"]),0)
        newblock=dict(x,height=2,parent=hash_of(rb))
        from quorum_rules import binding
        stamp={"ledger":hash_of(lab.config),"parent":hash_of(rb),"generation":0,"binding":binding(exact)}
        newblock["command"]=dict(exact,gate=sign(lab.executor,APP+"execute",stamp))
        check("revoked claim at current parent",len(lab.votes(0,newblock,"prepare",reports={})["votes"]),0)
        observe("policy certificate alone leaves request open",[[qc]],exact,"UNRESOLVED")

    with ExitStack() as stack:
        lab = fresh(stack)
        x,y=(lab.block(lab.effect(i)) for i in (9,10))
        p=lab.votes(0,x,"prepare",reports={})
        lab.votes(0,x,"commit","AB",prepared=p)
        # Replacement starts with the other payload. It must discover and fetch x.
        reply=lab.coordinate(1,y)
        check("replacement selected carried block",reply["certificate"]["block"]==x,True)
        observe("stateless coordinator recovered carried authorization",[[reply["certificate"]]],x["command"],"COMMITTED")
        check("competing request still unresolved",lab.recover(y["command"])["outcome"],"UNRESOLVED")

    with ExitStack() as stack:
        lab=fresh(stack)
        x,y=(lab.block(lab.effect(i)) for i in (11,12))
        prepared=lab.votes(0,x,"prepare",reports={})
        lab.votes(0,x,"commit","A",prepared=prepared)
        reports=lab.change(1,y,"BCD")
        q=lab.decide(1,y,reports,"BCD")
        observe("minority commit lock superseded by safe quorum",[[q]],y["command"],"COMMITTED")
        reports=lab.change(2,x)
        check("two different prepared views reported",
              sorted({r["prepared"]["view"] for r in reports.values()}),[0,1])
        review("highest certificate selects y",2,y,reports,True)
        review("old prepared x excluded",2,x,reports,False)
        review("stale promises cannot enter next view",3,y,reports,False)
        check("lower prepared view cannot win",len(lab.votes(2,x,"prepare",reports=reports)["votes"]),0)
        q2=lab.decide(2,y,reports)
        observe("highest prepared value survives third view",[[q],[q2]],y["command"],"COMMITTED")
        # Same request and permit ID, different evidence must not disclose the terminal receipt.
        altered=dict(y["command"],claim=x["command"]["claim"])
        check("substituted recovery input",lab.recover(altered)["outcome"],"UNRESOLVED")

    with ExitStack() as stack:
        lab=fresh(stack)
        x=lab.block(lab.effect(13,ttl=3))
        r=lab.change(1,x)
        prepared=lab.votes(1,x,"prepare",reports=r)
        check("live permit reached prepared quorum",len(prepared["votes"]),3)
        time.sleep(max(0,x["command"]["lease"]["expires"]-time.time())+0.05)
        check("permit expires between prepare and commit",len(lab.votes(1,x,"commit",prepared=prepared)["votes"]),0)
        check("prepared certificate alone never discloses a receipt",lab.recover(x["command"])["outcome"],"UNRESOLVED")

    folder.mkdir(exist_ok=True,parents=True)
    for name,value in (("matrix",matrix),("pins",pins),("proofs",proofs),("changes",changes),("change-pins",change_pins)):
        (folder/(name+".json")).write_bytes(wire(value)+b"\n")
    print(f"PASS {len(matrix)} observations, {len(proofs)} public proof cases")


if __name__=="__main__":
    os.umask(0o077)
    run(Path(sys.argv[1]))

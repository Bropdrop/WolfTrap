"""Disposable target-owned SQLite ledger. All side effects are confined to this lab."""
from contextlib import closing
import json
from pathlib import Path
import secrets
import sqlite3
import sys
import time

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
import blackout
from counter import Checkpoint, increment_id
from severance import TCP, rpc, binding, sign, verify
from verifier import Denied, digest, evaluate, require, wire

ACL = {
    "target": {"auditor":{"audit"}, "admin": {"permit", "transition", "replace", "fence", "view"},
               "client": {"receipt"}, "gate": {"prepare", "execute"}},
    "gate": {"client": {"submit"}},
    "retainer": {"target": {"head", "advance"}, "auditor":{"head"}},
    "recovery":{"admin":{"approve"}}, "witness":{"admin":{"approve"}},
}
SCHEMA = """
CREATE TABLE meta(id INTEGER PRIMARY KEY CHECK(id=1), realm TEXT, revision INTEGER,
                  counter INTEGER, generation INTEGER, gate_pin TEXT, policy TEXT);
CREATE TABLE permits(id TEXT PRIMARY KEY, rid TEXT, request TEXT, policy TEXT, spent INTEGER);
CREATE TABLE reservations(token TEXT PRIMARY KEY, permit TEXT UNIQUE REFERENCES permits(id),
                          binding TEXT, epoch INTEGER, generation INTEGER);
CREATE TABLE decisions(token TEXT PRIMARY KEY REFERENCES reservations(token), rid TEXT, status TEXT, certificate TEXT);
CREATE UNIQUE INDEX one_increment_per_request ON decisions(rid) WHERE status='COMMITTED';
"""
TABLES = {"meta":"id","permits":"id","reservations":"token","decisions":"token"}


def initialize(path,realm,policy,gate_pin):
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript(SCHEMA)
        db.execute("INSERT INTO meta VALUES(1,?,0,0,1,?,?)",(realm,gate_pin,wire(policy).decode()))
        return fingerprint(snapshot(db))


def snapshot(db):
    return {name:db.execute(f"SELECT * FROM {name} ORDER BY {order}").fetchall()
            for name,order in TABLES.items()}


def fingerprint(state):
    return digest(wire(state))


def stage(name):
    """Qualification harness can pause the process at a transaction boundary."""


class Service:
    def __init__(self,name,path):
        self.name,self.path=name,path
        self.conf=json.loads((path/"config").read_bytes())
        self.keys={role:bytes.fromhex(value) for role,value in self.conf["incoming"].items()}
        self.private=MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(self.conf["seed"]))

    def dispatch(self,role,op,body):
        if self.name in ("recovery","witness"):
            return sign(self.private,"blackbox-"+self.name,body)
        if self.name=="retainer":
            with blackout.store(self.path/"state.db") as (db,state):
                if op=="advance":
                    require(state==body["old"] and body["new"]["revision"]==state["revision"]+1
                            and state["realm"]==body["new"]["realm"],"head-conflict")
                    state=body["new"]
                    db.execute("UPDATE state SET body=?",(wire(state),))
                db.commit()
                return sign(self.private,"blackbox-head",dict(state,challenge=body["challenge"]))
        if self.name=="gate":
            stage("before-prepare")
            req=dict(body,gate=self.private.public_key().public_bytes_raw().hex(),generation=self.conf["generation"])
            req["auth"]=sign(self.private,"blackbox-prepare",self.intent(req))
            ticket=rpc(self.conf,"target","gate","prepare",req)
            stage("after-prepare")
            req["token"]=ticket["token"]
            req["auth"]=sign(self.private,"blackbox-execute",dict(self.intent(req),token=req["token"]))
            result=rpc(self.conf,"target","gate","execute",req)
            stage("before-client-reply")
            return result
        return self.target(op,body)

    def intent(self,b):
        return {"realm":self.conf["realm"],"generation":b["generation"],"permit":b["permit"],"binding":binding(b)}

    def head(self,op,body):
        challenge=secrets.token_hex(24)
        cert=rpc(self.conf,"retainer","target",op,dict(body,challenge=challenge))
        result=verify(self.conf["retainer_pin"],"blackbox-head",cert)
        require(result["challenge"]==challenge,"stale-head")
        return cert

    def approvals(self,meta,op,b):
        expected={"realm":meta[1],"action":op,"revision":meta[2],"subject":b["subject"]}
        for role in ("recovery","witness"):
            require(verify(self.conf["roots"][role],"blackbox-"+role,b["votes"][role])==expected,"vote-scope")

    def target(self,op,b):
        with closing(sqlite3.connect((self.path/"state.db").as_uri()+"?mode=rw",uri=True)) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            state=snapshot(db)
            meta,=state["meta"]
            old={"realm":meta[1],"revision":meta[2],"hash":fingerprint(state)}
            head=self.head("head",{})
            require(all(head["body"][k]==v for k,v in old.items()),"UNRESOLVED-head-mismatch")
            if op=="audit":
                proof=sign(self.private,"blackbox-target-state",dict(old,challenge=b["challenge"]))
                return {"state":state,"proof":proof}
            if op=="view":
                return {"state":state,"head":head}
            if op=="receipt":
                return self.lookup(db,meta,b)
            result,changed,expires=self.mutate(db,meta,op,b)
            if changed:
                db.execute("UPDATE meta SET revision=revision+1")
                new=dict(old,revision=meta[2]+1,hash=fingerprint(snapshot(db)))
                if op in ("prepare","execute"):
                    stage("before-prepare-cas" if op=="prepare" else "before-witness-cas")
                self.head("advance",{"old":old,"new":new})
                if op in ("prepare","execute"):
                    stage("after-prepare-cas" if op=="prepare" else "after-witness-cas")
                if expires is not None:
                    require(int(time.time())<expires,"expired-at-commit")
                db.commit()
                if op in ("prepare","execute"):
                    stage("after-prepare-commit" if op=="prepare" else "after-target-commit")
            return result

    def lookup(self,db,m,b):
        row=db.execute("SELECT r.binding,d.certificate FROM reservations r LEFT JOIN decisions d USING(token) "
                       "WHERE r.permit=?",(b["permit"],)).fetchone()
        if not row or not row[1]:
            return {"status":"UNRESOLVED"}
        require(row[0]==wire(binding(b)).decode(),"receipt-binding")
        return json.loads(row[1])

    def mutate(self,db,m,op,b):
        realm,rev,value,gen,pin,policy=m[1:]
        policy=json.loads(policy)
        if op=="permit":
            raw=wire(b["request"])
            rid=increment_id(raw,"specimen")
            require(policy["mode"]=="active","quarantine")
            permit=secrets.token_hex(24)
            db.execute("INSERT INTO permits VALUES(?,?,?,?,0)",(permit,rid,digest(raw),fingerprint(policy)))
            return {"permit":permit},True,None
        if op=="transition":
            setup=self.conf["setup"]
            cp=Checkpoint(wire(setup["genesis"]),setup["pin"],setup["recovery"],setup["witness"],
                          "specimen",lambda:int(time.time()))
            cp.policy=wire(policy)
            cp.transition(wire(b))
            db.execute("UPDATE meta SET policy=?",(cp.policy.decode(),))
            return {"epoch":json.loads(cp.policy)["epoch"]},True,b["transition"]["expires"]
        if op=="replace":
            self.approvals(m,op,b)
            require(b["subject"]!=pin,"same-gate")
            from verifier import public_types
            public_types()["ml-dsa-65-v1"].from_public_bytes(bytes.fromhex(b["subject"]))
            db.execute("UPDATE meta SET generation=generation+1,gate_pin=?",(b["subject"],))
            return {"generation":gen+1},True,None
        if op=="fence":
            self.approvals(m,op,b)
            row=db.execute("SELECT token,binding,epoch,generation FROM reservations WHERE permit=?",(b["subject"],)).fetchone()
            require(row is not None,"unknown-reservation")
            token,coord,epoch,generation=row
            existing=db.execute("SELECT certificate FROM decisions WHERE token=?",(token,)).fetchone()
            if existing:
                return json.loads(existing[0]),False,None
            coord=json.loads(coord)
            return self.decide(db,realm,rev,token,b["subject"],coord,epoch,generation,"NOT_COMMITTED",value),True,None
        require(op in ("prepare","execute") and b["gate"]==pin and b["generation"]==gen,"retired-gate")
        intent=self.intent(b)
        expected=intent if op=="prepare" else dict(intent,token=b["token"])
        require(verify(pin,"blackbox-"+op,b["auth"])==expected,"gate-auth")
        coord=intent["binding"]
        expires=evaluate(wire(b["evidence"]),wire(b["request"]),policy,int(time.time()),expected_request_id=coord[0])[1]
        permit=b["permit"]
        supplied=db.execute("SELECT rid,request,policy,spent FROM permits WHERE id=?",(permit,)).fetchone()
        require(supplied==(coord[0],coord[1],fingerprint(policy),0),"invalid-or-consumed-permit")
        require(not db.execute("SELECT 1 FROM decisions WHERE rid=? AND status='COMMITTED'",(coord[0],)).fetchone(),"used-request")
        serial=wire(coord).decode()
        row=db.execute("SELECT token,binding,epoch,generation FROM reservations WHERE permit=?",(permit,)).fetchone()
        if op=="prepare" and row is None:
            token=secrets.token_hex(24)
            db.execute("INSERT INTO reservations VALUES(?,?,?,?,?)",(token,permit,serial,policy["epoch"],gen))
            return {"token":token},True,expires
        require(row and row[1:]==(serial,policy["epoch"],gen),"stale-reservation")
        if op=="prepare":
            return {"token":row[0]},False,None
        require(b["token"]==row[0],"ticket-binding")
        stage("before-target-write")
        db.execute("UPDATE meta SET counter=counter+1")
        stage("after-counter-write")
        cert=self.decide(db,realm,rev,row[0],permit,coord,policy["epoch"],gen,"COMMITTED",value+1)
        return cert,True,expires

    def decide(self,db,realm,rev,token,permit,coord,epoch,generation,status,value):
        changed=db.execute("UPDATE permits SET spent=1 WHERE id=? AND spent=0",(permit,)).rowcount
        require(changed==1,"consumption-conflict")
        if status=="COMMITTED":
            stage("after-permit-write")
        policy_pin,=db.execute("SELECT policy FROM permits WHERE id=?",(permit,)).fetchone()
        body={"realm":realm,"policy":policy_pin,"revision":rev+1,"token":token,"permit":permit,"binding":coord,
              "epoch":epoch,"generation":generation,"status":status,"value":value}
        cert=sign(self.private,"blackbox-target-decision",body)
        db.execute("INSERT INTO decisions VALUES(?,?,?,?)",(token,coord[0],status,wire(cert).decode()))
        if status=="COMMITTED":
            stage("after-receipt-write")
        return cert


def main():
    name=sys.argv[1]
    node=Service(name,Path("/private"))
    blackout.ACCESS=ACL
    with TCP(("127.0.0.1",node.conf["port"]),blackout.Handler) as server:
        server.service=node
        print("ready",flush=True)
        server.serve_forever()


if __name__=="__main__":
    main()

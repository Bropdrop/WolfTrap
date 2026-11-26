"""SEVERANCE disposable services. The retained anchor serializes every grant and fence."""
import json
import hmac
import os
from pathlib import Path
import secrets
import socket
import socketserver
import sys
import time

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
from blackout import read, send, tag, store, create_store, Handler
from counter import Checkpoint, increment_id
from verifier import Denied, digest, evaluate, public_types, require, wire

DOMAIN = "WT-CRYPTO-005/v1"
ACCESS = {"retainer":{"anchor":{"read","advance"}}, "anchor":{"client":{"reserve","query"}, "gate":{"arm","finish","view"},
                    "admin":{"permit","transition","resolve","replace","repair","view"}},
          "gate":{"client":{"execute","receipt"}, "admin":{"recover","observe"}},
          "recovery":{"admin":{"approve"}}, "witness":{"admin":{"approve"}}}


def sign(key, role, body):
    raw = wire([DOMAIN,role,body])
    return {"body":body,"signature":key.sign(raw).hex()}


def verify(pin, role, cert):
    try:
        public_types()["ml-dsa-65-v1"].from_public_bytes(bytes.fromhex(pin)).verify(
            bytes.fromhex(cert["signature"]),wire([DOMAIN,role,cert["body"]]))
    except Exception as exc:
        raise Denied("certificate") from exc
    return cert["body"]


def rpc(config, target, role, op, body):
    peer = config["peers"][target]
    key = bytes.fromhex(peer["key"])
    with socket.create_connection(("127.0.0.1",peer["port"]),timeout=3) as sock, sock.makefile("rwb") as stream:
        challenge = read(stream)
        header = [target,role,challenge,secrets.token_hex(32),op,body]
        send(stream,[role,header[3],op,body,tag(key,"request",*header)])
        reply,mac = read(stream)
        require(hmac.compare_digest(mac,tag(key,"reply",*header,reply)), "stale-or-foreign-response")
        if "error" in reply:
            raise Denied(reply["error"])
        return reply["ok"]


def binding(body):
    raw = wire(body["request"])
    return [increment_id(raw,"specimen"),digest(raw),digest(wire(body["evidence"]))]


def evaluate_current(state, body):
    rid, req, _ = binding(body)
    require(req in state["permits"],"disposable-permit")
    return evaluate(wire(body["evidence"]),wire(body["request"]),state["policy"],
                    int(time.time()),expected_request_id=rid)[1]


def b_digest(value):
    return digest(wire(value))


class Node:
    def __init__(self,name,path):
        self.name,self.path = name,path
        self.conf=json.loads((path/"config").read_bytes())
        self.keys={k:bytes.fromhex(v) for k,v in self.conf["incoming"].items()}
        self.private=MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(self.conf["seed"]))

    def anchor(self,op,body):
        reply=rpc(self.conf,"anchor","gate",op,body)
        return verify(self.conf["anchor_pin"],"anchor",reply)

    def dispatch(self,role,op,body):
        if self.name in ("witness","recovery"):
            return sign(self.private,self.name,body)
        if self.name=="gate":
            return self.gate(op,body)
        if self.name=="retainer":
            with store(self.path/"state.db") as (db,state):
                if op=="advance":
                    require(b_digest(state)==body["prior"] and body["next"]["revision"]==state["revision"]+1,
                            "retainer-conflict")
                    state=body["next"]
                    db.execute("UPDATE state SET body=?",(wire(state),))
                db.commit()
                return sign(self.private,"retainer",state)
        with store(self.path/"state.db") as (db,state):
            def retained(action,data):
                cert=rpc(self.conf,"retainer","anchor",action,data)
                return verify(self.conf["retainer_pin"],"retainer",cert)
            live=retained("read",{})
            if op=="repair":
                self.approval(live,op,body)
                require(body["target"]==b_digest(live),"repair-binding")
                db.execute("UPDATE state SET body=?",(wire(live),))
                db.commit()
                return sign(self.private,"anchor",{"status":"REPAIRED","revision":live["revision"]})
            require(state==live,"coordinated-rollback")
            result,changed=self.step(state,op,body)
            if changed:
                state["revision"]+=1
                require(retained("advance",{"prior":b_digest(live),"next":state})==state,"retainer-state")
                db.execute("UPDATE state SET body=?",(wire(state),))
            # Issue an attestation only after the state transaction is durable.
            db.commit()
            return sign(self.private,"anchor",dict(result,revision=state["revision"],realm=self.conf["realm"]))

    def approval(self,s,op,b):
        expected={"action":op,"revision":s["revision"],"realm":self.conf["realm"],"target":b["target"]}
        for role in ("recovery","witness"):
            require(verify(self.conf["roots"][role],role,b["votes"][role])==expected,"approval-scope")

    def step(self,s,op,b):
        pending=s["pending"]
        if op=="view":
            return {"pending":pending,"journal":s["journal"],"gate_pin":s["gate_pin"],"generation":s["generation"]},False
        if op=="query":
            token=b["token"]
            decision=s["terminal"].get(token)
            if decision:
                require(binding(b)==decision["ticket"]["binding"],"receipt-binding")
                return decision,False
            return {"status":"UNRESOLVED","token":token},False
        if op=="reserve":
            coord=binding(b)
            expires=evaluate_current(s,b)
            require(pending is None and coord[0] not in s["used"],"busy-or-consumed")
            ticket={"token":secrets.token_hex(24),"binding":coord,"generation":s["generation"],
                    "expires":expires,"prior":digest(wire(s["journal"])),"epoch":s["policy"]["epoch"]}
            s["pending"]={"phase":"RESERVED","ticket":ticket}
            return ticket,True
        if op=="arm":
            require(pending and pending["phase"]=="RESERVED","late-or-already-armed")
            ticket=pending["ticket"]
            require(ticket["token"]==b["token"] and ticket["binding"]==binding(b)
                    and ticket["generation"]==b["generation"] and ticket["prior"]==b["prior"],"stale-gate")
            expected={"token":ticket["token"],"generation":s["generation"],"prior":ticket["prior"]}
            require(verify(s["gate_pin"],"arm-request",b["gate_auth"])==expected,"arm-identity")
            evaluate_current(s,b)
            pending["phase"]="ARMED"
            return ticket,True
        if op=="finish":
            proof=verify(s["gate_pin"],"gate-commit",b["proof"])
            require(pending and pending["phase"]=="ARMED" and proof==pending["ticket"],"receipt-scope")
            token=proof["token"]
            decision={"status":"COMMITTED","ticket":proof,"proof":b["proof"],"gate_pin":s["gate_pin"],"lineage":s["lineage"]}
            s["journal"].append(proof)
            s["used"].append(proof["binding"][0])
            s["permits"].remove(proof["binding"][1])
            s["terminal"][token]=decision
            s["pending"]=None
            return decision,True
        if op=="resolve":
            token=b["target"]
            if token in s["terminal"]:
                return s["terminal"][token],False
            self.approval(s,op,b)
            require(pending and pending["ticket"]["token"]==token,"unknown-reservation")
            if pending["phase"]!="RESERVED":
                return {"status":"UNRESOLVED","token":token},False
            ticket=pending["ticket"]
            decision={"status":"NOT_COMMITTED","ticket":ticket,"votes":b["votes"],"fence_revision":s["revision"]+1}
            s["terminal"][token]=decision
            s["pending"]=None
            s["permits"].remove(ticket["binding"][1])
            return decision,True
        require(pending is None,"unresolved-reservation")
        if op=="replace":
            self.approval(s,op,b)
            public_types()["ml-dsa-65-v1"].from_public_bytes(bytes.fromhex(b["target"]))
            require(b["target"]!=s["gate_pin"],"same-incarnation")
            s["lineage"].append({"pin":b["target"],"revision":s["revision"],"votes":b["votes"]})
            s["gate_pin"]=b["target"]
            s["generation"]+=1
        elif op=="permit":
            increment_id(wire(b),"specimen")
            require(s["policy"]["mode"]=="active","quarantine")
            if digest(wire(b)) not in s["permits"]:
                s["permits"].append(digest(wire(b)))
        elif op=="transition":
            setup=self.conf["setup"]
            cp=Checkpoint(wire(setup["genesis"]),setup["pin"],setup["recovery"],setup["witness"],
                          "specimen",lambda:int(time.time()))
            cp.policy=wire(s["policy"])
            cp.transition(wire(b))
            s["policy"]=json.loads(cp.policy)
            s["permits"]=[]
        else:
            raise Denied("operation")
        return {"status":"OK"},True

    def gate(self,op,b):
        with store(self.path/"state.db") as (db,s):
            view=self.anchor("view",{})
            own=self.private.public_key().public_bytes_raw().hex()
            require(view["gate_pin"]==own,"retired-gate")
            if op=="recover":
                require(view["pending"] is None and s["generation"] is None,"rebuild-blocked")
                s.update(generation=view["generation"],journal=view["journal"])
            elif op=="observe":
                pending=view["pending"]
                require(pending and s["journal"]==view["journal"]+[pending["ticket"]],"no-positive-proof")
                return self.anchor("finish",{"proof":sign(self.private,"gate-commit",pending["ticket"])})
            else:
                require(s["generation"]==view["generation"] and s["journal"]==view["journal"],"rollback-or-pending")
                if op=="receipt":
                    coord=binding(b)
                    item=next((t for t in s["journal"] if t["binding"]==coord),None)
                    require(item is not None,"receipt-binding")
                    return sign(self.private,"receipt",item)
                identity={"token":b["token"],"generation":s["generation"],"prior":digest(wire(s["journal"]))}
                ticket=self.anchor("arm",dict(b,**identity,gate_auth=sign(self.private,"arm-request",identity)))
                require(ticket["binding"]==binding(b) and ticket["token"]==b["token"],"ticket-scope")
                s["journal"].append({k:v for k,v in ticket.items() if k not in ("revision","realm")})
            db.execute("UPDATE state SET body=?",(wire(s),))
            if op=="execute":
                require(int(time.time())<ticket["expires"],"expired")
            db.commit()
            if op=="execute":
                return self.anchor("finish",{"proof":sign(self.private,"gate-commit",s["journal"][-1])})
            return {"status":"RESTORED","value":len(s["journal"])}


class TCP(socketserver.ThreadingMixIn,socketserver.TCPServer):
    allow_reuse_address=True
    daemon_threads=True


def serve():
    name=sys.argv[1]
    node=Node(name,Path("/private"))
    # Reuse BLACKOUT II's bounded challenge/response server with this service ACL.
    import blackout
    blackout.ACCESS=ACCESS
    with TCP(("127.0.0.1",node.conf["port"]),Handler) as server:
        server.service=node
        print(json.dumps({"ready":name,"uid":os.getuid(),"gid":os.getgid(),
                          "mount_ns":os.readlink("/proc/self/ns/mnt"),"user_ns":os.readlink("/proc/self/ns/user"),
                          "uid_map":Path("/proc/self/uid_map").read_text().strip(),
                          "visible_roots":sorted(os.listdir("/"))}),flush=True)
        server.serve_forever()


if __name__=="__main__":
    serve()

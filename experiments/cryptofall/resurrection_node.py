"""Single-height view changes repeat at each certified ledger parent."""
import json
import socketserver
import sqlite3
import sys
import time
from pathlib import Path

import blackout
from quorum_node import Replica
from quorum_rules import advance, binding, hash_of
from resurrection_proof import DOMAIN, APP, MEMBERS, ballots, lease, natural, slot
from severance import sign, verify
from verifier import require, wire


def provision(path):
    with sqlite3.connect(path/"store") as db:
        db.executescript("""
          CREATE TABLE rounds(height INTEGER PRIMARY KEY, view INTEGER, report BLOB, prepared BLOB);
          CREATE TABLE ballots(height INTEGER, view INTEGER, phase TEXT, digest TEXT, signature BLOB,
                               proposal BLOB, PRIMARY KEY(height,view,phase));
        """)


def new_view(config, scope, view, reports, candidate):
    if view == 0:
        require(reports == {}, "initial view")
        return
    require(set(reports) <= set(MEMBERS) and len(reports)>=3, "promise quorum")
    carried = []
    for member,r in reports.items():
        proof = r["prepared"]
        body = verify(config["replicas"][member], DOMAIN+"promise/"+member,r["signature"])
        require(body == dict(scope,view=view,prepared=hash_of(proof)), "promise scope")
        if proof is not None:
            ballots(config,scope,"prepare",proof)
            require(proof["view"] < view, "previous preparation")
            carried.append((proof["view"],proof["digest"]))
    if carried:
        highest = max(v for v,_ in carried)
        require({d for v,d in carried if v==highest} == {candidate}, "highest prepared")


class Member(Replica):
    def dispatch(self,role,op,msg):
        with sqlite3.connect((self.path/"store").as_uri()+"?mode=rw",uri=True) as db:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            state = json.loads(db.execute("SELECT data FROM current").fetchone()[0])
            scope = slot(self.public,state)
            h = scope["height"]
            if op == "history":
                return [json.loads(row[0]) for row in db.execute("SELECT qc FROM history ORDER BY height")]
            if op == "payload":
                row = db.execute("SELECT proposal FROM ballots WHERE digest=? LIMIT 1",(msg,)).fetchone()
                require(row, "unavailable payload")
                return json.loads(row[0])
            if op == "lookup":
                bound = binding(msg)
                grant = verify(self.public["permit"],APP+"permit",msg["permit"])
                require(grant == {"ledger":scope["ledger"], "id":bound["permit"], "operation":bound["operation"],
                                  "claim":bound["evidence"], "policy":msg["claim"]["claim"]["policy"]},"lookup")
                return [[json.loads(raw),v,json.loads(sig)] for raw,v,sig in
                        db.execute("SELECT proposal,view,signature FROM ballots WHERE phase='commit'")
                        if json.loads(raw)["receipt"].get("binding")==bound]
            if op == "install":
                b,cert = msg["block"],msg["commit"]
                if b["height"] < h:
                    row = db.execute("SELECT qc FROM history WHERE height=?",(b["height"],)).fetchone()
                    require(row and json.loads(row[0])["block"]==b,"history conflict")
                    return "already installed"
                require(hash_of(b)==cert["digest"], "commit value")
                for t in ballots(self.public,scope,"commit",cert):
                    lease(b["command"],t)
                    successor = advance(self.public,state,b,t)
                db.execute("INSERT INTO history VALUES(?,?)",(h,wire(msg)))
                db.execute("UPDATE current SET data=?",(wire(successor),))
                return "installed"
            require(scope == msg["slot"] and natural(msg["view"]), "slot")
            v = msg["view"]
            db.execute("INSERT OR IGNORE INTO rounds VALUES(?,0,NULL,NULL)",(h,))
            promised,report,prepared = db.execute("SELECT view,report,prepared FROM rounds WHERE height=?",(h,)).fetchone()
            if op=="promise":
                require(v>0 and v>=promised, "obsolete promise")
                if v==promised:
                    return json.loads(report)
                proof = json.loads(prepared) if prepared else None
                signed = sign(self.key,DOMAIN+"promise/"+self.member,dict(scope,view=v,prepared=hash_of(proof)))
                result = {"signature":signed,"prepared":proof}
                db.execute("UPDATE rounds SET view=?,report=? WHERE height=?",(v,wire(result),h))
                return result
            require(op in ("prepare","commit") and promised==v, "obsolete ballot")
            b = msg["block"]
            d = hash_of(b)
            if op=="prepare":
                new_view(self.public,scope,v,msg["reports"],d)
            else:
                proof = msg["prepared"]
                ballots(self.public,scope,"prepare",proof)
                require(proof["view"] == v and proof["digest"] == d, "stale prepare")
            row = db.execute("SELECT digest,signature FROM ballots WHERE height=? AND view=? AND phase=?",(h,v,op)).fetchone()
            if row:
                require(row[0]==d, "double ballot")
                return json.loads(row[1])
            now = int(time.time())
            lease(b["command"],now)
            advance(self.public,state,b,now)
            sig = sign(self.key,DOMAIN+op+"/"+self.member,dict(scope,view=v,digest=d,time=now))
            db.execute("INSERT INTO ballots VALUES(?,?,?,?,?,?)",(h,v,op,d,wire(sig),wire(b)))
            if op=="commit":
                db.execute("UPDATE rounds SET prepared=? WHERE height=?",(wire(proof),h))
            return sig


if __name__ == "__main__":
    with socketserver.ThreadingTCPServer(("127.0.0.1",0),blackout.Handler) as server:
        server.service = Member(Path(sys.argv[1]).resolve())
        blackout.ACCESS[server.service.member] = {role:("prepare","commit","promise","install","history","lookup","payload")
                                                 for role in server.service.keys}
        print(server.server_address[1],flush=True)
        server.serve_forever()

"""Read-only verifier. Trusted keys and a fresh audit challenge are external inputs."""
import hashlib
import json
from pathlib import Path
import sys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PublicKey


def encoded(obj):
    return json.dumps(obj,sort_keys=True,separators=(",",":")).encode()


def digest(obj):
    return hashlib.sha256(encoded(obj)).hexdigest()


def check(test):
    if not test:
        raise ValueError("inconsistent evidence")


def signed(pin,role,cert):
    pub=MLDSA65PublicKey.from_public_bytes(bytes.fromhex(pin))
    pub.verify(bytes.fromhex(cert["signature"]),encoded(["WT-CRYPTO-005/v1",role,cert["body"]]))
    return cert["body"]


def adjudicate(pins,challenge,audit,head,permit,binding,*,target_claims=(),replicated_logs=()):
    """Ordinary log content carries no vote. Conflicting pinned target claims freeze."""
    try:
        state=audit["state"]
        m,=state["meta"]
        expected={"realm":pins["realm"],"revision":m[2],"hash":digest(state),"challenge":challenge}
        check(m[1]==pins["realm"])
        check(signed(pins["target"],"blackbox-target-state",audit["proof"])==expected)
        check(signed(pins["retainer"],"blackbox-head",head)==expected)
        permits={p[0]:p for p in state["permits"]}
        reservations={r[0]:r for r in state["reservations"]}
        issued=set()
        committed=[]
        spent=set()
        selected=None
        for token,rid,status,raw in state["decisions"]:
            b=signed(pins["target"],"blackbox-target-decision",json.loads(raw))
            r=reservations[token]
            p=permits[r[1]]
            check(b["realm"]==m[1] and b["status"]==status and b["revision"]<=m[2])
            check((token,p[0],json.loads(r[2]),r[3],r[4])==
                  (b["token"],b["permit"],b["binding"],b["epoch"],b["generation"]))
            check(rid==p[1]==b["binding"][0] and p[2]==b["binding"][1] and p[3]==b["policy"] and p[4]==1 and p[0] not in spent)
            spent.add(p[0])
            if status=="COMMITTED":
                check(rid not in issued)
                issued.add(rid)
                committed.append(b["value"])
            else:
                check(status=="NOT_COMMITTED")
            if permit==p[0] and binding==b["binding"]:
                selected=b
        check(sorted(committed)==list(range(1,m[3]+1)))
        check(spent=={p[0] for p in permits.values() if p[4]})
        if selected is None:
            return "UNRESOLVED"
        for cert in target_claims:
            b=signed(pins["target"],"blackbox-target-decision",cert)
            check(b["realm"]==pins["realm"])
            same_effect=(b["status"]==selected["status"]=="COMMITTED" and b["binding"][0]==binding[0])
            if b["token"]==selected["token"] or b["permit"]==permit or same_effect:
                check(b==selected)
        return selected["status"]
    except (KeyError,TypeError,ValueError,IndexError,InvalidSignature):
        return "UNRESOLVED"


if __name__=="__main__":
    folder=Path(sys.argv[1])
    expected=json.loads(Path(__file__).with_name("blackbox_expected.json").read_text())
    rows=[json.loads(s) for s in (folder/"matrix.jsonl").read_text().splitlines()]
    check(rows==expected)
    packets=json.loads((folder/"audit.json").read_text())
    pins=json.loads((folder/"pins.json").read_text())
    check(set(packets)=={r[0] for r in rows})
    increments=set()
    for name,outcome,value in rows:
        packet=packets[name]
        obs=packet["sql_observation"]
        decisions=obs["decisions"]
        committed=[d[2] for d in decisions if d[1]=="COMMITTED"]
        check(obs["value"]==value==len(set(committed))==len(committed))
        expected_id=2 if packet["fixture"] in ("race","revocation") else 1
        check(all(rid==f"{expected_id:032x}" for rid in committed))
        for permit,status,rid,_ in decisions:
            if status=="COMMITTED":
                increments.add((packet["fixture"],permit,rid))
        check(obs["spent"]==sorted(d[0] for d in decisions))
        check(all(json.loads(d[3])[0]==d[2] for d in decisions))
        result=adjudicate(pins[packet["fixture"]],**packet["inputs"])
        check(result==outcome)
        if result!="UNRESOLVED":
            check(packet["inputs"]["audit"]["state"]["meta"][0][3]==value)
    check(len(increments)==12)
    print(f"PASS: {len(rows)} crash and evidence outcomes")

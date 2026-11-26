"""Stateless local relay. Exact recovery only reads durable ballots and histories."""
import json
import sys
from resurrection_proof import ballots, chain, disclose, natural, slot
from resurrection_node import new_view
from quorum_rules import hash_of
from severance import rpc
from verifier import Denied, require


def recover(job):
    cfg,request = job["config"],job["request"]
    histories,candidates = [],{}
    for member in job["peers"]:
        try:
            history = rpc(job,member,job["role"],"history",None)
            chain(cfg,history)
            histories.append(history)
            for block,v,sig in rpc(job,member,job["role"],"lookup",request):
                d = hash_of(block)
                qc = candidates.setdefault((d,v),{"block":block,"commit":{"digest":d,"view":v,"votes":{}}})
                qc["commit"]["votes"][member] = sig
        except (OSError,Denied,ValueError,TypeError,KeyError):
            continue
    prefixes = {hash_of(cfg):[]}
    for hist in histories:
        for i,qc in enumerate(hist):
            prefixes[hash_of(qc["block"])] = hist[:i+1]
    for qc in candidates.values():
        parent = qc["block"]["parent"]
        if parent in prefixes and len(qc["commit"]["votes"])>=3:
            histories.append(prefixes[parent]+[qc])
    result = disclose(cfg,histories,job["floor"],request)
    return {"outcome":result,"proof":max(histories,key=len) if result!="UNRESOLVED" else []}


def coordinate(job):
    """Attempt one externally requested view. A stalled attempt never releases a permit."""
    cfg,view = job["config"],job["view"]
    state,heads = chain(cfg,job["history"])
    h,d = job["floor"]
    require(natural(h) and h<len(heads) and heads[h]==d,"retained floor")
    scope = slot(cfg,state)
    def collect(op,msg):
        answers = {}
        for m in job["peers"]:
            try:
                answers[m] = rpc(job,m,job["role"],op,msg)
            except (OSError,Denied):
                continue
        return answers
    base = {"view":view,"slot":scope}
    reports = collect("promise",base) if view else {}
    candidate = job["candidate"]
    chosen = hash_of(candidate)
    carried = [r["prepared"] for r in reports.values() if r["prepared"] is not None]
    if carried:
        chosen = max(carried,key=lambda c:c["view"])["digest"]
    new_view(cfg,scope,view,reports,chosen)
    if hash_of(candidate)!=chosen:
        candidates = collect("payload",chosen)
        candidate = next((b for b in candidates.values() if hash_of(b)==chosen),None)
        require(candidate is not None,"unavailable prepared value")
    msg = dict(base,block=candidate)
    def certify(phase,**fields):
        votes = collect(phase,dict(msg,**fields))
        cert = {"view":view,"digest":chosen,"votes":votes}
        ballots(cfg,scope,phase,cert)
        return cert
    prepared = certify("prepare",reports=reports)
    qc = {"block":candidate,"commit":certify("commit",prepared=prepared)}
    chain(cfg,job["history"]+[qc])
    collect("install",qc)
    return {"outcome":"CERTIFIED", "certificate":qc}


if __name__=="__main__":
    job = json.load(sys.stdin)
    try:
        answer = coordinate(job) if "candidate" in job else recover(job)
    except (Denied,KeyError,TypeError,ValueError,IndexError):
        answer = {"outcome":"UNRESOLVED"}
    print(json.dumps(answer))

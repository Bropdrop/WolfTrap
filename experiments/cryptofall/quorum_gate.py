"""Stateless authenticated relay. Gates have link credentials, no voting or effect keys."""
import json
import sys
from concurrent.futures import ThreadPoolExecutor

from quorum_review import recover, replay
from quorum_rules import certified, hash_of
from severance import rpc
from verifier import Denied, require


def lookup(job):
    """Recover from the exact client envelope without a retained proposal or a new vote."""
    config, exact = job["config"], job["exact"]
    histories, candidates = [], {}
    prefixes = {hash_of(config): []}
    for member in job["peers"]:
        try:
            reply = rpc(job, member, job["role"], "lookup", exact)
            history = reply["history"]
            _, heads = replay(config, history)
            for height, head in enumerate(heads):
                prefixes[head] = history[:height]
            histories.append(history)
            for block, cert in reply["locks"]:
                group = candidates.setdefault(hash_of(block), {"block":block,"votes":{}})
                group["votes"][member] = cert
        except (Denied, OSError, KeyError, ValueError, TypeError):
            continue
    for qc in candidates.values():
        parent = prefixes.get(qc["block"]["parent"])
        if parent is not None and len(qc["votes"]) >= 3:
            histories.append(parent + [qc])
    outcome = recover(config,histories,job["floor"],exact)
    if outcome == "UNRESOLVED":
        return {"outcome":outcome}
    proof = max(histories,key=len)
    state, _ = replay(config,proof)
    receipt = state["requests"][exact["operation"]["request_id"]]
    return {"outcome":outcome, "receipt":receipt, "proof":proof}


def execute(job):
    if "exact" in job:
        return lookup(job)
    config, block = job["config"], job["block"]
    history = job["history"]
    state, heads = replay(config, history)
    height, pin = job["floor"]
    require(0 <= height < len(heads) and heads[height] == pin, "floor")
    creds = {"peers": job["peers"]}
    def call(member, op, obj):
        return rpc(creds, member, job["role"], op, obj)

    def vote(member):
        try:
            try:
                return call(member, "locked", block)
            except Denied:
                return call(member, "vote", block)
        except (Denied, OSError):
            return None

    members = list(creds["peers"])
    with ThreadPoolExecutor(len(members)) as pool:
        ballots = dict(zip(members, pool.map(vote, members)))
    qc = {"block": block, "votes": {k: v for k, v in ballots.items() if v}}
    try:
        certified(config, state, qc)
    except Denied:
        return {"outcome": "UNRESOLVED", "qc": qc}
    for member in members:
        try:
            call(member, "install", qc)
        except (Denied, OSError):
            pass
    if block["command"]["kind"] in ("policy", "replace"):
        return {"outcome": block["command"]["kind"].upper(), "qc": qc}
    outcome = recover(config, [history + [qc]], job["floor"], block["command"])
    return {"outcome": outcome, "qc": qc}


if __name__ == "__main__":
    print(json.dumps(execute(json.load(sys.stdin))))

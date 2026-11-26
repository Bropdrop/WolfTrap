"""Public WT-008 wire and offline decision verifier. No replica or coordinator imports."""
import json
import sys
from pathlib import Path

from quorum_review import interpret
from quorum_rules import DOMAIN as APP, MEMBERS, binding, hash_of, initial
from severance import verify
from verifier import Denied, require

DOMAIN = "WT-CRYPTO-008/"


def slot(config, state):
    return {"ledger": hash_of(config), "height": state["height"] + 1, "parent": state["head"]}


def natural(v):
    return type(v) is int and 0 <= v < 2**63


def ballots(config, scope, phase, cert):
    view, block, signatures = cert["view"], cert["digest"], cert["votes"]
    require(natural(view) and isinstance(block,str) and len(block)==64, "ballot fields")
    require(set(signatures) <= set(MEMBERS) and len(signatures) >= 3, "quorum")
    times = []
    for member, sig in signatures.items():
        body = verify(config["replicas"][member], DOMAIN+phase+"/"+member, sig)
        t = body["time"]
        require(natural(t) and body == dict(scope,view=view,digest=block,time=t), "ballot scope")
        times.append(t)
    return times


def lease(cmd, now):
    if cmd["kind"] == "effect":
        token = cmd["lease"]
        require(set(token) == {"serial","expires"} and natural(token["expires"])
                and token["expires"] > now and cmd["permit"]["body"]["id"] == hash_of(["WT008 permit",token]),
                "permit deadline")


def chain(config, history):
    state = initial(config)
    heads = [state["head"]]
    for qc in history:
        block = qc["block"]
        cert = qc["commit"]
        require(hash_of(block) == cert["digest"], "receipt digest")
        for t in ballots(config, slot(config,state), "commit", cert):
            lease(block["command"],t)
            next_state = interpret(config,state,block,t)
        state = next_state
        heads.append(state["head"])
    return state,heads


def disclose(config, evidence, floor, request):
    try:
        chains = [chain(config,h) for h in evidence]
        require(chains,"no evidence")
        state,heads = max(chains,key=lambda pair:len(pair[1]))
        height,head = floor
        require(natural(height) and height < len(heads) and heads[height] == head,"retained floor")
        require(all(heads[:len(h)] == h for _,h in chains),"contradictory certificates")
        exact = binding(request)
        grant = verify(config["permit"],APP+"permit",request["permit"])
        require(grant == {"ledger":heads[0],"id":exact["permit"],"operation":exact["operation"],
                          "claim":exact["evidence"],"policy":request["claim"]["claim"]["policy"]}, "exact permit")
        receipt = state["requests"][exact["request_id"]]
        require(exact == receipt["binding"], "exact receipt")
        return receipt["outcome"]
    except (Denied, KeyError, ValueError, TypeError, IndexError):
        return "UNRESOLVED"


def review_change(config,history,view,proposal,reports):
    """Public review of safe-value selection, separate from the signer implementation."""
    try:
        state,_ = chain(config,history)
        scope = slot(config,state)
        require(proposal["parent"] == scope["parent"] and proposal["height"] == scope["height"]
                and natural(view) and view>0 and len(reports)>=3 and set(reports)<=set(MEMBERS), "scope")
        carries = {}
        for member,record in reports.items():
            proof = record["prepared"]
            promise = verify(config["replicas"][member],DOMAIN+"promise/"+member,record["signature"])
            require(promise==dict(scope,view=view,prepared=hash_of(proof)), "promise")
            if proof is not None:
                ballots(config,scope,"prepare",proof)
                require(proof["view"]<view, "future evidence")
                carries.setdefault(proof["view"],set()).add(proof["digest"])
        return not carries or carries[max(carries)]=={hash_of(proposal)}
    except (Denied,KeyError,TypeError,ValueError,IndexError):
        return False


if __name__ == "__main__":
    folder = Path(sys.argv[1])
    records = json.loads((folder/"proofs.json").read_bytes())
    pins = json.loads((folder/"pins.json").read_bytes())
    expected = json.loads(Path(__file__).with_name("resurrection_expected.json").read_bytes())
    require(set(records)==set(pins)==set(expected["proofs"]), "proof coverage")
    for name,r in records.items():
        require(hash_of(r["config"])==pins[name]["genesis"],"genesis")
        require(disclose(r["config"],r["chains"],pins[name]["floor"],r["request"])==expected["proofs"][name], name)
    require(json.loads((folder/"matrix.json").read_bytes())==expected["matrix"], "live matrix")
    changes = json.loads((folder/"changes.json").read_bytes())
    require(set(changes)==set(expected["changes"]), "view proof coverage")
    config_pins = json.loads((folder/"change-pins.json").read_bytes())
    for name,row in changes.items():
        require(config_pins[name]==hash_of(row["config"]), "view genesis")
        require(review_change(**row)==expected["changes"][name],name)
    print(f"PASS {len(records)} public decisions, {len(changes)} view changes and frozen matrix")

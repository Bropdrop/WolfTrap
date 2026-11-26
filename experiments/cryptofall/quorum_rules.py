"""Public deterministic execution rules for a fixed disposable QUORUM instance."""
import json

from counter import Checkpoint, increment_id
from severance import verify
from verifier import current_key, unhex, digest, evaluate, require, slots, wire

DOMAIN = "WT-CRYPTO-007/"
MEMBERS = ("A", "B", "C", "D")


def hash_of(obj):
    return digest(wire(obj))


def keys_distinct(config, policy, gate):
    unhex(gate, 1952)
    keys = list(config["replicas"].values()) + [config["permit"], gate]
    keys += [key["public"] for key in config["roots"].values()]
    keys += [key["public"] for key in slots(policy).values()]
    require(len(keys) == len(set(keys)), "shared-identity")


def initial(config):
    require(set(config["replicas"]) == set(MEMBERS), "membership")
    keys_distinct(config, config["policy"], config["gate"])
    return {"head": hash_of(config), "height": 0, "policy": config["policy"],
            "gate": config["gate"], "generation": 0, "value": 0, "requests": {}, "permits": {}}


def binding(cmd):
    request = increment_id(wire(cmd["operation"]), "specimen")
    return {"request_id": request, "operation": hash_of(cmd["operation"]),
            "evidence": hash_of(cmd["claim"]), "permit": cmd["permit"]["body"]["id"]}


def advance(config, previous, block, now):
    """One state transition. All output fields signed by the votes are re-derived."""
    require(set(block) == {"parent", "height", "command", "receipt"}
            and block["parent"] == previous["head"]
            and type(block["height"]) is int and block["height"] == previous["height"] + 1, "ancestry")
    state = json.loads(wire(previous))
    command = block["command"]
    policy = state["policy"]
    if command["kind"] == "policy":
        roots = config["roots"]
        cp = Checkpoint(wire(config["policy"]), hash_of(config["policy"]), roots["recovery-test"],
                        roots["policy-witness-test"], "specimen", lambda: now)
        cp.policy = wire(policy)
        cp.transition(wire(command["doc"]))
        state["policy"] = json.loads(cp.policy)
        keys_distinct(config, state["policy"], state["gate"])
        receipt = {"policy": hash_of(state["policy"])}
    elif command["kind"] == "replace":
        new = command["new"]
        require(new != state["gate"], "same gate")
        keys_distinct(config, policy, new)
        auth = {"ledger": hash_of(config), "parent": previous["head"],
                "generation": state["generation"] + 1, "new": new}
        for role in ("recovery-test", "policy-witness-test"):
            current_key(policy, config["roots"][role])
            require(verify(config["roots"][role]["public"], DOMAIN + "replace/" + role,
                           command["approval"][role]) == auth, "replacement-authority")
        state.update(gate=new, generation=auth["generation"])
        receipt = auth
    else:
        kind = command["kind"]
        require(kind in ("effect", "fence"), "command")
        bound = binding(command)
        permit = verify(config["permit"], DOMAIN + "permit", command["permit"])
        require(permit == {"id": bound["permit"], "operation": bound["operation"],
                           "claim": bound["evidence"], "policy": command["claim"]["claim"]["policy"],
                           "ledger": hash_of(config)} and isinstance(permit["id"], str)
                and bool(permit["id"]), "permit-binding")
        request = bound["request_id"]
        require(request not in state["requests"] and bound["permit"] not in state["permits"], "spent")
        if kind == "effect":
            stamp = {"ledger": hash_of(config), "parent": previous["head"],
                     "generation": state["generation"], "binding": bound}
            require(verify(state["gate"], DOMAIN + "execute", command["gate"]) == stamp, "gate-generation")
            evaluate(wire(command["claim"]), wire(command["operation"]), policy, now, expected_request_id=request)
            state["value"] += 1
            outcome = "COMMITTED"
        else:
            auth = {"ledger": hash_of(config), "parent": previous["head"], "binding": bound}
            for role in ("recovery-test", "policy-witness-test"):
                current_key(policy, config["roots"][role])
                require(verify(config["roots"][role]["public"], DOMAIN + "fence/" + role,
                               command["approval"][role]) == auth, "fence-authority")
            outcome = "NOT_COMMITTED"
        receipt = {"binding": bound, "value": state["value"], "outcome": outcome}
        state["requests"][request] = receipt
        state["permits"][bound["permit"]] = request
    require(wire(block["receipt"]) == wire(receipt), "receipt-binding")
    state.update(height=block["height"], head=hash_of(block))
    return state


def certified(config, previous, qc):
    block = qc["block"]
    voters = qc["votes"]
    require(3 <= len(voters) <= 4 and set(voters) <= set(MEMBERS), "threshold")
    state = None
    for member, cert in voters.items():
        vote = verify(config["replicas"][member], DOMAIN + "vote/" + member, cert)
        require(vote == {"ledger": hash_of(config), "block": hash_of(block), "time": vote["time"]}
                and type(vote["time"]) is int, "vote-binding")
        state = advance(config, previous, block, vote["time"])
    return state

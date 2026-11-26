"""Offline proof checker. No replica, gate, fixture, SQL or network dependencies."""
import json
import sys
from pathlib import Path

from counter import Checkpoint
from quorum_rules import DOMAIN, MEMBERS, binding, hash_of, initial, keys_distinct
from severance import verify
from verifier import Denied, current_key, evaluate, require, wire


def interpret(config, prior, block, timestamp):
    """Independent receipt and spend reconstruction using predecessor crypto checks."""
    require(set(block) == {"parent","height","command","receipt"} and block["parent"] == prior["head"]
            and type(block["height"]) is int and block["height"] == prior["height"] + 1, "disconnected")
    result = json.loads(wire(prior))
    policy, roots = prior["policy"], config["roots"]
    cmd, kind = block["command"], block["command"]["kind"]
    scope = {"parent":prior["head"], "ledger":hash_of(config)}
    if kind == "policy":
        checker = Checkpoint(wire(config["policy"]), hash_of(config["policy"]),
                             roots["recovery-test"], roots["policy-witness-test"], "specimen", lambda:timestamp)
        checker.policy = wire(policy)
        checker.transition(wire(cmd["doc"]))
        result["policy"] = json.loads(checker.policy)
        receipt = {"policy":hash_of(result["policy"])}
    elif kind == "replace":
        require(cmd["new"] != prior["gate"], "same executor")
        result.update(gate=cmd["new"], generation=prior["generation"]+1)
        receipt = dict(scope, generation=result["generation"], new=cmd["new"])
    else:
        require(kind in ("effect","fence"), "unknown effect")
        bound = binding(cmd)
        permit = verify(config["permit"], DOMAIN+"permit", cmd["permit"])
        expected = {"ledger":scope["ledger"], "id":bound["permit"], "operation":bound["operation"],
                    "claim":bound["evidence"], "policy":cmd["claim"]["claim"]["policy"]}
        require(permit == expected and type(permit["id"]) is str and permit["id"], "invalid permit")
        rid = bound["request_id"]
        require(rid not in prior["requests"] and permit["id"] not in prior["permits"], "duplicate")
        if kind == "effect":
            attested = verify(prior["gate"], DOMAIN+"execute", cmd["gate"])
            require(attested == dict(scope, generation=prior["generation"], binding=bound), "executor")
            evaluate(wire(cmd["claim"]), wire(cmd["operation"]), policy, timestamp, expected_request_id=rid)
            result["value"] += 1
        receipt = {"binding":bound, "value":result["value"],
                   "outcome":"COMMITTED" if kind=="effect" else "NOT_COMMITTED"}
        result["permits"][permit["id"]] = rid
        result["requests"][rid] = receipt
    if kind in ("replace","fence"):
        approved = receipt if kind == "replace" else dict(scope, binding=bound)
        for role in ("recovery-test","policy-witness-test"):
            key = current_key(policy, roots[role])
            require(verify(key["public"], DOMAIN+kind+"/"+role, cmd["approval"][role]) == approved, "authority")
    keys_distinct(config, result["policy"], result["gate"])
    require(wire(receipt) == wire(block["receipt"]), "wrong receipt")
    result.update(head=hash_of(block), height=block["height"])
    return result


def replay(config, history):
    state = initial(config)
    heads = [state["head"]]
    for qc in history:
        block = qc["block"]
        voters = qc["votes"]
        require(set(voters) <= set(MEMBERS) and len(voters) >= 3, "insufficient distinct voters")
        for member, envelope in voters.items():
            statement = verify(config["replicas"][member], DOMAIN + "vote/" + member, envelope)
            require(statement["ledger"] == heads[0] and statement["block"] == hash_of(block)
                    and type(statement["time"]) is int, "foreign statement")
            successor = interpret(config, state, block, statement["time"])
        state = successor
        heads.append(state["head"])
    return state, heads


def recover(config, histories, floor, exact):
    """Invalid proof or contradictory certified history freezes this review."""
    try:
        valid = [replay(config, history) for history in histories]
        require(valid, "no proofs")
        state, heads = max(valid, key=lambda pair: len(pair[1]))
        height, retained = floor
        require(type(height) is int and 0 <= height < len(heads) and heads[height] == retained, "floor")
        for _, other in valid:
            require(heads[:len(other)] == other, "conflicting certified histories")
        bound = binding(exact)
        receipt = state["requests"].get(bound["request_id"])
        require(receipt and receipt["binding"] == bound, "no exact receipt")
        # Also authenticate the presented permit, even if its ID and payload were copied.
        permit = verify(config["permit"], DOMAIN + "permit", exact["permit"])
        require(permit["ledger"] == heads[0] and permit["claim"] == bound["evidence"]
                and permit["operation"] == bound["operation"]
                and permit["policy"] == exact["claim"]["claim"]["policy"], "permit disclosure")
        return receipt["outcome"]
    except (Denied, ValueError, KeyError, TypeError, IndexError):
        return "UNRESOLVED"


def audit(directory):
    records = json.loads((directory / "proofs.json").read_text())
    pins = json.loads((directory / "retained.json").read_text())
    expected = json.loads(Path(__file__).with_name("quorum_expected.json").read_text())
    matrix = json.loads((directory / "matrix.json").read_text())
    require(len(matrix) == len(expected["matrix"]) and {r["case"]:r["observed"] for r in matrix} == expected["matrix"],
            "matrix observations")
    require(set(pins) == set(expected["proofs"]), "retained case set")
    names = set()
    for record in records:
        name = record["case"]
        require(name not in names, "duplicate review")
        names.add(name)
        config = record["config"]
        pin = pins[name]
        require(hash_of(config) == pin["genesis"], "substituted genesis")
        result = recover(config, record["histories"], pin["floor"], record["exact"])
        require(result == record["expected"] == expected["proofs"][name], name)
    require(names == set(expected["proofs"]), "missing proofs")
    print(f"PASS {len(names)} recorded public proof decisions")


if __name__ == "__main__":
    audit(Path(sys.argv[1]))

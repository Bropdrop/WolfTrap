"""Research runner. Synthetic sources and fixed SQL fixtures only."""
import concurrent.futures
from contextlib import closing
import json
import hashlib
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from threading import Barrier

import fixtures
import host
import oracle
from recovery import reconcile

HERE = Path(__file__).resolve().parent


def invoke(path, proposal, tokens, keys):
    try:
        return host.submit(path, proposal, tokens, keys)
    except host.Hold:
        return "HOLD"
    except host.Denied as exc:
        return "DENY/" + str(exc)


def update(path, sql):
    with closing(sqlite3.connect(path)) as db, db:
        db.execute(sql)


def killed_child(path, point):
    binding = fixtures.BASE.copy()
    with closing(sqlite3.connect(path)) as db:
        if point == "before-commit":
            db.create_function("fixture_interrupt", 0, lambda: os._exit(74))
            db.execute("CREATE TEMP TRIGGER dying AFTER INSERT ON effects "
                       "BEGIN SELECT fixture_interrupt(); END")
        host.dispatch(db, binding, {r: fixtures.issue(r, binding) for r in fixtures.ROLES}, fixtures.roots())
        os._exit(75)


def exercise(case, path):
    action = case["input"]
    binding = {**fixtures.BASE, **action.get("approved", {})}
    proposal = {**binding, **action.get("propose", {})}
    fixtures.provision(path, binding)
    before = oracle.observe(path)
    keys = fixtures.roots()
    tokens = {r: fixtures.issue(r, binding) for r in fixtures.ROLES}
    for role, params in action.get("issuance", {}).items():
        tokens[role] = fixtures.issue(role, binding, **params)
    if "missing" in action:
        del tokens[action["missing"]]
    if action.get("shared-custody"):
        keys["policy"] = keys["owner"]
        tokens["policy"] = fixtures.issue("policy", binding, signer="owner")
    if action.get("replace-token"):
        tokens["owner"] = tokens["policy"]
    changes = {"revoked": "UPDATE policy SET credential_active=0",
               "withdrawn": "UPDATE policy SET grant_active=0",
               "fenced": "UPDATE policy SET generation=2",
               "expired": "UPDATE policy SET tick=20",
               "policy-change": "UPDATE policy SET policy_version='fixture-policy-v2'",
               "lost-policy": "DELETE FROM policy",
               "fact": "INSERT INTO facts VALUES ('fixture-observation-42')"}
    if change := action.get("checkpoint"):
        update(path, changes[change])
    memory = None
    if "source" in action:
        memory = fixtures.recall(path.with_suffix(".memory"), action["source"], action["content"],
                                 binding, lose_source=action.get("drop-source", False))
        if action.get("claim-as-grant"):
            tokens["owner"] = memory.text
    dispatch = lambda: invoke(path, proposal, tokens, keys)
    mode = action.get("mode", "dispatch")
    if mode == "restart-expired-owner":
        update(path, "UPDATE policy SET tick=13")
    elif mode == "old-client":
        update(path, "UPDATE policy SET generation=2")
    witness_at_dispatch = oracle.observe(path)
    state = witness_at_dispatch["policy"]
    identity = host.assess_identity(tokens.get("issuer"), keys, state["tick"], proposal,
                                    state["generation"], state["credential"]).status if state else None
    if mode in {"restart-expired-owner", "old-client"}:
        # Start a fresh interpreter with only the previously prepared fictional request.
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()), "resume", str(path)],
                               input=json.dumps([proposal, tokens]), text=True, capture_output=True,
                               timeout=20, check=True)
        responses = [child.stdout.strip()]
    elif mode == "duplicate":
        responses = [dispatch(), dispatch()]
    elif mode == "concurrent":
        barrier = Barrier(2)
        def concurrent_dispatch():
            barrier.wait(timeout=10)
            return dispatch()
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(concurrent_dispatch) for _ in range(2)]
            responses = sorted(f.result() for f in futures)
    elif mode in {"before-commit", "after-commit"}:
        child = subprocess.run([sys.executable, str(Path(__file__).resolve()), "child",
                                str(path), mode], check=False, timeout=20)
        responses = [f"EXIT/{child.returncode}"]
        # Query independent durable state before deciding on recovery.
        observed = reconcile(path, proposal)
        if observed == "RECOVERED":
            responses.extend(["RECOVERED", dispatch()])  # Deliberately inject a duplicate.
        elif observed == "OBSERVED_EMPTY":
            responses.extend([observed, dispatch()])
        else:
            responses.append("HOLD")
    elif mode == "fake-ack":
        responses = ["ACK", "RECOVERED" if reconcile(path, proposal) == "RECOVERED" else "HOLD"]
    elif mode == "unqueryable":
        responses = ["TIMEOUT", reconcile(path.with_suffix(".missing"), proposal)]
    elif mode == "conflicting-receipt":
        responses = [dispatch(), reconcile(path, {**proposal, "destination": "purse-c"})]
    else:
        responses = [dispatch()]
    after = oracle.observe(path)
    witness_checks = oracle.witnesses(tokens, proposal, state)
    result = oracle.verdict(case["expected"], before, after, responses)
    if after["effects"] and not all(w["current_and_bound"] for w in witness_checks.values()):
        result = "CONTROL_GAP"
    if "identity" in case["expected"] and identity != case["expected"]["identity"]:
        result = "CONTROL_GAP"
    if memory:
        expected_source = None if action.get("drop-source") else action["source"]
        expected_digest = hashlib.sha256(action["content"].encode()).hexdigest() if expected_source else None
        if (memory.source != expected_source or memory.source_sha256 != expected_digest or
                memory.trust != "UNTRUSTED_DATA" or memory.provenance != case["expected"]["provenance"] or
                memory.origin_task == memory.retrieval_task or memory.origin_session == memory.retrieval_session or
                memory.stages != ("SOURCE", "INGESTION", "MEMORY", "RETRIEVAL", "DECISION", "PROPOSED EFFECT")):
            result = "CONTROL_GAP"
    return dict(id=case["id"], expected=case["expected"], proposed=proposal, before=before,
                at_dispatch=witness_at_dispatch, after=after, responses=responses,
                identity=identity, witnesses=witness_checks, memory=vars(memory) if memory else None, oracle=result)


def run(ids=None):
    cases = json.loads((HERE / "cases.json").read_text())
    selected = [c for c in cases if ids is None or c["id"] in ids]
    if not selected or (ids is not None and len(selected) != len(ids)):
        raise ValueError("invalid case selection")
    with tempfile.TemporaryDirectory() as tmp:
        return [exercise(case, Path(tmp) / f"case-{i}.sqlite") for i, case in enumerate(selected)]


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "child" and sys.argv[3] in {"before-commit", "after-commit"}:
        killed_child(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "resume":
        proposal, tokens = json.loads(sys.stdin.read(32768))
        print(invoke(Path(sys.argv[2]), proposal, tokens, fixtures.roots()))
    elif len(sys.argv) == 1:
        results = run()
        print(json.dumps(results, sort_keys=True, indent=2))
        sys.exit(any(r["oracle"] != "MATCH" for r in results))
    else:
        sys.exit(2)

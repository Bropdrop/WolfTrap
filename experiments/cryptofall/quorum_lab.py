"""Local process and network qualification. Keys and SQL volumes are disposable."""
import json
import os
import secrets
import shutil
import signal
import socketserver
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey as Key
from challenge import Fixture, ED, PQ
from quorum_node import initialize
from quorum_review import recover, replay
from quorum_rules import DOMAIN, MEMBERS, binding, hash_of, initial
from severance import rpc, sign
from verifier import Denied, wire

HERE = Path(__file__).resolve().parent


class Drop(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.shutdown(2)


class Lab:
    def __init__(self, root, stack):
        self.root = root
        self.stack = stack
        self.f = Fixture(root)
        self.f.now = int(time.time())
        self.seeds = {m: secrets.token_bytes(32) for m in MEMBERS}
        self.keys = {m: Key.from_seed_bytes(seed) for m, seed in self.seeds.items()}
        self.issuer = Key.generate()
        self.executor = Key.generate()
        self.config = {"gate": self.executor.public_key().public_bytes_raw().hex(), "policy": self.f.genesis, "roots": self.f.anchor.roots,
                       "permit": self.issuer.public_key().public_bytes_raw().hex(),
                       "replicas": {m: k.public_key().public_bytes_raw().hex() for m,k in self.keys.items()}}
        self.history = []
        self.initial = initial(self.config)
        self.floor = [0, hash_of(self.config)]
        self.peers = {role: {} for role in ("gate1", "gate2")}
        self.children = {}
        self.links = {}
        for m in MEMBERS:
            path = root / m
            path.mkdir(mode=0o700)
            self.links[m] = {r: secrets.token_hex(32) for r in self.peers}
            (path / "identity").write_bytes(wire({"seed": self.seeds[m].hex(), "links": self.links[m],
                                                  "member": m, "public": self.config}))
            initialize(path, self.config)
            shutil.copyfile(path / "store", path / "genesis-backup")
            self.start(m)
        drop = stack.enter_context(socketserver.ThreadingTCPServer(("127.0.0.1", 0), Drop))
        threading.Thread(target=drop.serve_forever, daemon=True).start()
        stack.callback(drop.shutdown)
        self.cut = drop.server_address[1]

    def start(self, m, crash_at=None):
        args = [sys.executable, str(HERE / "quorum_node.py"), str(self.root / m)]
        if crash_at:
            args = [sys.executable, str(HERE / "quorum_crash_probe.py"), crash_at, str(self.root / m)]
        child = subprocess.Popen(args,
                                 stdout=subprocess.PIPE, text=True)
        self.children[m] = child
        self.stack.callback(self.stop, child)
        port = int(child.stdout.readline())
        for role in self.peers:
            self.peers[role][m] = {"port": port, "key": self.links[m][role]}

    @staticmethod
    def stop(child):
        if child.poll() is None:
            child.kill()
            child.wait()
        child.stdout.close()

    def restart(self, member, restore=False):
        self.stop(self.children[member])
        if restore:
            path = self.root / member
            shutil.copyfile(path / "genesis-backup", path / "store")
        self.start(member)

    def effect(self, n, lifetime=20):
        f = self.f
        f.now = int(time.time())
        raw = f.operation(f"{n:032x}")
        claim = f.claim(operation=raw, expires=f.now + lifetime)
        permit = sign(self.issuer, DOMAIN + "permit", {"id": f"permit-{n}", "operation": hash_of(json.loads(raw)),
                      "claim": hash_of(claim), "policy": claim["claim"]["policy"], "ledger": hash_of(self.config)})
        return {"kind": "effect", "operation": json.loads(raw), "claim": claim, "permit": permit}

    def block(self, cmd, history=None):
        state, _ = replay(self.config, self.history if history is None else history)
        kind = cmd["kind"]
        if kind == "effect" and "gate" not in cmd:
            stamp = {"ledger": hash_of(self.config), "parent": state["head"],
                     "generation": state["generation"], "binding": binding(cmd)}
            cmd = dict(cmd, gate=sign(self.executor, DOMAIN + "execute", stamp))
        if kind == "replace":
            receipt = cmd["approval"]["recovery-test"]["body"]
        elif kind == "policy":
            receipt = {"policy": hash_of(cmd["doc"]["transition"]["next"])}
        else:
            receipt = {"outcome": "COMMITTED" if kind == "effect" else "NOT_COMMITTED",
                       "binding": binding(cmd), "value": state["value"] + int(kind == "effect")}
        return {"command": cmd, "parent": state["head"], "height": state["height"] + 1, "receipt": receipt}

    def call(self, member, op, obj):
        return rpc({"peers": self.peers["gate1"]}, member, "gate1", op, obj)

    def gate(self, block, allowed="ABCD", role="gate1", history=None, exact=None):
        peers = {m: dict(p, port=p["port"] if m in allowed else self.cut) for m,p in self.peers[role].items()}
        job = {"config": self.config, "block": block, "peers": peers, "role": role,
               "history": self.history if history is None else history, "floor": self.floor}
        if exact is not None:
            job.pop("block")
            job["exact"] = exact
        child = subprocess.run([sys.executable, str(HERE / "quorum_gate.py")], input=wire(job),
                               stdout=subprocess.PIPE, check=True)
        return json.loads(child.stdout)

    def forged(self, block, members):
        statement = {"ledger": hash_of(self.config), "block": hash_of(block), "time": int(time.time())}
        return {"block": block, "votes": {m: sign(self.keys[m], DOMAIN + "vote/" + m, statement) for m in members}}


def run(out):
    rows, proofs, pins = [], [], {}

    def check(name, actual, expected):
        if actual != expected:
            raise AssertionError((name, actual, expected))
        rows.append({"case": name, "observed": actual, "expected": expected})

    def review(name, histories, exact, expected, floor=None):
        retained = floor or lab.floor
        check(name, recover(lab.config, histories, retained, exact), expected)
        proofs.append({"case": name, "config": lab.config, "histories": histories, "exact": exact, "expected": expected})
        pins[name] = {"genesis": hash_of(lab.config), "floor": retained}

    def cluster(stack):
        path = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        return Lab(path, stack)

    with ExitStack() as stack:
        lab = cluster(stack)
        cmd = lab.effect(1)
        block = lab.block(cmd)
        half = lab.gate(block, "AB")
        check("two reachable voters", len(half["qc"]["votes"]), 2)
        review("unsafe threshold", [[half["qc"]]], cmd, "UNRESOLVED")
        review("copied ordinary block", [[{"block": block, "votes": {}}]], cmd, "UNRESOLVED")
        alt = lab.block(lab.effect(2))
        lab.restart("A")
        try:
            lab.call("A", "vote", alt)
        except Denied as exc:
            check("vote lock survived process death", str(exc), "locked")
        else:
            raise AssertionError("lost lock")
        equiv = lab.forged(alt, "A")
        equiv["votes"]["D"] = lab.call("D", "vote", alt)
        review("compromised A double voted with isolated D", [[equiv]], alt["command"], "UNRESOLVED")
        # The third durable vote exists, but its recipient dies before QC assembly or install.
        # A relay dies with the last vote in memory before publishing any QC.
        script = ("import json,os,signal,sys; from severance import rpc; "
                  "rpc(*json.load(sys.stdin)); os.kill(os.getpid(),signal.SIGKILL)")
        crashed = subprocess.run([sys.executable, "-c", script], cwd=HERE,
            input=wire([{"peers":lab.peers["gate1"]}, "C", "gate1", "vote", block]))
        check("relay killed after durable third vote", crashed.returncode, -signal.SIGKILL)
        check("no finalized log after third vote", lab.call("C", "history", None), [])
        with ThreadPoolExecutor(2) as pool:
            observed = list(pool.map(lambda role: lab.gate(None, "ABC", role, exact=cmd),
                                     ("gate1","gate2")))
        check("two new relays recover using client bytes alone", [r["outcome"] for r in observed], ["COMMITTED"]*2)
        for response in observed:
            assert response["receipt"] == block["receipt"]
        review("signed receipt disclosed from surviving locks", [r["proof"] for r in observed],cmd,"COMMITTED")
        check("read-only recovery left installed logs empty", lab.call("B","history",None), [])
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda role: lab.gate(block, "ABC", role), ("gate1", "gate2")))
        check("two replacement gates recover lost certificate", [r["outcome"] for r in results], ["COMMITTED"] * 2)
        hist = [results[0]["qc"]]
        review("three signatures after lost reply", [hist], cmd, "COMMITTED")
        review("stale replica D", [lab.call("D", "history", None)], cmd, "UNRESOLVED")
        lab.call("D", "install", hist[0])
        review("D verified and installed majority branch", [lab.call("D", "history", None)], cmd, "COMMITTED")
        other = dict(cmd, claim=lab.f.claim(operation=wire(cmd["operation"]), expires=lab.f.now + 19))
        review("substituted disclosure evidence", [hist], other, "UNRESOLVED")
        lab.history = hist
        check("delayed duplicate at next height", lab.gate(lab.block(cmd))["outcome"], "UNRESOLVED")
        check("one logical increment at all replicas",
              [replay(lab.config, lab.call(m, "history", None))[0]["value"] for m in MEMBERS], [1]*4)
        # Multi-identity restore exceeds the fault budget. Retain the original certificate separately.
        floor_file = lab.root / "reviewer-floor.json"
        floor_file.write_bytes(wire([1, hash_of(block)]))
        for m in "ABC":
            lab.restart(m, restore=True)
        lab.history = []
        fork = [lab.gate(alt, "ABC")["qc"]]
        review("conflicting commitments", [hist, fork], cmd, "UNRESOLVED")
        review("rollback against retained floor", [fork], alt["command"], "UNRESOLVED", json.loads(floor_file.read_bytes()))
        # Untrusted quorum signs a block with an invalid hybrid endorsement but a real permit.
        bad = lab.effect(3)
        bad["claim"]["signatures"] = bad["claim"]["signatures"][2:]
        payload = dict(bad["permit"]["body"], claim=hash_of(bad["claim"]))
        bad["permit"] = sign(lab.issuer, DOMAIN + "permit", payload)
        false = lab.forged(lab.block(bad), "ABC")
        review("authority substitution", [[false]], bad, "UNRESOLVED")

    with ExitStack() as stack:
        lab = cluster(stack)
        cmd = lab.effect(4)
        old = lab.block(cmd)
        lab.call("A", "vote", old)
        f = lab.f
        rev = f.transition("emergency-quarantine", mode="quarantine", revoked_algorithms=[ED])
        revblock = lab.block({"kind": "policy", "doc": rev})
        result = lab.gate(revblock, "BCD")
        check("revocation wins against outstanding vote", result["outcome"], "POLICY")
        lab.history.append(result["qc"])
        lab.call("A", "install", result["qc"])
        check("delayed pre-revocation proposal lacks quorum", lab.gate(old, history=[])["outcome"], "UNRESOLVED")
        check("old algorithm rejected at new parent", lab.gate(lab.block(cmd))["outcome"], "UNRESOLVED")
        review("revocation alone leaves effect unresolved", [lab.history[:]], cmd, "UNRESOLVED")
        auth = {"ledger":hash_of(lab.config), "parent":hash_of(revblock), "binding":binding(cmd)}
        approvals = {r: sign(f.private[r,PQ], DOMAIN + "fence/" + r, auth) for r in f.anchor.roots}
        fence = lab.block(dict(cmd, kind="fence", approval=approvals))
        competing = lab.gate(fence)
        check("ordered dual-authority cancellation", competing["outcome"], "NOT_COMMITTED")
        lab.history.append(competing["qc"])
        review("proved non-commitment", [lab.history[:]], cmd, "NOT_COMMITTED")
        f.anchor.policy = wire(rev["transition"]["next"])
        restore = f.transition("recover", mode="active", profile="pq-only", keys=f.effect_keys("pq-only"))
        rb = lab.block({"kind":"policy", "doc":restore})
        check_result = lab.gate(rb)
        check("independently authorized PQ-only recovery", check_result["outcome"], "POLICY")
        lab.history.append(check_result["qc"])
        f.anchor.policy = wire(restore["transition"]["next"])
        fresh = lab.effect(5)
        fb = lab.block(fresh)
        res = lab.gate(fb)
        check("fresh PQ-only effect", res["outcome"], "COMMITTED")
        review("historical fence and PQ recovery chain", [lab.history + [res["qc"]]], fresh, "COMMITTED")

    with ExitStack() as stack:
        lab = cluster(stack)
        first, second = lab.block(lab.effect(6)), lab.block(lab.effect(7))
        with ThreadPoolExecutor(2) as pool:
            a = pool.submit(lab.gate, first, "AB", "gate1")
            b = pool.submit(lab.gate, second, "CD", "gate2")
            check("two competing recovery proposals under partition", [a.result()["outcome"], b.result()["outcome"]],
                  ["UNRESOLVED"]*2)
        check("split locks remain blocked after healing", [lab.gate(x)["outcome"] for x in (first, second)],
              ["UNRESOLVED"]*2)

    with ExitStack() as stack:
        lab = cluster(stack)
        old_effect = lab.block(lab.effect(8))
        def replacement(key):
            new = key.public_key().public_bytes_raw().hex()
            auth = {"ledger":hash_of(lab.config), "parent":lab.floor[1], "generation":1, "new":new}
            approval = {r:sign(lab.f.private[r,PQ], DOMAIN + "replace/" + r, auth) for r in lab.f.anchor.roots}
            return lab.block({"kind":"replace","new":new,"approval":approval})
        winner = Key.generate()
        first = replacement(winner)
        second = replacement(Key.generate())
        with ThreadPoolExecutor(2) as pool:
            won = pool.submit(lab.gate, first, "ABC", "gate1")
            lost = pool.submit(lab.gate, second, "D", "gate2")
            a,b = won.result(),lost.result()
        check("competing dual-approved execution identities", [a["outcome"], b["outcome"]], ["REPLACE","UNRESOLVED"])
        lab.history.append(a["qc"])
        lab.call("D","install",a["qc"])
        stale = lab.block(old_effect["command"])
        check("replaced executor packet rejected", lab.gate(stale)["outcome"], "UNRESOLVED")
        wrong = lab.block(lab.effect(9))
        check("old key cannot sign for new generation", lab.gate(wrong)["outcome"], "UNRESOLVED")
        lab.executor = winner
        new_cmd = lab.effect(10)
        good = lab.gate(lab.block(new_cmd))
        review("winner alone admits fresh increment", [lab.history+[good["qc"]]], new_cmd, "COMMITTED")
        # Commit wins before a competing revocation. Historical exact recovery remains possible.
        lab.history.append(good["qc"])
        rev = lab.f.transition("emergency-quarantine", mode="quarantine", revoked_algorithms=[ED])
        later = lab.gate(lab.block({"kind":"policy","doc":rev}))
        lab.history.append(later["qc"])
        review("historical decision survives later revocation", [lab.history], new_cmd, "COMMITTED")

    with ExitStack() as stack:
        lab = cluster(stack)
        too_long = lab.effect(11, 31)
        check("31-second hybrid claim denied by all four", len(lab.gate(lab.block(too_long))["qc"]["votes"]), 0)
        short = lab.effect(12, 3)
        block = lab.block(short)
        t1 = lab.call("A","vote",block)
        t2 = lab.call("B","vote",block)
        time.sleep(max(0, short["claim"]["claim"]["expires"] - time.time()) + 0.05)
        partial = lab.gate(block)
        check("no fresh third vote after expiry", sorted(partial["qc"]["votes"]), ["A","B"])
        counterfeit = {"block":block, "votes":{"A":t1,"B":t2,"C":t1}}
        review("one identity repeated under another label", [[counterfeit]], short, "UNRESOLVED")
        valid = lab.effect(13)
        vb = lab.block(valid)
        for m in "CD":
            lab.call(m,"vote",vb)
        check("all four locks occupied by two exact proposals", lab.gate(vb)["outcome"], "UNRESOLVED")

    with ExitStack() as stack:
        lab = cluster(stack)
        valid = lab.effect(14, 3)
        vb = lab.block(valid)
        for m in "ABC":
            lab.call(m,"vote",vb)
        time.sleep(max(0, valid["claim"]["claim"]["expires"] - time.time()) + 0.05)
        late = lab.gate(vb)
        check("expired claim recovers only already-durable votes", sorted(late["qc"]["votes"]), ["A","B","C"])
        review("expired exact request has historical proof", [[late["qc"]]], valid, "COMMITTED")
        imported = json.loads(wire(late["qc"]))
        imported["block"]["receipt"]["value"] = 9
        review("changed receipt breaks commitment proof", [[imported]], valid, "UNRESOLVED")

    with ExitStack() as stack:
        lab = cluster(stack)
        exact = lab.effect(15)
        block = lab.block(exact)
        qc = {"block":block, "votes":{m:lab.call(m,"vote",block) for m in "ABC"}}
        for member,point in (("D","between writes"),("C","after commit")):
            lab.stop(lab.children[member])
            lab.start(member,point)
            try:
                lab.call(member,"install",qc)
            except ConnectionError:
                pass
            else:
                raise AssertionError("expected lost installation response")
            check("replica killed "+point,lab.children[member].wait(timeout=5),-signal.SIGKILL)
            with sqlite3.connect(lab.root / member / "store") as observer:
                state = json.loads(observer.execute("SELECT data FROM current").fetchone()[0])
                history = [json.loads(r[0]) for r in observer.execute("SELECT qc FROM history ORDER BY height")]
            expected_count = int(point == "after commit")
            check("atomic SQL rows "+point,
                  [state["value"],len(state["requests"]),len(state["permits"]),len(history)], [expected_count]*4)
            assert state == replay(lab.config,history)[0]
            lab.start(member)
            lab.call(member,"install",qc)
            review("reinstalled replica "+member+" exact recovery",[lab.call(member,"history",None)],exact,"COMMITTED")

    out.mkdir(parents=True, exist_ok=True)
    for name, data in (("matrix",rows), ("proofs",proofs), ("retained",pins)):
        (out / (name + ".json")).write_bytes(wire(data) + b"\n")
    print(f"PASS {len(rows)} observations")


if __name__ == "__main__":
    os.umask(0o077)
    run(Path(sys.argv[1]))

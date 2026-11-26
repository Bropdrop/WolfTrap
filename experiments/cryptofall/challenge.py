"""Black-box outcomes and independent signing inputs for the disposable lab."""

import hashlib
import json
import multiprocessing
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from functools import partial
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from threading import Event
from unittest.mock import patch

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import counter
import verifier

REALM = "wolftrap:cryptofall:disposable:v2"
OWNER = "owner-test"
WITNESS = "effect-witness-test"
RECOVERY = "recovery-test"
POLICY_WITNESS = "policy-witness-test"
ED, PQ = "ed25519-v1", "ml-dsa-65-v1"
ALGORITHMS = {"hybrid": (ED, PQ), "pq-only": (PQ,)}


def encode(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class CrashCheckpoint(counter.Checkpoint):
    """Keep the sequence in parent-owned shared memory across the writer's death."""

    def __init__(self, *args):
        self.shared_sequence = multiprocessing.get_context("fork").Value("q", 0)
        super().__init__(*args)

    @property
    def sequence(self):
        return self.shared_sequence.value

    @sequence.setter
    def sequence(self, value):
        self.shared_sequence.value = value


class Fixture:
    def __init__(self, path, checkpoint_type=counter.Checkpoint):
        self.path = Path(path)
        self.now = 100
        self.committed_requests = []
        self.private = {}
        self.public = {}
        for label in (OWNER, WITNESS, "replacement", RECOVERY, POLICY_WITNESS, "wrong"):
            kinds = (ED, PQ) if label in (OWNER, WITNESS, "replacement") else (PQ,)
            self.public[label] = {}
            for algorithm in kinds:
                key_type = ed25519.Ed25519PrivateKey if algorithm == ED else mldsa.MLDSA65PrivateKey
                private = key_type.generate()
                self.private[label, algorithm] = private
                self.public[label][algorithm] = private.public_key().public_bytes_raw().hex()
        self.genesis = {"v": 2, "realm": REALM, "mode": "active", "profile": "hybrid",
                        "epoch": 0, "predecessor": "0" * 64, "keys": self.effect_keys(),
                        "revoked_keys": [], "revoked_algorithms": []}
        genesis = encode(self.genesis)
        self.anchor = checkpoint_type(genesis, sha(genesis), self.key(RECOVERY, PQ),
                                      self.key(POLICY_WITNESS, PQ), "specimen", lambda: self.now)
        self.counter = counter.Counter(self.path / "counter.db", self.anchor)
        self.counter.initialize()
        self.nonce = "23" * 16
        self.request = self.operation(self.nonce)
        self.anchor.set_disposable_permit(self.request, enabled=True)

    @staticmethod
    def operation(request_id, instance="specimen"):
        return encode({"action": "increment", "instance": instance, "request_id": request_id})

    def key(self, label, algorithm):
        return {"public": self.public[label][algorithm], "algorithm": algorithm}

    def fingerprint(self, label, algorithm):
        return sha(encode(self.key(label, algorithm)))

    def effect_keys(self, profile="hybrid", owner=OWNER):
        return {role: {alg: self.public[label][alg] for alg in ALGORITHMS[profile]}
                for role, label in ((OWNER, owner), (WITNESS, WITNESS))}

    def seal(self, domain, body, role, signer, algorithm):
        key = self.fingerprint(signer, algorithm)
        message = encode([REALM, domain, role, key, algorithm, body])
        return {"key": key, "algorithm": algorithm, "role": role,
                "signature": self.private[signer, algorithm].sign(message).hex()}

    def claim(self, *, operation=None, owner=OWNER, **changes):
        operation = self.request if operation is None else operation
        current = json.loads(self.anchor.policy)
        body = {"v": 2, "realm": REALM, "policy": sha(self.anchor.policy), "epoch": current["epoch"],
                "nonce": json.loads(operation)["request_id"], "request": sha(operation),
                "issued": self.now, "expires": self.now + 20}
        body.update(changes)
        return {"claim": body, "signatures": [self.seal("effect", body, role, signer, alg)
                for role, signer in ((OWNER, owner), (WITNESS, WITNESS)) for alg in ALGORITHMS[current["profile"]]]}

    def transition(self, action="rotate", *, owner=OWNER, signers=None, body_changes=None, **changes):
        new = json.loads(self.anchor.policy)
        if signers is None:
            if action == "rotate":
                signers = [(OWNER, owner, alg) for alg in ALGORITHMS[new["profile"]]]
            else:
                signers = [(RECOVERY, RECOVERY, PQ)]
            signers.append((POLICY_WITNESS, POLICY_WITNESS, PQ))
        new.update(epoch=new["epoch"] + 1, predecessor=sha(self.anchor.policy))
        new.update(changes)
        body = {"action": action, "next": new, "realm": REALM, "instance": "specimen",
                "issued": self.now, "expires": self.now + 20}
        body.update(body_changes or {})
        return {"transition": body, "signatures": [self.seal("transition", body, *slot) for slot in signers]}

    def advance(self, transition):
        before = self.anchor.policy
        try:
            self.anchor.transition(encode(transition))
        except verifier.Denied:
            check(self.anchor.policy == before, "denied transition changed policy")
            raise
        self.counter.synchronize()

    def quarantine(self, **changes):
        self.advance(self.transition("emergency-quarantine", mode="quarantine", **changes))

    def submit(self, request, evidence):
        value = self.counter.apply(request, evidence)
        self.committed_requests.append(json.loads(request)["request_id"])
        return value

    def apply(self, claim, operation=None):
        return self.submit(self.request if operation is None else operation, encode(claim))

    def counts(self):
        with closing(sqlite3.connect(self.counter.path)) as db:
            value, = db.execute("SELECT value FROM state").fetchone()
            ids = [row[0] for row in db.execute("SELECT nonce FROM receipts ORDER BY value")]
            return value, ids


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def corrupted(signature):
    return ("00" if signature[:2] != "00" else "01") + signature[2:]


def expect_denied(call, reason):
    try:
        call()
    except verifier.Denied as exc:
        check(str(exc) == reason, str(exc))
    else:
        raise AssertionError("unexpected authority")


def race(f):
    old = f.claim()
    started, proceed = Event(), Event()

    def pending():
        verifier.evaluate(encode(old), f.request, f.genesis, f.now, expected_request_id=f.nonce)
        started.set()
        check(proceed.wait(5), "race synchronization")
        return f.apply(old)

    with ThreadPoolExecutor(1) as pool:
        future = pool.submit(pending)
        try:
            check(started.wait(5), "race synchronization")
            keys = f.effect_keys(owner="replacement")
            f.advance(f.transition(keys=keys, revoked_keys=[f.fingerprint(OWNER, ED)]))
            new_request = f.operation("24" * 16)
            f.anchor.set_disposable_permit(new_request, enabled=True)
            f.apply(f.claim(owner="replacement", operation=new_request), new_request)
        finally:
            proceed.set()
        future.result()


def commit_before_revocation(f):
    """Force the updater to contend while the writer holds its final commit fence."""
    at_commit, contended = Event(), Event()
    lock = f.anchor.lock

    class ObservedLock:
        def __enter__(self):
            if not lock.acquire(blocking=False):
                contended.set()
                lock.acquire()

        def __exit__(self, *args):
            lock.release()

    class PausedCommit(sqlite3.Connection):
        def commit(self):
            at_commit.set()
            check(contended.wait(5), "policy writer did not reach the held commit fence")
            super().commit()

    doc = f.claim()
    stop = f.transition("emergency-quarantine", mode="quarantine", revoked_algorithms=[ED])
    connect = partial(sqlite3.connect, factory=PausedCommit)
    with patch.object(f.anchor, "lock", ObservedLock()), patch.object(counter.sqlite3, "connect", connect):
        with ThreadPoolExecutor(2) as pool:
            write = pool.submit(f.apply, doc)
            check(at_commit.wait(5), "counter writer did not reach commit")
            revoke = pool.submit(f.advance, stop)
            check(write.result(timeout=10) == 1, "expected the already-fenced write")
            revoke.result(timeout=10)
    f.apply(doc)


def crash(f, *, after_commit):
    claim = f.claim()

    class CrashAtCommit(sqlite3.Connection):
        def commit(self):
            if after_commit:
                super().commit()
            os._exit(17)

    def writer():
        connection = partial(sqlite3.connect, factory=CrashAtCommit)
        with patch.object(counter.sqlite3, "connect", connection):
            f.apply(claim)

    child = multiprocessing.get_context("fork").Process(target=writer)
    child.start()
    child.join(10)
    if child.is_alive():
        child.kill()
        child.join()
    check(child.exitcode == 17 and f.anchor.sequence == 1, "writer missed the real commit boundary")
    f.counter = counter.Counter(f.counter.path, f.anchor)
    if after_commit:
        check(f.counter.receipt(f.nonce, f.request, encode(claim)) == 1, "read receipt after lost reply")
        # The writer died before it could acknowledge. Record the durable receipt.
        f.committed_requests.append(f.nonce)
    f.apply(claim)


def scenario(name, f):
    omitted = {"missing-owner-ed": (OWNER, ED), "missing-owner-pq": (OWNER, PQ),
               "missing-witness-ed": (WITNESS, ED), "missing-witness-pq": (WITNESS, PQ)}
    if name in omitted:
        doc = f.claim()
        doc["signatures"] = [s for s in doc["signatures"] if (s["role"], s["algorithm"]) != omitted[name]]
        f.apply(doc)
    elif name in {"hybrid-one-key-per-role", "signatures-permuted", "effect-signature-domain"}:
        doc = f.claim()
        if name == "hybrid-one-key-per-role":
            doc["signatures"] = [s for s in doc["signatures"]
                                 if (s["role"], s["algorithm"]) in ((OWNER, ED), (WITNESS, PQ))]
        elif name == "signatures-permuted":
            doc["signatures"].reverse()
        else:
            doc["signatures"][0] = f.seal("transition", doc["claim"], OWNER, OWNER, ED)
        f.apply(doc)
    elif name in {"positive-hybrid", "missing-signature", "duplicate-signature", "wrong-role",
                "unknown-algorithm", "algorithm-substitution", "bad-ed25519", "bad-ml-dsa"}:
        doc = f.claim()
        seals = doc["signatures"]
        if name == "missing-signature":
            seals.pop()
        elif name == "duplicate-signature":
            seals[1] = seals[0]
        elif name == "wrong-role":
            seals[0]["role"] = WITNESS
        elif name == "unknown-algorithm":
            seals[0]["algorithm"] = "unknown-v1"
        elif name == "algorithm-substitution":
            seals[0] = f.seal("effect", doc["claim"], OWNER, WITNESS, PQ)
        elif name.startswith("bad-"):
            seal = next(s for s in seals if s["algorithm"] == (PQ if name == "bad-ml-dsa" else ED))
            seal["signature"] = corrupted(seal["signature"])
        f.apply(doc)
    elif name in {"wrong-realm", "request-binding", "request-id-binding", "stale-epoch",
                  "thirty-second-claim", "thirty-one-second-claim"}:
        changes = {"wrong-realm": {"realm": "foreign"}, "request-binding": {"request": "ab" * 32},
                   "request-id-binding": {"nonce": "ab" * 16}, "thirty-second-claim": {"expires": f.now + 30},
                   "thirty-one-second-claim": {"expires": f.now + 31},
                   "stale-epoch": {"epoch": 1}}
        f.apply(f.claim(**changes[name]))
    elif name in {"stale-clock", "checkpoint-unavailable", "commit-expiry"}:
        doc = f.claim()
        if name == "commit-expiry":
            clock = iter([100, 100, 121])
            f.anchor.clock = lambda: next(clock)
        elif name == "stale-clock":
            f.now = 99
        else:
            f.anchor.available = False
        f.apply(doc)
    elif name in {"backend-unavailable", "backend-identity", "backend-binary-pin"}:
        doc = f.claim()
        probes = {"backend-unavailable": patch.object(verifier, "version", side_effect=ImportError),
                  "backend-identity": patch.object(verifier, "version", return_value="0"),
                  "backend-binary-pin": patch.object(verifier, "extension_sha256", return_value="0" * 64)}
        with probes[name]:
            f.apply(doc)
    elif name in {"duplicate-field", "oversized-wire", "deep-wire", "noncanonical-wire"}:
        malformed = {"duplicate-field": b'{"a":0,"a":1}', "oversized-wire": b" " * 32769,
                     "deep-wire": b"[" * 2000 + b"]" * 2000, "noncanonical-wire": b'{ "a": 0 }'}
        f.submit(f.request, malformed[name])
    elif name in {"forged-policy", "foreign-transition", "expired-transition",
                  "same-epoch", "wrong-predecessor", "compromised-owner"}:
        variants = {"foreign-transition": {"body_changes": {"instance": "foreign"}},
                    "expired-transition": {"body_changes": {"issued": 70, "expires": 100}},
                    "same-epoch": {"epoch": 0, "revoked_algorithms": ["ed25519-v1"]}, "wrong-predecessor": {"predecessor": "ab" * 32},
                    "compromised-owner": {"action": "emergency-quarantine", "mode": "quarantine",
                                          "signers": ((RECOVERY, OWNER, ED), (POLICY_WITNESS, POLICY_WITNESS, PQ))}}
        doc = f.transition(**variants.get(name, {}))
        if name == "forged-policy":
            doc["transition"]["next"]["revoked_algorithms"] = ["ed25519-v1"]
        f.advance(doc)
    elif name in {"reintroduced-key", "dropped-revocation", "algorithm-revocation"}:
        if name == "algorithm-revocation":
            f.advance(f.transition(revoked_algorithms=["ed25519-v1"]))
            f.anchor.set_disposable_permit(f.request, enabled=True)
            f.apply(f.claim())
        else:
            revoked = f.fingerprint(OWNER, ED)
            f.advance(f.transition(keys=f.effect_keys(owner="replacement"),
                                   revoked_keys=[revoked]))
            doc = f.transition(owner="replacement", keys=(f.genesis["keys"] if name == "reintroduced-key"
                               else f.effect_keys(owner="replacement")),
                               revoked_keys=[] if name == "dropped-revocation" else [revoked])
            f.advance(doc)
    elif name == "same-epoch-claim-pin":
        f.apply(f.claim(policy="ab" * 32))
    elif name == "foreign-effect":
        foreign = f.operation(f.nonce, instance="different-counter")
        doc = f.claim(request=sha(foreign))
        f.submit(foreign, encode(doc))
    elif name == "rotate-while-quarantined":
        f.quarantine()
        f.advance(f.transition(mode="active"))
    elif name == "evidence-withdrawn-permit":
        doc = f.claim()
        verifier.evaluate(encode(doc), f.request, f.genesis, f.now, expected_request_id=f.nonce)
        f.anchor.set_disposable_permit(f.request, enabled=False)
        f.apply(doc)
    elif name == "permit-bound-to-policy":
        f.advance(f.transition())
        f.apply(f.claim())
    elif name == "permit-bound-to-request":
        other = f.operation("42" * 16)
        f.apply(f.claim(operation=other), other)
    elif name in {"ordinary-profile-change", "unknown-profile"}:
        new_profile = "pq-only" if name == "ordinary-profile-change" else "unknown"
        f.advance(f.transition(profile=new_profile, keys=f.effect_keys("pq-only")))
    elif name in {"recover-to-pq-only", "pq-only-missing-owner", "pq-only-missing-witness"}:
        old = f.claim()
        f.quarantine(revoked_algorithms=[ED])
        f.advance(f.transition("recover", mode="active", profile="pq-only", keys=f.effect_keys("pq-only")))
        f.anchor.set_disposable_permit(f.request, enabled=True)
        expect_denied(lambda: f.apply(old), "current-policy")
        doc = f.claim()
        if name != "recover-to-pq-only":
            remove = OWNER if name == "pq-only-missing-owner" else WITNESS
            doc["signatures"] = [s for s in doc["signatures"] if s["role"] != remove]
        f.apply(doc)
    elif name in {"pq-revoked-at-recovery", "revoked-policy-witness", "wrong-recovery-witness"}:
        if name == "pq-revoked-at-recovery":
            f.quarantine(revoked_algorithms=[PQ])
        elif name == "revoked-policy-witness":
            f.quarantine(revoked_keys=[f.fingerprint(POLICY_WITNESS, PQ)])
        else:
            f.quarantine()
        witness = "wrong" if name == "wrong-recovery-witness" else POLICY_WITNESS
        f.advance(f.transition("recover", mode="active",
                               signers=((RECOVERY, RECOVERY, PQ), (POLICY_WITNESS, witness, PQ))))
    elif name in {"duplicate-role-key", "recovery-keys-shared-with-effects"}:
        keys = f.effect_keys()
        keys[WITNESS][PQ] = f.public[OWNER if name == "duplicate-role-key" else RECOVERY][PQ]
        f.advance(f.transition(keys=keys))
    elif name == "rotate-without-owner-pq":
        doc = f.transition(signers=((OWNER, OWNER, ED), (POLICY_WITNESS, POLICY_WITNESS, PQ)))
        f.advance(doc)
    elif name == "revoke-in-place":
        f.advance(f.transition(revoked_keys=[f.fingerprint(OWNER, ED)]))
        f.apply(f.claim())
    elif name == "expiry-at-policy-publication":
        doc = f.transition()
        clock = iter([f.now, f.now + 20])
        f.anchor.clock = lambda: next(clock)
        f.advance(doc)
    elif name == "replayed-successor":
        doc = f.transition()
        f.advance(doc)
        f.advance(doc)
    elif name in {"revoked-owner-after-recovery", "recovery-success"}:
        keys = f.effect_keys(owner="replacement")
        f.quarantine(keys=keys, revoked_keys=[f.fingerprint(OWNER, ED)])
        f.advance(f.transition("recover", mode="active"))
        f.anchor.set_disposable_permit(f.request, enabled=True)
        f.apply(f.claim(owner=OWNER if name == "revoked-owner-after-recovery" else "replacement"))
    elif name == "quarantine":
        f.quarantine()
        f.apply(f.claim())
    elif name == "revoked-recovery-root":
        f.quarantine(revoked_keys=[f.fingerprint(RECOVERY, PQ)])
        f.advance(f.transition("recover", mode="active"))
    elif name.startswith("recovery-"):
        if name != "recovery-without-quarantine":
            f.quarantine(**({"revoked_algorithms": ["ed25519-v1"]} if name == "recovery-revoked-algorithm" else {}))
        variants = {"recovery-without-witness": {"signers": ((RECOVERY, RECOVERY, PQ),)},
                    "recovery-wrong-root": {"signers": ((RECOVERY, "wrong", PQ), (POLICY_WITNESS, POLICY_WITNESS, PQ))}}
        doc = f.transition("recover", mode="active", **variants.get(name, {}))
        if name == "recovery-stale-checkpoint":
            f.anchor.available = False
        if name == "recovery-backend-failure":
            with patch.object(verifier, "version", side_effect=ImportError):
                f.advance(doc)
        f.advance(doc)
        f.apply(f.claim())
    elif name == "commit-revocation-race":
        race(f)
    elif name == "counter-commit-before-revocation":
        commit_before_revocation(f)
    elif name == "exact-receipt-and-replay":
        doc = f.claim()
        f.apply(doc)
        f.counter = counter.Counter(f.counter.path, f.anchor)
        check(f.counter.receipt(f.nonce, f.request, encode(doc)) == 1, "receipt recovery")
        expect_denied(lambda: f.counter.receipt(f.nonce, f.request, encode(f.claim())), "receipt-binding")
        f.apply(doc)
    elif name == "concurrent-replay":
        doc = f.claim()
        with ThreadPoolExecutor(2) as pool:
            jobs = [pool.submit(f.apply, doc) for _ in range(2)]
            outcomes = []
            for job in jobs:
                try:
                    outcomes.append(job.result())
                except verifier.Denied as exc:
                    outcomes.append(str(exc))
        check(outcomes.count(1) == 1 and outcomes.count("authorization-used") == 1, "one-use race")
        raise verifier.Denied("authorization-used")
    elif name == "receipt-after-quarantine":
        doc = f.claim()
        f.apply(doc)
        f.quarantine()
        f.now += 21
        check(f.counter.receipt(f.nonce, f.request, encode(doc)) == 1, "historical exact receipt")
        f.apply(doc)
    elif name == "tampered-archive":
        raw = encode(f.claim())
        check(verifier.historical_archive(raw, sha(raw)) == "HISTORICAL_BYTES_ONLY", "historical")
        verifier.historical_archive(raw + b"x", sha(raw))
    elif name == "restored-db":
        before = f.counter.path.read_bytes()
        doc = f.claim()
        f.apply(doc)
        f.counter.path.write_bytes(before)
        f.counter = counter.Counter(f.counter.path, f.anchor)
        f.apply(doc)
    elif name == "restored-policy-epoch":
        before = f.counter.path.read_bytes()
        old = f.claim()
        f.quarantine()
        f.counter.path.write_bytes(before)
        f.counter = counter.Counter(f.counter.path, f.anchor)
        expect_denied(lambda: f.apply(old), "checkpoint-state-mismatch")
        f.counter.synchronize()
        f.apply(old)
    elif name in {"crash-before-commit", "crash-after-commit"}:
        crash(f, after_commit=name == "crash-after-commit")
    else:
        raise AssertionError(name)


def ed25519_known_answer():
    # RFC 8032 section 7.1, TEST 1 (empty message).
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    verifier.public_types()["ed25519-v1"].from_public_bytes(public).verify(signature, b"")
    print(json.dumps({"known_answer": "RFC 8032 section 7.1 TEST 1", "status": "verified"}))


def mldsa_known_answers():
    sample = json.loads(Path(__file__).with_name("acvp-sigver.json").read_text())
    key_type = verifier.public_types()[PQ]
    for row in sample["tests"]:
        public = key_type.from_public_bytes(bytes.fromhex(row["pk"]))
        try:
            public.verify(bytes.fromhex(row["signature"]), bytes.fromhex(row["message"]), bytes.fromhex(row["context"]))
            valid = True
        except InvalidSignature:
            valid = False
        check(valid is row["testPassed"], "ACVP verification mismatch")
        print(json.dumps({"known_answer": "NIST ACVP ML-DSA-65 sigVer", "tgId": sample["tgId"],
                          "tcId": row["tcId"], "expected": row["testPassed"], "observed": valid}))


def openssl_crosscheck(f):
    executable = "/usr/bin/openssl"
    for role, algorithm in ((OWNER, ED), (WITNESS, PQ)):
        private = f.private[role, algorithm]
        raw = b"WT-CRYPTO-002 independent provider verification"
        sig = private.sign(raw)
        public = private.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
        for name, data in (("msg", raw), ("public.pem", public), ("sig", sig)):
            (f.path / name).write_bytes(data)
        args = [executable, "pkeyutl", "-verify", "-pubin", "-inkey", "public.pem", "-rawin",
                "-in", "msg", "-sigfile", "sig"]
        subprocess.run(args, cwd=f.path, check=True, capture_output=True)
        (f.path / "msg").write_bytes(raw + b"x")
        negative = subprocess.run(args, cwd=f.path, capture_output=True)
        check(negative.returncode == 1, "independent negative verification")
        print(json.dumps({"provider": "OpenSSL CLI", "role": role, "algorithm": algorithm, "positive": "verified", "negative": "denied"}))


def run(cases):
    expectations = json.loads(Path(__file__).with_name("expected.json").read_text())
    mismatches = 0
    for name in cases or expectations:
        with tempfile.TemporaryDirectory() as path:
            f = Fixture(path, CrashCheckpoint if name.startswith("crash-") else counter.Checkpoint)
            reason = "committed"
            try:
                scenario(name, f)
            except verifier.Denied as exc:
                reason = str(exc)
            value, receipt_ids = f.counts()
            expected = expectations[name]
            commits = f.committed_requests
            expected_ids = expected["committed_requests"]
            match = (reason == expected["outcome"] and value == expected["counter"]
                     and commits == expected_ids and receipt_ids == expected_ids[:value])
            print(json.dumps({"case": name, "expected": expected, "observed": [reason, value],
                              "committed_requests": commits, "receipt_ids": receipt_ids,
                              "receipts": len(receipt_ids), "checkpoint_sequence": f.anchor.sequence, "match": match}))
            mismatches += not match
    return mismatches


if __name__ == "__main__":
    if len(sys.argv) == 1:
        ed25519_known_answer()
        mldsa_known_answers()
        with tempfile.TemporaryDirectory() as path:
            openssl_crosscheck(Fixture(path))
    sys.exit(bool(run(sys.argv[1:])))

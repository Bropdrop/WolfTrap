"""Compare the pinned v1 prototype with v2 using the same disposable public keys."""

import importlib
import json
from pathlib import Path
import sys
import tempfile

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import verifier
from challenge import ED, OWNER, PQ, REALM, WITNESS, Fixture, check, encode, sha

ARCHIVE_SHA256 = "926a1976693eef52553b1df145c42148ad100f3e4f42cb4dc5742f9bd68d2b02"
ROLES = {OWNER: "owner", WITNESS: "witness"}
ALGORITHMS = {ED: "Ed25519", PQ: "ML-DSA-65"}


def legacy_inputs(legacy, fixture, profile, *, expires=130):
    current = json.loads(fixture.anchor.policy)
    keys, signers = [], []
    for role, label in ROLES.items():
        for algorithm, name in ALGORITHMS.items():
            if profile == "pq-only" and algorithm == ED:
                continue
            signer = fixture.private[role, algorithm]
            public = signer.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
            keys.append(legacy.Key(label, name, public))
            signers.append(signer)
    revoked = frozenset({"Ed25519"}) if profile == "pq-only" else frozenset()
    policy = legacy.Policy(REALM, current["epoch"], profile, tuple(keys), revoked_algorithms=revoked)
    claim = {"realm": REALM, "epoch": policy.epoch, "policy_digest": legacy.policy_digest(policy),
             "request_id": fixture.nonce, "effect_digest": sha(fixture.request), "issued_at": 100, "expires_at": expires}
    seals = tuple(legacy.Signature(key.role, key.alg, key.kid, signer.sign(legacy.message(claim, key.role, key.alg, key.kid)))
                  for key, signer in zip(keys, signers, strict=True))
    return policy, claim, seals


def compare(legacy, f, name, profile, *, keep=lambda role, algorithm: True,
            expires=130, expected_request=None, expected=True, repetitions=1):
    old_policy, old_claim, old_sigs = legacy_inputs(legacy, f, profile, expires=expires)
    old_sigs = tuple(s for s in old_sigs if keep(s.role, s.alg))
    new = f.claim(expires=expires)
    new["signatures"] = [s for s in new["signatures"] if keep(ROLES[s["role"]], ALGORITHMS[s["algorithm"]])]
    new_wire = encode(new)
    request_id = f.nonce if expected_request is None else expected_request
    expected_status = "EVIDENCE_ACCEPTED" if expected else "DENY"
    for _ in range(repetitions):
        v1 = legacy.evaluate(old_policy, old_claim, old_sigs, expected_request=request_id,
                             expected_effect=sha(f.request), now=f.now, epoch_floor=old_policy.epoch)
        try:
            verifier.evaluate(new_wire, f.request, json.loads(f.anchor.policy), f.now, expected_request_id=request_id)
            v2 = "EVIDENCE_ACCEPTED"
        except verifier.Denied:
            v2 = "DENY"
        check(v1.status == v2 == expected_status and f.counts() == (0, []), name)
    print(json.dumps({"comparison": name, "profile": profile, "expected": expected_status,
                      "original": v1.status, "successor": v2, "evaluations_per_version": repetitions,
                      "disposable_effects": 0}))
    return old_sigs


def inspect(archive):
    raw = archive.read_bytes()
    check(sha(raw) == ARCHIVE_SHA256, "unexpected prototype archive")
    sys.path.insert(0, str(archive.resolve()) + "/WolfTrap-CRYPTOFALL-0.1.0a1")
    try:
        legacy = importlib.import_module("cryptofall")
    finally:
        sys.path.pop(0)
    check(str(archive.resolve()) + "/" in legacy.__file__, "unexpected prototype module")
    with tempfile.TemporaryDirectory() as path:
        f = Fixture(path)
        accepted = compare(legacy, f, "all-four-at-thirty-seconds", "hybrid")
        compare(legacy, f, "repeat-evidence-without-effect", "hybrid", repetitions=2)
        compare(legacy, f, "one-algorithm-per-role", "hybrid", expected=False,
                keep=lambda role, alg: (role, alg) in (("owner", "Ed25519"), ("witness", "ML-DSA-65")))
        compare(legacy, f, "thirty-one-seconds", "hybrid", expires=131, expected=False)
        compare(legacy, f, "different-request-id", "hybrid", expected_request="ab" * 16, expected=False)

        # Keep the v2 metadata and same keys, but carry only genuine v1 signature bytes.
        v2 = f.claim(expires=130)
        for new, old in zip(v2["signatures"], accepted, strict=True):
            new["signature"] = old.value.hex()
        try:
            f.apply(v2)
        except verifier.Denied as exc:
            check(str(exc) == "signature-or-backend", "cross-version signature mismatch")
        else:
            raise AssertionError("v1 signatures authorized a v2 effect")
        check(f.counts() == (0, []), "cross-version effect")
        print(json.dumps({"boundary": "genuine-v1-signatures-at-v2-counter", "result": "DENY", "disposable_effects": 0}))

        f.quarantine(revoked_algorithms=[ED])
        f.advance(f.transition("recover", mode="active", profile="pq-only", keys=f.effect_keys("pq-only")))
        compare(legacy, f, "explicit-pq-only-after-classical-revocation", "pq-only")
        compare(legacy, f, "pq-only-needs-witness", "pq-only", keep=lambda role, alg: role == "owner", expected=False)

        classification = verifier.historical_archive(raw, ARCHIVE_SHA256)
        check(classification == "HISTORICAL_BYTES_ONLY", "archive classification")
        try:
            verifier.historical_archive(raw[:-1], ARCHIVE_SHA256)
        except verifier.Denied as exc:
            check(str(exc) == "archive-integrity", "archive rejection")
        else:
            raise AssertionError("changed prototype archive accepted")
        check(f.counts() == (0, []), "historical effect")
        print(json.dumps({"boundary": "supplied-archive", "classification": classification,
                          "altered_bytes": "DENY", "disposable_effects": 0}))


if __name__ == "__main__":
    inspect(Path(sys.argv[1]))

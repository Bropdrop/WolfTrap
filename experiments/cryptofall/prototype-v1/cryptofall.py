"""WT-CRYPTO-001 standalone evaluation only. Never grants or executes authority."""
from dataclasses import dataclass
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

# Exact, parameter-free DER SubjectPublicKeyInfo encodings and signature lengths.
ALGS = {
    'Ed25519': (bytes.fromhex('302a300506032b6570032100'), 44, 64),
    'ML-DSA-65': (bytes.fromhex('308207b2300b0609608648016503040312038207a100'), 1974, 3309),
}
ROLES = ('owner', 'witness')
MODES = {'hybrid': ('Ed25519', 'ML-DSA-65'), 'pq-only': ('ML-DSA-65',)}
HEX = re.compile(r'[0-9a-f]{64}\Z')
TOKEN = re.compile(r'[A-Za-z0-9_.:-]{1,96}\Z')
OPENSSL = '/usr/bin/openssl'
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'OPENSSL_CONF': '/dev/null'}

@dataclass(frozen=True)
class Key:
    role: str
    alg: str
    public: bytes
    @property
    def kid(self):
        return hashlib.sha256(self.public).hexdigest()

@dataclass(frozen=True)
class Policy:
    realm: str
    epoch: int
    mode: str
    keys: tuple[Key, ...]
    revoked_keys: frozenset[str] = frozenset()
    revoked_algorithms: frozenset[str] = frozenset()

@dataclass(frozen=True)
class Signature:
    role: str
    alg: str
    kid: str
    value: bytes

@dataclass(frozen=True)
class Verdict:
    status: str
    reason: str

FIELDS = {'realm', 'epoch', 'policy_digest', 'request_id', 'effect_digest', 'issued_at', 'expires_at'}

def token(v):
    return type(v) is str and TOKEN.fullmatch(v) is not None

def digest(v):
    return type(v) is str and HEX.fullmatch(v) is not None

def natural(v):
    return type(v) is int and 0 <= v < 2**63

def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')

def valid_key(k):
    if type(k) is not Key or k.role not in ROLES or k.alg not in ALGS or type(k.public) is not bytes:
        return False
    prefix, size, _ = ALGS[k.alg]
    return len(k.public) == size and k.public.startswith(prefix)

def validate_policy(p):
    if type(p) is not Policy or not token(p.realm) or not natural(p.epoch) or p.mode not in MODES:
        return False
    if type(p.keys) is not tuple or len(p.keys) > 16 or not all(valid_key(k) for k in p.keys):
        return False
    if type(p.revoked_keys) is not frozenset or type(p.revoked_algorithms) is not frozenset:
        return False
    if len(p.revoked_keys) > 128 or not all(digest(k) for k in p.revoked_keys) or not p.revoked_algorithms <= ALGS.keys():
        return False
    # No reuse across roles; exactly one pinned key per required role/algorithm.
    expected = {(r, a) for r in ROLES for a in MODES[p.mode]}
    return (len({k.kid for k in p.keys}) == len(p.keys)
            and len(p.keys) == len(expected)
            and {(k.role, k.alg) for k in p.keys} == expected)

def policy_digest(p):
    return hashlib.sha256(b'WT-CRYPTO-001/policy/v1\0' + canonical({
        'realm': p.realm, 'epoch': p.epoch, 'mode': p.mode,
        'keys': sorted((k.role, k.alg, k.kid) for k in p.keys),
        'revoked_keys': sorted(p.revoked_keys), 'revoked_algorithms': sorted(p.revoked_algorithms),
    })).hexdigest()

def message(claim, role, alg, kid):
    # Each signature binds the same claim plus its role and algorithm slot.
    return b'WT-CRYPTO-001/evidence/v1\0' + canonical({'claim': claim, 'role': role, 'alg': alg, 'kid': kid})

def verify_signature(k, msg, sig):
    if not valid_key(k) or type(sig) is not bytes or len(sig) != ALGS[k.alg][2]:
        return False
    with tempfile.TemporaryDirectory(prefix='cryptofall-verify-') as tmp:
        root = Path(tmp)
        for name, value in [('key.der', k.public), ('msg', msg), ('sig', sig)]:
            (root / name).write_bytes(value)
        proc = subprocess.run([OPENSSL, 'pkeyutl', '-verify', '-rawin', '-pubin', '-keyform', 'DER', '-inkey', str(root/'key.der'), '-in', str(root/'msg'), '-sigfile', str(root/'sig')], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, env=ENV, check=False)
        return proc.returncode == 0

def evaluate(policy, claim, signatures, *, expected_request, expected_effect, now, epoch_floor):
    """Inputs policy, clock, floor, and expected request/effect MUST be trusted.

    Acceptance is a signature-evidence result only. No owner grant, freshness
    witness, persistent replay fence, policy transition or protected effect.
    """
    def deny(reason):
        return Verdict('DENY', reason)
    try:
        if not validate_policy(policy) or not natural(now) or not natural(epoch_floor):
            return deny('invalid-trusted-input')
        if policy.epoch != epoch_floor:
            return deny('policy-epoch-mismatch')
        if not token(expected_request) or not digest(expected_effect):
            return deny('invalid-expected-request')
        if type(claim) is not dict or set(claim) != FIELDS:
            return deny('invalid-claim-shape')
        if not all(natural(claim[f]) for f in ('epoch','issued_at','expires_at')):
            return deny('invalid-claim-integer')
        if not token(claim['realm']) or not token(claim['request_id']) or not digest(claim['effect_digest']) or not digest(claim['policy_digest']):
            return deny('invalid-claim-value')
        if (claim['realm'], claim['epoch'], claim['policy_digest']) != (policy.realm, policy.epoch, policy_digest(policy)):
            return deny('policy-binding-mismatch')
        if (claim['request_id'], claim['effect_digest']) != (expected_request, expected_effect):
            return deny('request-effect-mismatch')
        if not (claim['issued_at'] <= now < claim['expires_at'] and 0 < claim['expires_at']-claim['issued_at'] <= 30):
            return deny('freshness')
        if type(signatures) is not tuple or len(signatures) != len(policy.keys):
            return deny('signature-set-mismatch')
        by_slot = {(k.role,k.alg): k for k in policy.keys}
        seen = set()
        for s in signatures:
            if type(s) is not Signature or type(s.role) is not str or type(s.alg) is not str or not digest(s.kid):
                return deny('invalid-signature-shape')
            slot = (s.role,s.alg)
            k = by_slot.get(slot)
            if k is None or slot in seen or s.kid != k.kid:
                return deny('signature-slot-mismatch')
            seen.add(slot)
            if k.alg in policy.revoked_algorithms or k.kid in policy.revoked_keys:
                return deny('revoked-trust')
            if not verify_signature(k, message(claim,s.role,s.alg,s.kid), s.value):
                return deny('signature-invalid-or-backend-failed')
        if seen != set(by_slot):
            return deny('signature-set-mismatch')
        return Verdict('EVIDENCE_ACCEPTED', 'all-required-signatures-valid; no execution authority')
    except (OSError, subprocess.SubprocessError, TypeError, ValueError, AttributeError, OverflowError):
        return deny('malformed-input-or-backend-unavailable')

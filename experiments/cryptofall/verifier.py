"""Evidence-only, opt-in CRYPTOFALL wire verification."""

import hashlib
import json
import re
from functools import lru_cache
from importlib.metadata import version
from types import MappingProxyType

REALM = "wolftrap:cryptofall:disposable:v2"
BACKEND = ("50.0.0", "OpenSSL 4.0.1 9 Jun 2026")
EXTENSION_SHA256 = "613ec570594be2691ce18fe8aa51aa4716584c0e586ec97dd790c4b9757b5a83"
REGISTRY = MappingProxyType({"ed25519-v1": (32, 64), "ml-dsa-65-v1": (1952, 3309)})
PROFILES = MappingProxyType({"hybrid": ("ed25519-v1", "ml-dsa-65-v1"), "pq-only": ("ml-dsa-65-v1",)})
EFFECT_ROLES = ("owner-test", "effect-witness-test")
MAX_LIFETIME = 30


class Denied(Exception):
    """The input supplies no usable authority."""


def require(condition, reason):
    if not condition:
        raise Denied(reason)


def wire(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def unique(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), "duplicate-field")
    return result


def unsupported_number(_):
    raise Denied("wire-number")


def parse(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 32768, "wire-size")
    depth = 0
    for token in re.finditer(rb'"(?:[^"\\]|\\.)*"|[{}\[\]]', raw):
        symbol = token[0]
        if symbol in (b"{", b"["):
            depth += 1
            require(depth <= 12, "wire-depth")
        elif symbol in (b"}", b"]"):
            depth -= 1
    try:
        result = json.loads(raw.decode("ascii"), object_pairs_hook=unique,
                            parse_float=unsupported_number, parse_constant=unsupported_number)
        require(type(result) is dict and wire(result) == raw, "canonical-wire")
    except (ValueError, RecursionError, OverflowError) as exc:
        raise Denied("wire-syntax") from exc
    return result


def shape(document, fields):
    names = fields.split() if isinstance(fields, str) else fields
    require(type(document) is dict and set(document) == set(names), "schema")


def natural(value):
    return type(value) is int and 0 <= value <= 2**53 - 1


def unhex(value, size):
    require(type(value) is str and len(value) == 2 * size
            and re.fullmatch("[0-9a-f]+", value), "hex-field")
    return bytes.fromhex(value)


def key_id(key):
    shape(key, "algorithm public")
    algorithm = key["algorithm"]
    require(type(algorithm) is str and algorithm in REGISTRY, "algorithm")
    unhex(key["public"], REGISTRY[algorithm][0])
    return digest(wire(key))


@lru_cache(maxsize=1)
def extension_sha256():
    from cryptography.hazmat.bindings import _rust

    with open(_rust.__file__, "rb") as extension:
        return hashlib.file_digest(extension, "sha256").hexdigest()


def public_types():
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa

    require((version("cryptography"), backend.openssl_version_text()) == BACKEND, "backend-identity")
    require(extension_sha256() == EXTENSION_SHA256, "backend-identity")
    return {"ed25519-v1": ed25519.Ed25519PublicKey, "ml-dsa-65-v1": mldsa.MLDSA65PublicKey}


def check_signature(domain, body, role, key, seal):
    shape(seal, "role key algorithm signature")
    algorithm = key["algorithm"]
    require(seal["role"] == role and seal["key"] == key_id(key)
            and seal["algorithm"] == algorithm, "signature-coordinate")
    public_size, sign_size = REGISTRY[algorithm]
    public = unhex(key["public"], public_size)
    signature = unhex(seal["signature"], sign_size)
    message = wire([REALM, domain, role, seal["key"], algorithm, body])
    try:
        public_types()[algorithm].from_public_bytes(public).verify(signature, message)
    except Denied:
        raise
    except Exception as exc:
        raise Denied("signature-or-backend") from exc


def endorsements(domain, body, seals, keys):
    require(type(seals) is list and len(seals) == len(keys), "signature-count")
    remaining = keys.copy()
    for seal in seals:
        shape(seal, "role key algorithm signature")
        role, algorithm = seal["role"], seal["algorithm"]
        require(type(role) is str and type(algorithm) is str, "signature-coordinate")
        key = remaining.pop((role, algorithm), None)
        require(key is not None, "signature-coordinate")
        check_signature(domain, body, role, key, seal)


def slots(document, roles=EFFECT_ROLES):
    """Enumerate only the slots required by the provisioned policy."""
    return {(role, alg): {"algorithm": alg, "public": document["keys"][role][alg]}
            for role in roles for alg in PROFILES[document["profile"]]}


def policy(document):
    shape(document, "v realm epoch predecessor mode profile keys revoked_keys revoked_algorithms")
    require(type(document["v"]) is int and document["v"] == 2
            and document["realm"] == REALM and natural(document["epoch"]), "policy-coordinate")
    unhex(document["predecessor"], 32)
    require(document["mode"] in ("active", "quarantine"), "policy-mode")
    profile = document["profile"]
    require(type(profile) is str and profile in PROFILES, "policy-profile")
    keys = document["keys"]
    shape(keys, EFFECT_ROLES)
    for role in EFFECT_ROLES:
        shape(keys[role], PROFILES[profile])
    required = slots(document)
    require(len({key_id(key) for key in required.values()}) == len(required), "shared-effect-key")
    for field in ("revoked_keys", "revoked_algorithms"):
        values = document[field]
        require(type(values) is list and len(values) <= 64
                and all(type(value) is str for value in values)
                and values == sorted(set(values)), "revocation-schema")
    for revoked in document["revoked_keys"]:
        unhex(revoked, 32)
    require(set(document["revoked_algorithms"]) <= REGISTRY.keys(), "revoked-algorithm")
    return document


def current_key(document, key):
    require(key_id(key) not in document["revoked_keys"]
            and key["algorithm"] not in document["revoked_algorithms"], "revoked-signer")
    return key


def evaluate(raw, request, current, now, *, expected_request_id):
    """Verify evidence against the caller's requested bytes, identity, time and policy."""
    policy(current)
    envelope = parse(raw)
    shape(envelope, "claim signatures")
    claim = envelope["claim"]
    shape(claim, "v realm epoch policy nonce request issued expires")
    unhex(claim["nonce"], 16)
    require(type(claim["v"]) is int and claim["v"] == 2 and claim["realm"] == REALM
            and natural(claim["epoch"]) and claim["epoch"] == current["epoch"]
            and claim["policy"] == digest(wire(current)) and current["mode"] == "active", "current-policy")
    require(claim["request"] == digest(request), "request-binding")
    require(claim["nonce"] == expected_request_id, "request-id-binding")
    issued, expires = claim["issued"], claim["expires"]
    require(natural(now) and natural(issued) and natural(expires) and issued <= now < expires
            and 0 < expires - issued <= MAX_LIFETIME, "claim-time")
    keys = {slot: current_key(current, key) for slot, key in slots(current).items()}
    endorsements("effect", claim, envelope["signatures"], keys)
    return claim["nonce"], expires


def historical_archive(raw, retained_digest):
    """Classify bytes against an independently retained digest, without authority."""
    require(type(raw) is bytes and len(raw) <= 32768 and digest(raw) == retained_digest, "archive-integrity")
    return "HISTORICAL_BYTES_ONLY"

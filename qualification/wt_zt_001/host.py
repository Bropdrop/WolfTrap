"""Fictional host. Only dispatch accepts a proposal. No transport or general effect API."""
import json
from contextlib import closing
from dataclasses import dataclass
import sqlite3

import jwt
from wolftrap.canonical import sha256_json

AUDIENCE = "urn:wolftrap:fixture:host"
ROLES = ("issuer", "owner", "policy")
FIELDS = {"principal", "tenant", "session", "task", "operation", "resource",
          "destination", "tool", "units", "currency", "slot", "claim"}
SCHEMA = """
CREATE TABLE policy (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1), binding TEXT NOT NULL,
    policy_version TEXT NOT NULL, generation INTEGER NOT NULL, tick INTEGER NOT NULL,
    credential_active INTEGER NOT NULL, grant_active INTEGER NOT NULL, ceiling INTEGER NOT NULL
);
CREATE TABLE facts (claim TEXT PRIMARY KEY);
CREATE TABLE effects (slot TEXT PRIMARY KEY, binding TEXT NOT NULL, digest TEXT NOT NULL,
    generation INTEGER NOT NULL, policy_version TEXT NOT NULL, tick INTEGER NOT NULL);
"""


class Denied(ValueError):
    pass


def statement(token, role, roots, tick):
    if token is None:
        raise Denied("missing-witness")
    if not isinstance(token, str) or len(token) > 8192:
        raise Denied("missing-or-invalid-witness")
    try:
        claims = jwt.decode(token, roots[role], algorithms=["EdDSA"], issuer=role,
                            audience=AUDIENCE, options={"strict_aud": True,
                            "require": ["iss", "aud", "nbf", "exp", "sub", "jti", "scope"],
                            "verify_exp": False, "verify_nbf": False})
    except (jwt.InvalidTokenError, TypeError, ValueError) as exc:
        raise Denied("untrusted-signature-or-claims") from exc
    # This closed fixture has a host-owned integer clock. No caller may supply the time.
    if type(claims["nbf"]) is not int or type(claims["exp"]) is not int:
        raise Denied("invalid-time")
    if not claims["nbf"] <= tick < claims["exp"]:
        raise Denied("outside-validity")
    return claims


@dataclass(frozen=True)
class Identity:
    status: str
    reason: str


def assess_identity(token, roots, tick, proposal, generation, active):
    if not active:
        return Identity("REVOKED_IDENTITY", "revoked-credential")
    if token is None:
        return Identity("DECLARED_IDENTITY", "missing-witness")
    try:
        claim = statement(token, "issuer", roots, tick)
    except Denied as exc:
        return Identity("UNKNOWN_IDENTITY", str(exc))
    scope = {k: proposal[k] for k in ("principal", "tenant", "session")}
    scope["generation"] = generation
    if (claim["sub"] != proposal["principal"] or claim["jti"] != proposal["slot"] or
            json.dumps(claim["scope"], sort_keys=True) != json.dumps(scope, sort_keys=True)):
        return Identity("CONFLICTING_IDENTITY", "scope-mismatch")
    return Identity("ATTESTED_IDENTITY", "matched-issuer")


def dispatch(db, proposal, tokens, roots):
    """The caller supplies a host-owned connection and independently selected public roots."""
    if set(roots) != set(ROLES) or len({k.public_bytes_raw() for k in roots.values()}) != 3:
        raise Denied("overlapping-trust-roots")
    if not isinstance(proposal, dict) or set(proposal) != FIELDS:
        raise Denied("unsupported-proposal")
    if type(proposal["units"]) is not int or not all(
        isinstance(proposal[k], str) and 0 < len(proposal[k]) <= 128 for k in FIELDS - {"units"}
    ):
        raise Denied("invalid-proposal")
    if set(tokens) - set(ROLES):
        raise Denied("missing-witness")
    with db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT binding, policy_version, generation, tick, credential_active, "
                         "grant_active, ceiling FROM policy WHERE singleton=1").fetchone()
        if row is None:
            raise Denied("missing-checkpoint")
        binding, version, generation, tick, credential_active, grant_active, ceiling = row
        allowed = json.loads(binding)
        identity = assess_identity(tokens.get("issuer"), roots, tick, proposal, generation, credential_active)
        if identity.status != "ATTESTED_IDENTITY":
            raise Denied(identity.reason)
        if not grant_active:
            raise Denied("revoked-grant")
        if proposal != allowed:
            raise Denied("outside-host-policy")
        if not 0 < proposal["units"] <= ceiling:
            raise Denied("limit")
        if proposal["operation"] not in {"transfer-fixture-units", "record-fixture-fact", "send-fixture-note"}:
            raise Denied("unsupported-operation")
        if proposal["operation"] == "record-fixture-fact":
            if not db.execute("SELECT 1 FROM facts WHERE claim=?", (proposal["claim"],)).fetchone():
                raise Denied("uncorroborated-claim")
        digest = sha256_json(proposal)
        for role in ("owner", "policy"):
            claim = statement(tokens.get(role), role, roots, tick)
            expected = {
                "binding": proposal, "digest": digest, "version": version, "generation": generation}
            if claim["sub"] != proposal["principal"] or claim["jti"] != proposal["slot"]:
                raise Denied("wrong-subject-or-use")
            if json.dumps(claim["scope"], sort_keys=True) != json.dumps(expected, sort_keys=True):
                raise Denied("scope-mismatch")
        try:
            db.execute("INSERT INTO effects VALUES (?, ?, ?, ?, ?, ?)",
                       (proposal["slot"], binding, digest, generation, version, tick))
        except sqlite3.IntegrityError as exc:
            raise Denied("spent-slot") from exc
    return "ACK"


def submit(path, proposal, tokens, roots):
    with closing(sqlite3.connect(path, timeout=10)) as db:
        return dispatch(db, proposal, tokens, roots)

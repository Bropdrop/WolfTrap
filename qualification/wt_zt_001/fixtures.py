"""Public deterministic fixture issuers. Their keys have no external authority."""
import hashlib
import json
import sqlite3
from contextlib import closing
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from host import SCHEMA

BASE = dict(principal="agent-alder", tenant="tenant-blue", session="session-1", task="task-42",
            operation="transfer-fixture-units", resource="purse-a", destination="purse-b",
            tool="fixture-ledger-v1", units=4, currency="TEST", slot="one-use-17", claim="none")
VERSION = "fixture-policy-v1"
ROLES = ("issuer", "owner", "policy")


def key(role):
    seed = hashlib.sha256(("public WT-ZT-001 fixture only/" + role).encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def roots():
    return {role: key(role).public_key() for role in ROLES}


def issue(role, binding, *, signer=None, generation=1, version=VERSION, start=10, end=20,
          scope_patch=None, subject=None):
    encoded = json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
    if role == "issuer":
        scope = {k: binding[k] for k in ("principal", "tenant", "session")}
        scope["generation"] = generation
    else:
        scope = dict(binding=binding, digest=hashlib.sha256(encoded).hexdigest(),
                     version=version, generation=generation)
    scope.update(scope_patch or {})
    return jwt.encode(dict(iss=role, aud="urn:wolftrap:fixture:host",
                           sub=binding["principal"] if subject is None else subject, jti=binding["slot"], nbf=start, exp=end,
                           scope=scope), key(signer or role), algorithm="EdDSA")


def provision(path, binding):
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript(SCHEMA)
        db.execute("INSERT INTO policy VALUES (1, ?, ?, 1, 12, 1, 1, 10)",
                   (json.dumps(binding, sort_keys=True), VERSION))


@dataclass(frozen=True)
class Observation:
    source: str
    trust: str
    stages: tuple
    text: str

    def derive(self, stage, text):
        return Observation(self.source, self.trust, (*self.stages, stage), text)


def recall(source, text):
    item = Observation(source, "UNTRUSTED_DATA", ("SOURCE",), text)
    for stage in ("INGESTION", "MEMORY", "RETRIEVAL", "DECISION", "PROPOSED EFFECT"):
        item = item.derive(stage, "Untrusted summary: " + item.text if stage == "MEMORY" else item.text)
    return item

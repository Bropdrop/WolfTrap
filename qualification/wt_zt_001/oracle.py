"""Read-only SQLite observer. No imports from the fixture issuer, host or agent."""
import hashlib
import json
import sqlite3
from contextlib import closing

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

VERSION = "wt-zt-oracle/1"


# Reviewed public fixtures pinned by this verifier. No key comes from the target or receipt.
ROOTS = {
    "issuer": "cdf51fe456b117206b21fb4a12319e53bc2f08204f157d715fc45743e4a5f1f4",
    "owner": "59605984452e1d9e7ef2b3ec149969f3a505135b239385420873ce3c78bf6323",
    "policy": "00b38dc416b0d400ce4c920a2d2451c3217059059ec848c856644de242f945d1",
}


def witnesses(tokens, request, policy):
    encoded = json.dumps(request, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    results = {}
    for role, pin in ROOTS.items():
        token = tokens.get(role)
        result = dict(issuer=role, public_key_sha256=hashlib.sha256(bytes.fromhex(pin)).hexdigest(),
                      statement_sha256=hashlib.sha256(token.encode()).hexdigest() if token else None,
                      signature="UNVERIFIED", current_and_bound=False)
        results[role] = result
        if token is None:
            continue
        try:
            claims = jwt.decode(token, Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin)),
                                algorithms=["EdDSA"], issuer=role, audience="urn:wolftrap:fixture:host",
                                options={"verify_exp":False,"verify_nbf":False,"strict_aud":True})
        except jwt.InvalidTokenError:
            continue
        result["signature"] = "VERIFIED"
        if policy is None:
            continue
        if role == "issuer":
            scope = {k:request[k] for k in ("principal","session","tenant")}
            scope["generation"] = policy["generation"]
        else:
            scope = dict(binding=request, digest=digest, version=policy["version"],
                         generation=policy["generation"])
        result["current_and_bound"] = (
            type(claims.get("exp")) is int and type(claims.get("nbf")) is int
            and claims["nbf"] <= policy["tick"] < claims["exp"] and claims.get("sub") == request["principal"]
            and claims.get("jti") == request["slot"] and json.dumps(claims.get("scope"), sort_keys=True)
            == json.dumps(scope, sort_keys=True)
            and bool(policy["credential"]) and bool(policy["grant"])
            and policy["binding"] == request and 0 < request["units"] <= policy["limit"])
    return results


def observe(path):
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
        data = db.execute("SELECT slot, binding, digest, generation, policy_version, tick "
                          "FROM effects ORDER BY slot").fetchall()
        policy = db.execute("SELECT binding,policy_version,generation,tick,credential_active,"
                            "grant_active,ceiling FROM policy WHERE singleton=1").fetchone()
    effects = [dict(slot=s, binding=json.loads(b), digest=d, generation=g, version=v, tick=t)
               for s, b, d, g, v, t in data]
    state = None if policy is None else dict(binding=json.loads(policy[0]), version=policy[1],
                    generation=policy[2], tick=policy[3], credential=policy[4],
                    grant=policy[5], limit=policy[6])
    return {"effects": effects, "policy": state}


def verdict(expected, before, after, responses):
    """Compare the complete effect window to the separately authored casebook."""
    rows = []
    for binding in expected["effects"]:
        encoded = json.dumps(binding, separators=(",", ":"), sort_keys=True).encode("ascii")
        rows.append(dict(binding=binding, slot=binding["slot"], generation=1,
                         version="fixture-policy-v1", tick=12,
                         digest=hashlib.sha256(encoded).hexdigest()))
    ledger_ok = before["effects"] == [] and after["effects"] == rows
    receipt_ok = responses == expected["responses"]
    if not ledger_ok or not receipt_ok:
        return "CONTROL_GAP"
    return "MATCH"

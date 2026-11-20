"""Authored fixture expectations and independent canonicalization for qualification.

This module does not import the engine, its policy, its validators or its ledger.
"""

from __future__ import annotations

import hashlib
import json


def frame(name, data):
    payload = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(b"wolftrap.wolfprint/v1\x00" + name.encode("ascii") + b"\x00" + payload.encode("ascii")).hexdigest()


def architecture(manifest):
    fields = dict(manifest)
    fields.setdefault("protected_config_sha256", "UNKNOWN")
    if isinstance(fields["mcp_tools"], list):
        fields["mcp_tools"] = sorted(fields["mcp_tools"], key=lambda t: (t["server_sha256"], t["tool_sha256"]))
    if isinstance(fields["capabilities"], list):
        fields["capabilities"] = sorted(fields["capabilities"])
    return frame("architecture", fields)


def operation(data):
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


OK = "FIXTURE_ATTESTED"
BAD = "INVALID_OR_EXPIRED_IDENTITY_EVIDENCE"
FAKE = "CLAIMED_IDENTITY_SPOOFING"
ABSENT = "INCONCLUSIVE_IDENTITY"
KNOWN = ("KNOWN_ARCHITECTURE",)
NEW = (*KNOWN, "SAME_PRINCIPAL_NEW_INSTANCE")
CHANGED = ("CHANGED_ARCHITECTURE", "SAME_PRINCIPAL_NEW_INSTANCE")
OTHER = (*KNOWN, "SIMILAR_ARCHITECTURE_OTHER_PRINCIPAL")


def expectation(status=OK, labels=KNOWN, decision="ALLOW", grant=True):
    return status, labels, decision, grant


# Each family is exercised with four independently scoped tenants and delegation depths.
EXPECT = {
    "authorized": expectation(),
    "restart": expectation(labels=NEW),
    "concurrent": expectation(labels=NEW),
    "rotation": expectation(labels=(*NEW, "VERIFIED_KEY_ROTATION")),
    "changed-build-authorized": expectation(labels=CHANGED),
    "changed-schema-authorized": expectation(labels=CHANGED),
    "changed-policy-authorized": expectation(labels=CHANGED),
    "changed-capability-authorized": expectation(labels=CHANGED),
    "changed-without-new-grant": expectation(labels=CHANGED, decision="DENY", grant=False),
    "other-principal-same-build": expectation(labels=OTHER),
    "other-principal-quarantined": expectation(labels=OTHER, decision="QUARANTINE"),
    "other-principal-foreign-restriction": expectation(labels=OTHER),
    "other-principal-no-grant": expectation(labels=OTHER, decision="DENY", grant=False),
    "forged-build": expectation(FAKE, (FAKE,), "REAUTHENTICATE", False),
    "forged-schema": expectation(FAKE, (FAKE,), "REAUTHENTICATE", False),
    "cloned-subject": expectation(FAKE, (FAKE,), "REAUTHENTICATE", False),
    "changed-statement": expectation(FAKE, (FAKE,), "REAUTHENTICATE", False),
    "foreign-delegation": expectation(FAKE, (FAKE,), "REAUTHENTICATE", False),
    "wrong-domain": expectation(BAD, (BAD,), "REAUTHENTICATE", False),
    "wrong-issuer": expectation(BAD, (BAD,), "REAUTHENTICATE", False),
    "wrong-tenant": expectation(BAD, (BAD,), "REAUTHENTICATE", False),
    "wrong-audience": expectation(BAD, (BAD,), "REAUTHENTICATE", False),
    "expired-instance": expectation(BAD, (BAD,), "REAUTHENTICATE", False),
    "not-issued": expectation(BAD, (BAD,), "REAUTHENTICATE", False),
    "retired-key": expectation(BAD, (BAD,), "REAUTHENTICATE", False),
    "revoked-session": expectation(BAD, (BAD,), "REAUTHENTICATE", False),
    "replay": expectation(BAD, (BAD,), "REAUTHENTICATE", False),
    "missing-claim": expectation(ABSENT, (ABSENT,), "REAUTHENTICATE", False),
    "missing-session": expectation(ABSENT, (ABSENT,), "REAUTHENTICATE", False),
    "stale-registry": expectation(ABSENT, (ABSENT,), "REAUTHENTICATE", False),
    "self-declared": expectation(ABSENT, (ABSENT,), "REAUTHENTICATE", False),
    "revoked-grant": expectation(decision="DENY", grant=False),
    "wrong-scope": expectation(decision="DENY", grant=False),
    "wrong-operation": expectation(decision="DENY", grant=False),
    "stale-authority-epoch": expectation(decision="DENY", grant=False),
    "stale-policy-revision": expectation(decision="DENY", grant=False),
    "unattested-component": expectation(decision="REQUIRE_HUMAN_APPROVAL"),
    "unknown-model": expectation(labels=CHANGED, decision="REQUIRE_HUMAN_APPROVAL"),
    "read-only": expectation(decision="READ_ONLY"),
    "reauth-policy": expectation(decision="REAUTHENTICATE"),
    "human-policy": expectation(decision="REQUIRE_HUMAN_APPROVAL"),
    "quarantined": expectation(decision="QUARANTINE"),
    "denied": expectation(decision="DENY"),
    "policy-appeal-lifted": expectation(),
    "legitimate-read": expectation(),
    "future-revocation": expectation(),
    "reordered-manifest": expectation(),
    "benign-lookalike": expectation(),
    "indistinguishable-presentation": expectation(),
}

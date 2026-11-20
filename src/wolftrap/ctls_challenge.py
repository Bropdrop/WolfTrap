"""WT-CTLS-001: strictly offline, fictional licensing-authority challenge.

No interface to Health Canada, CTLS, accounts, real identities or networks.
The roles and two-approval rule below are *hypothetical research policy*, not
statements about Health Canada's actual procedures or implementation.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

SCHEMA = "wolftrap.wt-ctls-001.synthetic-authority/v1"
MANIFEST_SCHEMA = "wolftrap.wt-ctls-001.manifest/v1"
REPORT = "wt-ctls-001.report.json"
INPUTS = "wt-ctls-001.inputs.json"
MARKDOWN = "wt-ctls-001.report.md"
MANIFEST = "wt-ctls-001.manifest.json"
FILES = (INPUTS, REPORT, MARKDOWN)
NAME = re.compile(r"syn-[a-z0-9][a-z0-9-]{0,39}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_TICK = 10000
MAX_CASES = 100
MAX_COMMANDS = 40
MAX_ARTIFACT_BYTES = 3_000_000
ORG_A, ORG_B = "syn-org-a", "syn-org-b"
OWNER_A, OWNER_B = "syn-owner-a", "syn-owner-b"
WITNESS_A, WITNESS_B = "syn-reviewer-a", "syn-reviewer-b"
DEST_A = "syn-new-owner-a"


def canonical(data: Any) -> bytes:
    return (json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                       allow_nan=False) + "\n").encode("ascii")


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def valid_name(value: Any) -> bool:
    return type(value) is str and bool(NAME.fullmatch(value))


def binding_for(prepare: dict[str, Any]) -> str:
    """Digest of immutable request fields; NOT a signature or identity proof."""
    fields = ("org", "tx", "actor", "dest", "nonce", "expires", "epoch")
    return sha(canonical({k: prepare[k] for k in fields}))


FIELDS = {
    "PREPARE": {"op", "at", "org", "tx", "actor", "dest", "nonce", "expires", "epoch"},
    "APPROVE": {"op", "at", "org", "tx", "actor", "binding"},
    "COMMIT": {"op", "at", "org", "tx", "actor", "binding", "lost_reply"},
    "CANCEL": {"op", "at", "org", "tx", "actor"},
    "REVOKE_REVIEWER": {"op", "at", "org", "actor", "target"},
    "ADVANCE_EPOCH": {"op", "at", "org", "actor"},
    "USE": {"op", "at", "org", "actor", "operation_id", "value"},
    "LOSE_STATE": {"op", "at"},
    "RESTORE_STATE": {"op", "at"},
    "RESTART": {"op", "at"},
}
NAMES = {"org", "tx", "actor", "dest", "nonce", "target", "operation_id", "value"}


def validate_command(c: Any) -> None:
    if type(c) is not dict or c.get("op") not in FIELDS or set(c) != FIELDS[c["op"]]:
        raise ValueError("unsupported or incomplete synthetic command")
    if type(c["at"]) is not int or not 0 <= c["at"] <= MAX_TICK:
        raise ValueError("invalid logical time")
    if any(not valid_name(c[k]) for k in NAMES & set(c)):
        raise ValueError("only bounded fictional syn-* aliases are permitted")
    if "binding" in c and (type(c["binding"]) is not str
                            or DIGEST.fullmatch(c["binding"]) is None):
        raise ValueError("invalid synthetic binding digest")
    if "expires" in c and (type(c["expires"]) is not int
                           or not c["at"] < c["expires"] <= MAX_TICK):
        raise ValueError("invalid synthetic expiry")
    if "epoch" in c and (type(c["epoch"]) is not int
                         or not 0 <= c["epoch"] <= MAX_TICK):
        raise ValueError("invalid synthetic epoch")
    if "lost_reply" in c and type(c["lost_reply"]) is not bool:
        raise ValueError("lost_reply must be boolean")


@dataclass
class Outcome:
    code: str
    claimed_effect: dict[str, Any] | None = None


class AuthorityModel:
    """In-memory *fictional* host-authority and durable-checkpoint simulator.

    The 'fault' switch is used solely for offline negative mutation controls.
    Audit and effect records are separate observers; zero external side effects.
    """

    def __init__(self, *, effect_sink: Callable[[dict[str, Any]], None] | None = None,
                 fault: str | None = None):
        self.owners = {ORG_A: OWNER_A, ORG_B: OWNER_B}
        self.reviewers = {ORG_A: [WITNESS_A], ORG_B: [WITNESS_B]}
        self.epochs = {ORG_A: 1, ORG_B: 1}
        self.requests: dict[str, dict[str, Any]] = {}
        self.nonces: set[str] = set()
        self.operations: dict[str, dict[str, Any]] = {}
        self.effects: list[dict[str, Any]] = []
        self.audit: list[dict[str, Any]] = []
        self.known = True
        self.at = 0
        self.effect_sink = effect_sink
        self.fault = fault

    @staticmethod
    def _key(org: str, identifier: str) -> str:
        return org + ":" + identifier

    def _owner(self, org: str, actor: str) -> bool:
        return self.owners.get(org) == actor

    def _audit(self, command: dict[str, Any], code: str,
               effect: dict[str, Any] | None) -> None:
        previous = self.audit[-1]["hash"] if self.audit else sha(b"WT-CTLS-001:GENESIS")
        entry = {"sequence": len(self.audit) + 1, "previous": previous,
                 "command_digest": sha(canonical(command)), "decision": code,
                 "effect_digest": sha(canonical(effect)) if effect is not None else None}
        entry["hash"] = sha(canonical(entry))
        self.audit.append(entry)

    def _emit(self, effect: dict[str, Any]) -> dict[str, Any]:
        copied = copy.deepcopy(effect)
        if self.fault != "FAKE_SUCCESS":
            self.effects.append(copied)
            if self.effect_sink is not None:
                self.effect_sink(copy.deepcopy(copied))
        return copied

    def step(self, c: dict[str, Any]) -> Outcome:
        validate_command(c)
        if c["at"] < self.at:
            raise ValueError("out-of-order synthetic clock")
        self.at = c["at"]
        op = c["op"]
        result = Outcome("DENIED")
        if self.fault == "DENY_ALL" and op not in {"RESTART", "LOSE_STATE", "RESTORE_STATE"}:
            result = Outcome("DENIED")
        elif op == "RESTART":
            restored = self.from_checkpoint(self.checkpoint(), effect_sink=self.effect_sink,
                                            fault=self.fault)
            self.__dict__.update(restored.__dict__)
            result = Outcome("RESTARTED")
        elif op == "LOSE_STATE":
            self.known = False
            result = Outcome("STATE_UNKNOWN")
        elif op == "RESTORE_STATE":
            self.known = True
            result = Outcome("STATE_KNOWN")
        elif not self.known:
            result = Outcome("UNKNOWN_SECURITY_STATE")
        elif op == "PREPARE":
            result = self._prepare(c)
        elif op == "APPROVE":
            result = self._approve(c)
        elif op == "COMMIT":
            result = self._commit(c)
        elif op == "CANCEL":
            result = self._cancel(c)
        elif op == "REVOKE_REVIEWER":
            result = self._revoke_reviewer(c)
        elif op == "ADVANCE_EPOCH":
            result = self._advance_epoch(c)
        elif op == "USE":
            result = self._use(c)
        self._audit(c, result.code, result.claimed_effect)
        return result

    def _prepare(self, c: dict[str, Any]) -> Outcome:
        key = self._key(c["org"], c["tx"])
        binding = binding_for(c)
        old = self.requests.get(key)
        if old:
            if old["state"] == "CLOSED":
                return Outcome("CLOSED")
            if old["binding"] != binding:
                return Outcome("CONFLICTING_TX")
            return Outcome("ALREADY_COMMITTED" if old["state"] == "COMMITTED"
                           else "ALREADY_PREPARED")
        if not self._owner(c["org"], c["actor"]):
            return Outcome("NOT_OWNER")
        if c["epoch"] != self.epochs[c["org"]]:
            return Outcome("STALE_EPOCH")
        if c["dest"] == c["actor"]:
            return Outcome("SAME_OWNER")
        nonce_key = self._key(c["org"], c["nonce"])
        if nonce_key in self.nonces:
            return Outcome("NONCE_REUSED")
        self.nonces.add(nonce_key)
        self.requests[key] = {"binding": binding, "org": c["org"], "tx": c["tx"],
                              "source": c["actor"], "dest": c["dest"],
                              "expires": c["expires"], "epoch": c["epoch"],
                              "state": "PREPARED", "reviewer": None}
        return Outcome("PREPARED")

    def _lookup(self, c: dict[str, Any]) -> dict[str, Any] | None:
        return self.requests.get(self._key(c["org"], c["tx"]))

    def _active_request(self, c: dict[str, Any], req: dict[str, Any]) -> str | None:
        if req["state"] == "CLOSED":
            return "CLOSED"
        if req["state"] == "COMMITTED":
            return "ALREADY_COMMITTED"
        if c["at"] >= req["expires"]:
            return "EXPIRED"
        if self.fault != "ALLOW_STALE" and req["epoch"] != self.epochs[c["org"]]:
            return "STALE_EPOCH"
        if not self._owner(c["org"], req["source"]):
            return "SOURCE_REVOKED"
        if c["binding"] != req["binding"] and self.fault != "IGNORE_BINDING":
            return "BINDING_MISMATCH"
        return None

    def _approve(self, c: dict[str, Any]) -> Outcome:
        req = self._lookup(c)
        if req is None:
            return Outcome("UNKNOWN_TX")
        inactive = self._active_request(c, req)
        if inactive:
            return Outcome(inactive)
        if c["actor"] in {req["source"], req["dest"]}:
            return Outcome("SEPARATION_OF_DUTIES")
        if c["actor"] not in self.reviewers[c["org"]]:
            return Outcome("WITNESS_REQUIRED")
        if req["reviewer"] == c["actor"]:
            return Outcome("ALREADY_APPROVED")
        if req["reviewer"] is not None:
            return Outcome("ALREADY_APPROVED")
        req["reviewer"] = c["actor"]
        return Outcome("APPROVED")

    def _commit(self, c: dict[str, Any]) -> Outcome:
        req = self._lookup(c)
        if req is None:
            return Outcome("UNKNOWN_TX")
        if req["state"] == "COMMITTED":
            if c["actor"] == req["source"] and c["binding"] == req["binding"]:
                return Outcome("ALREADY_COMMITTED")
            return Outcome("CONFLICTING_REPLAY")
        inactive = self._active_request(c, req)
        if inactive:
            return Outcome(inactive)
        if c["actor"] != req["source"]:
            return Outcome("NOT_OWNER")
        if req["reviewer"] is None and self.fault != "NO_WITNESS":
            return Outcome("MISSING_WITNESS")
        if (req["reviewer"] not in self.reviewers[c["org"]]
                and self.fault != "NO_WITNESS"):
            return Outcome("WITNESS_REVOKED")
        old = self.owners[c["org"]]
        self.owners[c["org"]] = req["dest"]
        self.epochs[c["org"]] += 1
        req["state"] = "COMMITTED"
        effect = self._emit({"kind": "TRANSFER", "org": c["org"],
                             "tx": c["tx"], "from": old, "to": req["dest"]})
        return Outcome("ACK_LOST" if c["lost_reply"] else "COMMITTED", effect)

    def _cancel(self, c: dict[str, Any]) -> Outcome:
        req = self._lookup(c)
        if req is None:
            return Outcome("UNKNOWN_TX")
        if req["state"] == "COMMITTED":
            return Outcome("ALREADY_COMMITTED")
        if req["state"] == "CLOSED":
            return Outcome("CLOSED")
        if not self._owner(c["org"], c["actor"]):
            return Outcome("NOT_OWNER")
        req["state"] = "CLOSED"
        return Outcome("CLOSED")

    def _revoke_reviewer(self, c: dict[str, Any]) -> Outcome:
        if not self._owner(c["org"], c["actor"]):
            return Outcome("NOT_OWNER")
        if c["target"] not in self.reviewers[c["org"]]:
            return Outcome("UNKNOWN_REVIEWER")
        self.reviewers[c["org"]].remove(c["target"])
        self.epochs[c["org"]] += 1
        return Outcome("REVIEWER_REVOKED")

    def _advance_epoch(self, c: dict[str, Any]) -> Outcome:
        if not self._owner(c["org"], c["actor"]):
            return Outcome("NOT_OWNER")
        self.epochs[c["org"]] += 1
        return Outcome("EPOCH_ADVANCED")

    def _use(self, c: dict[str, Any]) -> Outcome:
        key = self._key(c["org"], c["operation_id"])
        # Authorize *before* looking up idempotency keys; otherwise outsiders
        # could learn whether a protected operation ID already exists.
        if not self._owner(c["org"], c["actor"]) and not (
                self.fault == "ALLOW_OLD_OWNER" and c["actor"] == OWNER_A):
            return Outcome("NOT_OWNER")
        old = self.operations.get(key)
        if old:
            if old == {"actor": c["actor"], "value": c["value"]}:
                return Outcome("ALREADY_APPLIED")
            return Outcome("CONFLICTING_OP")
        self.operations[key] = {"actor": c["actor"], "value": c["value"]}
        effect = self._emit({"kind": "PROFILE_WRITE", "org": c["org"],
                             "actor": c["actor"], "operation_id": c["operation_id"],
                             "value": c["value"]})
        return Outcome("APPLIED", effect)

    def checkpoint(self) -> bytes:
        state = {"owners": self.owners, "reviewers": self.reviewers, "epochs": self.epochs,
                 "requests": self.requests, "nonces": sorted(self.nonces),
                 "operations": self.operations, "effects": self.effects,
                 "audit": self.audit, "known": self.known, "at": self.at}
        return canonical({"schema": SCHEMA + "/checkpoint", "state": state,
                          "state_digest": sha(canonical(state))})

    @classmethod
    def from_checkpoint(cls, raw: bytes, *,
                        effect_sink: Callable[[dict[str, Any]], None] | None = None,
                        fault: str | None = None) -> AuthorityModel:
        if len(raw) > MAX_ARTIFACT_BYTES:
            raise ValueError("checkpoint too large")
        try:
            doc = json.loads(raw)
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("invalid checkpoint") from exc
        if type(doc) is not dict or set(doc) != {"schema", "state", "state_digest"}:
            raise ValueError("unrecognized checkpoint")
        if doc["schema"] != SCHEMA + "/checkpoint" or doc["state_digest"] != sha(canonical(doc["state"])):
            raise ValueError("checkpoint integrity failure")
        state = doc["state"]
        required = {"owners", "reviewers", "epochs", "requests", "nonces", "operations",
                    "effects", "audit", "known", "at"}
        if type(state) is not dict or set(state) != required:
            raise ValueError("checkpoint missing state")
        model = cls(effect_sink=effect_sink, fault=fault)
        for key in required - {"nonces"}:
            setattr(model, key, copy.deepcopy(state[key]))
        model.nonces = set(state["nonces"])
        model.verify_audit()
        return model

    def verify_audit(self) -> None:
        previous = sha(b"WT-CTLS-001:GENESIS")
        witnessed = []
        for idx, entry in enumerate(self.audit):
            if type(entry) is not dict or set(entry) != {
                    "sequence", "previous", "command_digest", "decision", "effect_digest", "hash"}:
                raise ValueError("audit entry schema violation")
            body = {k: v for k, v in entry.items() if k != "hash"}
            if (entry["sequence"] != idx + 1 or entry["previous"] != previous
                    or entry["hash"] != sha(canonical(body))):
                raise ValueError("audit chain mismatch")
            previous = entry["hash"]
            if entry["effect_digest"] is not None:
                witnessed.append(entry["effect_digest"])
        if witnessed != [sha(canonical(effect)) for effect in self.effects]:
            raise ValueError("effect ledger and audit diverge")


def P(*, at: int = 1, org: str = ORG_A, actor: str = OWNER_A, tx: str = "syn-tx-1",
      dest: str = DEST_A, nonce: str = "syn-nonce-1", expires: int = 20,
      epoch: int = 1) -> dict[str, Any]:
    return dict(op="PREPARE", at=at, org=org, actor=actor, tx=tx,
                dest=dest, nonce=nonce, expires=expires, epoch=epoch)


def A(p: dict[str, Any], *, at: int = 2, actor: str = WITNESS_A,
      binding: str | None = None, org: str | None = None,
      tx: str | None = None) -> dict[str, Any]:
    return dict(op="APPROVE", at=at, org=org or p["org"], tx=tx or p["tx"],
                actor=actor, binding=binding or binding_for(p))


def C(p: dict[str, Any], *, at: int = 3, actor: str | None = None,
      binding: str | None = None, lost_reply: bool = False,
      org: str | None = None, tx: str | None = None) -> dict[str, Any]:
    return dict(op="COMMIT", at=at, org=org or p["org"], tx=tx or p["tx"],
                actor=actor or p["actor"], binding=binding or binding_for(p),
                lost_reply=lost_reply)


def U(*, at: int = 4, org: str = ORG_A, actor: str = DEST_A,
      operation_id: str = "syn-use-1", value: str = "syn-value-1") -> dict[str, Any]:
    return dict(op="USE", at=at, org=org, actor=actor,
                operation_id=operation_id, value=value)


def X(op: str, at: int, **values: Any) -> dict[str, Any]:
    return dict(op=op, at=at, **values)


def T(p: dict[str, Any]) -> dict[str, Any]:
    return dict(kind="TRANSFER", org=p["org"], tx=p["tx"],
                **{"from": p["actor"], "to": p["dest"]})


def W(c: dict[str, Any]) -> dict[str, Any]:
    return dict(kind="PROFILE_WRITE", org=c["org"], actor=c["actor"],
                operation_id=c["operation_id"], value=c["value"])


def case(name: str, commands: list[dict[str, Any]], codes: str,
         effects: list[dict[str, Any]] | None = None,
         owner_a: str = OWNER_A, owner_b: str = OWNER_B) -> dict[str, Any]:
    expected_codes = codes.split()
    if len(commands) != len(expected_codes):
        raise ValueError("authored control has inconsistent command count")
    return {"case_id": name, "commands": commands, "expected_codes": expected_codes,
            "expected_effects": effects or [],
            "expected_owners": {ORG_A: owner_a, ORG_B: owner_b}}


def corpus() -> list[dict[str, Any]]:
    """Independent authored verdicts; the model does NOT calculate expected labels."""
    p = P()
    p2 = P(at=2, tx="syn-tx-2", nonce="syn-nonce-2", dest="syn-another-owner")
    beta = P(org=ORG_B, actor=OWNER_B, dest="syn-new-owner-b")
    wrong = sha(b"fictional wrong binding")
    return [
        case("positive-transfer-and-fenced-prior-owner", [p, A(p), C(p), U(), U(at=5, actor=OWNER_A)],
             "PREPARED APPROVED COMMITTED APPLIED NOT_OWNER", [T(p), W(U())], DEST_A),
        case("unauthorized-prepare", [P(actor="syn-outsider")], "NOT_OWNER"),
        case("cross-tenant-owner", [P(actor=OWNER_B)], "NOT_OWNER"),
        case("missing-witness", [p, C(p, at=2)], "PREPARED MISSING_WITNESS"),
        case("owner-self-approval", [p, A(p, actor=OWNER_A), C(p)],
             "PREPARED SEPARATION_OF_DUTIES MISSING_WITNESS"),
        case("destination-self-approval", [p, A(p, actor=DEST_A)],
             "PREPARED SEPARATION_OF_DUTIES"),
        case("untrusted-reviewer", [p, A(p, actor="syn-outsider")],
             "PREPARED WITNESS_REQUIRED"),
        case("duplicate-reviewer-approval", [p, A(p), A(p, at=3)],
             "PREPARED APPROVED ALREADY_APPROVED"),
        case("idempotent-commit", [p, A(p), C(p), C(p, at=4)],
             "PREPARED APPROVED COMMITTED ALREADY_COMMITTED", [T(p)], DEST_A),
        case("lost-acknowledgment-no-reapply", [p, A(p), C(p, lost_reply=True), C(p, at=4)],
             "PREPARED APPROVED ACK_LOST ALREADY_COMMITTED", [T(p)], DEST_A),
        case("duplicate-prepare-same-binding", [p, P(at=2)],
             "PREPARED ALREADY_PREPARED"),
        case("concurrent-transfer-one-winner", [p, p2, A(p, at=3), A(p2, at=4),
                                                 C(p, at=5), C(p2, at=6)],
             "PREPARED PREPARED APPROVED APPROVED COMMITTED STALE_EPOCH", [T(p)], DEST_A),
        case("revocation-before-approval", [p, X("REVOKE_REVIEWER", 2, org=ORG_A,
             actor=OWNER_A, target=WITNESS_A), A(p, at=3)],
             "PREPARED REVIEWER_REVOKED STALE_EPOCH"),
        case("revocation-between-approve-and-commit", [p, A(p), X("REVOKE_REVIEWER", 3,
             org=ORG_A, actor=OWNER_A, target=WITNESS_A), C(p, at=4)],
             "PREPARED APPROVED REVIEWER_REVOKED STALE_EPOCH"),
        case("epoch-advance-between-prepare-and-commit", [p, A(p), X("ADVANCE_EPOCH", 3,
             org=ORG_A, actor=OWNER_A), C(p, at=4)],
             "PREPARED APPROVED EPOCH_ADVANCED STALE_EPOCH"),
        case("expiry-at-exact-boundary", [P(expires=3), A(P(expires=3)), C(P(expires=3), at=3)],
             "PREPARED APPROVED EXPIRED"),
        case("cancel-and-late-commit", [p, A(p), X("CANCEL", 3, org=ORG_A,
             tx=p["tx"], actor=OWNER_A), C(p, at=4)],
             "PREPARED APPROVED CLOSED CLOSED"),
        case("cancel-restart-tombstone", [p, X("CANCEL", 2, org=ORG_A,
             tx=p["tx"], actor=OWNER_A), X("RESTART", 3), P(at=4)],
             "PREPARED CLOSED RESTARTED CLOSED"),
        case("unknown-security-state-fails-closed", [p, A(p), X("LOSE_STATE", 3),
             C(p, at=4), X("RESTORE_STATE", 5), C(p, at=6)],
             "PREPARED APPROVED STATE_UNKNOWN UNKNOWN_SECURITY_STATE STATE_KNOWN COMMITTED",
             [T(p)], DEST_A),
        case("restart-between-approval-and-commit", [p, A(p), X("RESTART", 3), C(p, at=4)],
             "PREPARED APPROVED RESTARTED COMMITTED", [T(p)], DEST_A),
        case("replay-commit-after-restart", [p, A(p), C(p), X("RESTART", 4), C(p, at=5)],
             "PREPARED APPROVED COMMITTED RESTARTED ALREADY_COMMITTED", [T(p)], DEST_A),
        case("cross-tenant-reviewer", [p, A(p, actor=WITNESS_B)],
             "PREPARED WITNESS_REQUIRED"),
        case("approval-digest-substitution", [p, A(p, binding=wrong)],
             "PREPARED BINDING_MISMATCH"),
        case("commit-digest-substitution", [p, A(p), C(p, binding=wrong)],
             "PREPARED APPROVED BINDING_MISMATCH"),
        case("copy-valid-approval-to-other-tx", [p, p2, A(p2, at=3, binding=binding_for(p))],
             "PREPARED PREPARED BINDING_MISMATCH"),
        case("nonce-reuse-distinct-transfer", [p, P(at=2, tx="syn-tx-3")],
             "PREPARED NONCE_REUSED"),
        case("request-id-conflict", [p, P(at=2, dest="syn-false-destination")],
             "PREPARED CONFLICTING_TX"),
        case("duplicate-protected-write", [U(at=1, actor=OWNER_A),
             U(at=2, actor=OWNER_A)], "APPLIED ALREADY_APPLIED",
             [W(U(at=1, actor=OWNER_A))]),
        case("conflicting-operation-replay", [U(at=1, actor=OWNER_A),
             U(at=2, actor=OWNER_A, value="syn-altered-value")],
             "APPLIED CONFLICTING_OP", [W(U(at=1, actor=OWNER_A))]),
        case("outsider-cannot-apply", [U(at=1, actor="syn-outsider")], "NOT_OWNER"),
        case("source-cannot-apply-after-transfer", [p, A(p), C(p), U(actor=OWNER_A)],
             "PREPARED APPROVED COMMITTED NOT_OWNER", [T(p)], DEST_A),
        case("other-tenant-unaffected", [p, A(p), C(p),
             U(org=ORG_B, actor=OWNER_B, at=4, operation_id="syn-beta-use")],
             "PREPARED APPROVED COMMITTED APPLIED",
             [T(p), W(U(org=ORG_B, actor=OWNER_B, at=4,
                         operation_id="syn-beta-use"))], DEST_A),
        case("restart-before-witness", [p, X("RESTART", 2), C(p, at=3), A(p, at=4),
             C(p, at=5)], "PREPARED RESTARTED MISSING_WITNESS APPROVED COMMITTED",
             [T(p)], DEST_A),
        case("revoked-approval-cannot-be-revived", [p, A(p),
             X("REVOKE_REVIEWER", 3, org=ORG_A, actor=OWNER_A, target=WITNESS_A),
             X("RESTART", 4), C(p, at=5)],
             "PREPARED APPROVED REVIEWER_REVOKED RESTARTED STALE_EPOCH"),
        case("unauthorized-revocation", [p, X("REVOKE_REVIEWER", 2, org=ORG_A,
             actor="syn-outsider", target=WITNESS_A), A(p, at=3), C(p, at=4)],
             "PREPARED NOT_OWNER APPROVED COMMITTED", [T(p)], DEST_A),
        case("cross-tenant-commit-attempt", [p, A(p), C(p, actor=OWNER_B), C(p, at=4)],
             "PREPARED APPROVED NOT_OWNER COMMITTED", [T(p)], DEST_A),
        case("alternate-tenant-positive-control", [beta, A(beta, actor=WITNESS_B), C(beta)],
             "PREPARED APPROVED COMMITTED", [T(beta)], OWNER_A, "syn-new-owner-b"),
    ]


def validate_corpus(cases: list[dict[str, Any]]) -> None:
    if not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("invalid case bound")
    ids = set()
    for item in cases:
        if type(item) is not dict or set(item) != {"case_id", "commands", "expected_codes",
                                                  "expected_effects", "expected_owners"}:
            raise ValueError("unexpected case fields")
        if not valid_name("syn-" + item["case_id"]):
            # Case names are labels rather than external identifiers.
            if not re.fullmatch(r"[a-z][a-z0-9-]{1,80}", item["case_id"]):
                raise ValueError("invalid case id")
        if item["case_id"] in ids:
            raise ValueError("duplicate case id")
        ids.add(item["case_id"])
        if not 1 <= len(item["commands"]) <= MAX_COMMANDS:
            raise ValueError("invalid command count")
        if len(item["commands"]) != len(item["expected_codes"]):
            raise ValueError("expected labels do not match commands")
        prev = -1
        for command in item["commands"]:
            validate_command(command)
            if command["at"] < prev:
                raise ValueError("unordered case time")
            prev = command["at"]
        if item["expected_owners"].keys() != {ORG_A, ORG_B}:
            raise ValueError("expected owner roster incomplete")


def execute_case(item: dict[str, Any], *, fault: str | None = None) -> dict[str, Any]:
    sink: list[dict[str, Any]] = []
    model = AuthorityModel(effect_sink=sink.append, fault=fault)
    answers = []
    claims = []
    for command in item["commands"]:
        output = model.step(command)
        answers.append(output.code)
        if output.claimed_effect is not None:
            claims.append(output.claimed_effect)
    try:
        model.verify_audit()
        audit_valid = True
    except ValueError:
        audit_valid = False
    return {"case_id": item["case_id"], "input_sha256": sha(canonical(item)),
            "expected_decisions": item["expected_codes"], "observed_decisions": answers,
            "expected_effects": item["expected_effects"], "observed_effects": sink,
            "claimed_effects": claims, "expected_owners": item["expected_owners"],
            "observed_owners": model.owners, "audit_valid": audit_valid,
            "audit_head": model.audit[-1]["hash"] if model.audit else None,
            "checkpoint_sha256": sha(model.checkpoint()),
            "passed": (answers == item["expected_codes"]
                       and sink == item["expected_effects"] and claims == sink
                       and model.owners == item["expected_owners"]
                       and model.effects == sink and audit_valid)}


SENTINELS = {
    "DENY_ALL": "positive-transfer-and-fenced-prior-owner",
    "NO_WITNESS": "missing-witness",
    "ALLOW_STALE": "epoch-advance-between-prepare-and-commit",
    "ALLOW_OLD_OWNER": "source-cannot-apply-after-transfer",
    "FAKE_SUCCESS": "positive-transfer-and-fenced-prior-owner",
    "IGNORE_BINDING": "approval-digest-substitution",
}


def evaluate() -> tuple[dict[str, Any], dict[str, Any]]:
    cases = corpus()
    validate_corpus(cases)
    rows = [execute_case(item) for item in cases]
    lookup = {item["case_id"]: item for item in cases}
    sentinels = [{"fault": fault, "control": control,
                  "detected": not execute_case(lookup[control], fault=fault)["passed"]}
                 for fault, control in SENTINELS.items()]
    successful = all(item["passed"] for item in rows) and all(
        sentinel["detected"] for sentinel in sentinels)
    inputs = {"schema": SCHEMA + "/inputs", "cases": cases,
              "fixture_source": "fictional synthetic identifiers only"}
    report = {"schema": SCHEMA, "case_class": "SYNTHETICALLY VERIFIED" if successful
              else "INCONCLUSIVE", "live_target": "NOT TESTED",
              "system": "fictional offline authority simulator; no CTLS access",
              "policy": "hypothetical two-role authorization (not claimed to be HC policy)",
              "source_module_sha256": sha(Path(__file__).read_bytes()),
              "summary": {"cases": len(cases), "passed": sum(r["passed"] for r in rows),
                          "failed": sum(not r["passed"] for r in rows),
                          "sentinels": len(sentinels),
                          "sentinels_detected": sum(s["detected"] for s in sentinels)},
              "results": rows, "mutation_controls": sentinels}
    return inputs, report


def markdown(report: dict[str, Any]) -> bytes:
    s = report["summary"]
    lines = ["# WT-CTLS-001 — fictional authority transfer and revocation",
             "", "**No Health Canada or CTLS systems were contacted.**",
             "", "**Live CTLS conformance:** NOT TESTED.",
             "", f"**Synthetic qualification:** {report['case_class']}",
             "", f"Cases: {s['passed']}/{s['cases']} passing; "
             f"mutation controls: {s['sentinels_detected']}/{s['sentinels']} detected.",
             "", "| Case | Authored decision oracle | Result |", "| --- | --- | --- |"]
    for item in report["results"]:
        lines.append(f"| {item['case_id']} | {' / '.join(item['expected_decisions'])} "
                     f"| {'PASS' if item['passed'] else 'FAIL'} |")
    lines += ["", "## Mutation controls", ""]
    for control in report["mutation_controls"]:
        lines.append(f"- {control['fault']}: {'DETECTED' if control['detected'] else 'MISSED'} "
                     f"by {control['control']}")
    lines += ["", "## Boundaries", "",
              "- This is a fictional policy model, not a reproduction of Health Canada procedures.",
              "- All actors, organizations, operations and payloads use synthetic aliases.",
              "- Logical schedules simulate concurrency and crash recovery; no real threads or databases.",
              "- A SHA-256 hash chain and manifest detect accidental alteration, not a trusted signature.",
              "- The model's `RESTART` reloads a checkpoint in process; not a durability benchmark.",
              "- There is no network access, authentication, cryptographic identity proof or live CTLS test.",
              ""]
    return ("\n".join(lines)).encode("utf-8")


def _write_new(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def run(output_dir: Path) -> tuple[dict[str, Any], int]:
    if output_dir.exists() or output_dir.is_symlink():
        raise ValueError("output directory must be new and unused")
    inputs, report = evaluate()
    payloads = {INPUTS: canonical(inputs), REPORT: canonical(report),
                MARKDOWN: markdown(report)}
    if any(len(data) > MAX_ARTIFACT_BYTES for data in payloads.values()):
        raise ValueError("evidence artifact exceeds bound")
    output_dir.mkdir(parents=False, exist_ok=False)
    for name, data in payloads.items():
        _write_new(output_dir / name, data)
    manifest = {"schema": MANIFEST_SCHEMA, "state": "COMPLETE",
                "files": {name: {"bytes": len(data), "sha256": sha(data)}
                          for name, data in sorted(payloads.items())}}
    _write_new(output_dir / MANIFEST, canonical(manifest))
    return report, 0 if report["case_class"] == "SYNTHETICALLY VERIFIED" else 1


def verify(evidence_dir: Path) -> dict[str, Any]:
    if evidence_dir.is_symlink() or not evidence_dir.is_dir():
        raise ValueError("evidence directory missing or linked")
    if {p.name for p in evidence_dir.iterdir()} != set(FILES) | {MANIFEST}:
        raise ValueError("missing or extra evidence file")
    payloads: dict[str, bytes] = {}
    for name in (*FILES, MANIFEST):
        path = evidence_dir / name
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARTIFACT_BYTES:
            raise ValueError("unsafe or oversized evidence file")
        payloads[name] = path.read_bytes()
    try:
        manifest = json.loads(payloads[MANIFEST])
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("invalid evidence manifest") from exc
    if manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("state") != "COMPLETE":
        raise ValueError("incomplete or unknown evidence")
    if set(manifest) != {"schema", "state", "files"} or set(manifest["files"]) != set(FILES):
        raise ValueError("manifest missing required artifact")
    for name in FILES:
        actual = {"bytes": len(payloads[name]), "sha256": sha(payloads[name])}
        if manifest["files"][name] != actual:
            raise ValueError("evidence digest or length mismatch")
    original_inputs, original_report = evaluate()
    expected = {INPUTS: canonical(original_inputs), REPORT: canonical(original_report),
                MARKDOWN: markdown(original_report)}
    if any(payloads[name] != expected[name] for name in FILES):
        raise ValueError("evidence does not match deterministic replay")
    return original_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="WT-CTLS-001: offline synthetic authority challenge")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("run").add_argument("--output-dir", type=Path, required=True)
    sub.add_parser("verify").add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            result, code = run(args.output_dir)
        else:
            result, code = verify(args.evidence_dir), 0
        s = result["summary"]
        print(f"{result['case_class']}: {s['passed']}/{s['cases']} synthetic cases; "
              f"{s['sentinels_detected']}/{s['sentinels']} mutations detected")
        return code
    except (ValueError, OSError, TypeError, KeyError) as exc:
        print(f"INCONCLUSIVE: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

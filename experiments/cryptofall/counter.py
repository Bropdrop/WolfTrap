"""Disposable SQLite counter and a separate, in-memory checkpoint model."""

import sqlite3
from contextlib import closing, contextmanager
from threading import Lock

from verifier import (MAX_LIFETIME, REALM, current_key, digest, endorsements, evaluate, key_id,
                      natural, parse, policy, require, shape, slots, unhex, wire)


def increment_id(request, instance):
    operation = parse(request)
    shape(operation, "action instance request_id")
    require(operation["action"] == "increment" and operation["instance"] == instance, "disposable-operation")
    unhex(operation["request_id"], 16)
    return operation["request_id"]


class Checkpoint:
    """Trusted model. Keep this object outside the local database restore domain."""

    def __init__(self, genesis, genesis_pin, recovery, witness, instance, clock):
        document = policy(parse(genesis))
        require(digest(genesis) == genesis_pin and document["epoch"] == 0
                and document["predecessor"] == "0" * 64, "genesis-pin")
        self.roots = parse(wire({"recovery-test": recovery, "policy-witness-test": witness}))
        self._disjoint(document)
        require(all(key["algorithm"] == "ml-dsa-65-v1" for key in self.roots.values()), "recovery-algorithm")
        self.policy = genesis
        self.instance = instance
        self.clock = clock
        self.last_time = 0
        self.sequence = 0
        self.available = True
        self.lock = Lock()
        self._disposable_permits = set()

    def _disjoint(self, document):
        keys = [*slots(document).values(), *self.roots.values()]
        require(len({key_id(key) for key in keys}) == len(keys), "shared-trust-key")

    def fresh(self):
        now = self.clock()
        require(self.available and natural(now) and now >= self.last_time, "checkpoint-unavailable-or-stale")
        self.last_time = now
        return now

    def set_disposable_permit(self, request, *, enabled):
        """Trusted fixture provisioning. Verification and signed transitions cannot issue permits."""
        with self.lock:
            self.fresh()
            increment_id(request, self.instance)
            require(type(enabled) is bool, "disposable-permit")
            binding = (digest(self.policy), request)
            if enabled:
                self._disposable_permits.add(binding)
            else:
                self._disposable_permits.discard(binding)

    def check_disposable_permit(self, policy_digest, request):
        # The writer holds the checkpoint lock through SQLite commit.
        require((policy_digest, request) in self._disposable_permits, "disposable-permit")

    def transition(self, raw):
        with self.lock:
            now = self.fresh()
            envelope = parse(raw)
            shape(envelope, "transition signatures")
            body = envelope["transition"]
            shape(body, "action instance realm issued expires next")
            require(body["realm"] == REALM and body["instance"] == self.instance, "transition-scope")
            issued, expires = body["issued"], body["expires"]
            require(natural(issued) and natural(expires) and issued <= now < expires
                    and expires - issued <= MAX_LIFETIME, "transition-time")
            old, new = parse(self.policy), policy(body["next"])
            self._disjoint(new)
            require(new["epoch"] == old["epoch"] + 1 and new["predecessor"] == digest(self.policy),
                    "policy-predecessor")
            for field in ("revoked_keys", "revoked_algorithms"):
                require(set(old[field]) <= set(new[field]), "revocation-regression")
            prior = slots(old)
            for slot, key in slots(new).items():
                # Revoking a pinned key in place is permitted. A removed
                # revoked key cannot be assigned to a slot in a later policy.
                require(key_id(key) not in new["revoked_keys"] or prior.get(slot) == key, "reintroduced-key")
            action = body["action"]
            require(new["profile"] == old["profile"] or action == "recover", "profile-transition")
            if action == "rotate":
                require(old["mode"] == new["mode"] == "active", "quarantine")
                keys = {slot: current_key(old, key) for slot, key in slots(old, ("owner-test",)).items()}
            else:
                allowed = (action == "emergency-quarantine" and new["mode"] == "quarantine"
                           or action == "recover" and old["mode"] == "quarantine" and new["mode"] == "active")
                require(allowed, "transition-action")
                recovery = current_key(old, self.roots["recovery-test"])
                keys = {("recovery-test", recovery["algorithm"]): recovery}
                if action == "recover":
                    for key in slots(new).values():
                        current_key(new, key)
            witness = current_key(old, self.roots["policy-witness-test"])
            keys[("policy-witness-test", witness["algorithm"])] = witness
            endorsements("transition", body, envelope["signatures"], keys)
            require(self.fresh() < expires, "transition-time")
            self.policy = wire(new)


class Counter:
    def __init__(self, path, checkpoint):
        self.path = path
        self.checkpoint = checkpoint

    def initialize(self):
        anchor = self.checkpoint
        with anchor.lock, closing(sqlite3.connect(self.path)) as db, db:
            anchor.fresh()
            require(anchor.sequence == 0, "checkpoint-already-used")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE state (instance TEXT NOT NULL, epoch INTEGER NOT NULL, "
                       "value INTEGER NOT NULL)")
            db.execute("INSERT INTO state VALUES (?, 0, 0)", (anchor.instance,))
            db.execute("CREATE TABLE receipts (nonce TEXT PRIMARY KEY, authorization BLOB NOT NULL, "
                       "request BLOB NOT NULL, value INTEGER NOT NULL)")

    @contextmanager
    def _locked_state(self):
        anchor = self.checkpoint
        with anchor.lock, closing(sqlite3.connect(self.path)) as db:
            db.execute("BEGIN IMMEDIATE")
            anchor.fresh()
            (state,) = db.execute("SELECT instance, epoch, value FROM state").fetchall()
            instance, epoch, value = state
            current = parse(anchor.policy)
            require(instance == anchor.instance and value == anchor.sequence
                    and epoch == current["epoch"], "checkpoint-state-mismatch")
            yield db, current, value

    def synchronize(self):
        """Apply a trusted policy advance to local metadata. Never restore effect state."""
        anchor = self.checkpoint
        with anchor.lock, closing(sqlite3.connect(self.path)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            anchor.fresh()
            (state,) = db.execute("SELECT instance, epoch, value FROM state").fetchall()
            instance, epoch, value = state
            epoch_now = parse(anchor.policy)["epoch"]
            require(instance == anchor.instance and value == anchor.sequence
                    and epoch <= epoch_now, "checkpoint-state-mismatch")
            db.execute("UPDATE state SET epoch = ?", (epoch_now,))

    def apply(self, request, authorization):
        anchor = self.checkpoint
        request_id = increment_id(request, anchor.instance)
        with self._locked_state() as (db, current, value):
            nonce, expires = evaluate(authorization, request, current, anchor.fresh(), expected_request_id=request_id)
            anchor.check_disposable_permit(digest(wire(current)), request)
            require(db.execute("SELECT 1 FROM receipts WHERE nonce = ?", (nonce,)).fetchone()
                    is None, "authorization-used")
            db.execute("INSERT INTO receipts VALUES (?, ?, ?, ?)", (nonce, authorization, request, value + 1))
            db.execute("UPDATE state SET value = ?", (value + 1,))
            # Reserve at the independent checkpoint before committing. An ambiguous
            # failure freezes on a mismatch. Never rewind the checkpoint to retry.
            require(anchor.fresh() < expires, "claim-time")
            anchor.sequence = value + 1
            db.commit()
            return value + 1

    def receipt(self, nonce, request, authorization):
        """An exact retry is a read, even after revocation or claim expiration."""
        with self._locked_state() as (db, _, _value):
            row = db.execute("SELECT authorization, request, value FROM receipts WHERE nonce = ?",
                             (nonce,)).fetchone()
            require(row is not None and row[:2] == (authorization, request), "receipt-binding")
            return row[2]

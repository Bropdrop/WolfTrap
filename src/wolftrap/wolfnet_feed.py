"""Verify the subscriber's pinned keys, signed log and advisory lifecycle."""

from __future__ import annotations

from . import wolfnet_crypto
from .cursorial_trace import need
from .wolfnet_format import advisory_id, digest, genesis, interval, signing_bytes, time_value, validate


class Trust:
    def __init__(self, bundle, now):
        validate(bundle, "trust")
        time_value(now)
        interval(bundle["since"], bundle["expires"])
        time_value(bundle["clock_origin"])
        need(bundle["since"] <= now < bundle["expires"], "stale-publisher-trust")
        self.bundle, self.scope, self.now = bundle, bundle["subscription"], now
        self.keys = {}
        used_public = set()
        actors = {}
        for key in sorted(bundle["keys"], key=lambda k: (k["signer"], k["revision"])):
            signer, revision = key["signer"], key["revision"]
            coordinate = (signer, revision)
            public = bytes.fromhex(key["public_key"])
            need(coordinate not in self.keys and public not in used_public and wolfnet_crypto.valid_key(public),
                 "ambiguous-or-invalid-trust-key")
            interval(key["since"], key["expires"])
            if key["revoked_at"] is not None:
                time_value(key["revoked_at"])
            role_org = (key["role"], key["org"])
            need(actors.setdefault(signer, role_org) == role_org, "ambiguous-signer-identity")
            parent = self.keys.get((signer, revision - 1))
            need(key["predecessor"] == revision - 1 and
                 (revision == 1 or (parent is not None and parent["since"] < key["since"])), "invalid-key-lineage")
            self.keys[coordinate] = key
            used_public.add(public)

    def check(self, seal, role, body, signed_at, *, anchored=False, current=False):
        key = self.keys.get((seal["signer"], seal["key_revision"]))
        need(key is not None and key["role"] == role, "untrusted-signer-or-role")
        need(key["since"] <= signed_at < key["expires"], "signature-outside-key-validity")
        revoked = key["revoked_at"]
        need(revoked is None or (signed_at < revoked and (anchored or self.now < revoked)), "revoked-signing-key")
        if current:
            need(self.now < key["expires"] and (revoked is None or self.now < revoked), "current-signer-unavailable")
        data = signing_bytes(role, seal["signer"], seal["key_revision"], body)
        need(wolfnet_crypto.verify(bytes.fromhex(key["public_key"]), data, bytes.fromhex(seal["signature"])),
             "invalid-ed25519-signature")
        return key


def _publication(envelope, trust, frame, anchored, prior):
    r = envelope["record"]
    need(r["subscription"] == trust.scope and all(r["subject"][k] == trust.scope[k] for k in ("issuer", "tenant", "trust_domain")),
         "publication-outside-subscriber-scope")
    need(r["advisory_id"] == advisory_id(trust.scope, r["publisher"], r["serial"]), "advisory-id-namespace-mismatch")
    interval(r["updated_at"], r["expires_at"], 30)
    time_value(r["created_at"])
    need(r["created_at"] <= r["updated_at"] <= frame["published_at"] and r["sharing_consent"], "unapproved-publication")
    need(r["severity"] > 0 or r["status"] != "ACTIVE", "clear-cannot-be-an-adverse-publication")
    status = r["status"]
    if prior is None:
        need(r["revision"] == 1 and r["created_at"] == r["updated_at"] and
             r["supersedes"] is None and r["withdraws"] is None and status in ("PENDING_REVIEW", "ACTIVE"),
             "invalid-first-advisory-revision")
    else:
        old = prior["record"]
        need(old["status"] != "WITHDRAWN" and r["revision"] == old["revision"] + 1
             and old["updated_at"] < r["updated_at"], "replayed-or-terminal-advisory")
        fixed = ("advisory_id", "created_at", "publisher", "serial", "subject", "operation_sha256", "resource_scope", "incident_ref")
        need(all(old[k] == r[k] for k in fixed), "supersession-subject-or-incident-substitution")
        back, unused = ("withdraws", "supersedes") if status == "WITHDRAWN" else ("supersedes", "withdraws")
        need(r[back] == prior["record_sha256"] and r[unused] is None, "broken-advisory-supersession")
        need(status != "PENDING_REVIEW" or old["status"] == "PENDING_REVIEW", "invalid-review-regression")
    author = envelope["author"]
    role = "reviewer" if status == "CONTESTED" and author["signer"] != r["publisher"] else "publisher"
    need(role == "reviewer" or author["signer"] == r["publisher"], "unauthorized-publisher")
    author_key = trust.check(author, role, r, r["updated_at"], anchored=anchored)
    approvals = envelope["approvals"]
    need([s["signer"] for s in approvals] == sorted(set(s["signer"] for s in approvals)), "ambiguous-approval-order")
    keys = [trust.check(s, "reviewer", r, r["updated_at"], anchored=anchored) for s in approvals]
    orgs = {key["org"] for key in keys}
    publisher_keys = [k for k in trust.keys.values() if k["signer"] == r["publisher"] and k["role"] == "publisher"]
    need(bool(publisher_keys), "unknown-publication-owner")
    pub_org = publisher_keys[0]["org"]
    need(pub_org not in orgs and len(orgs) == len(keys) and (role != "reviewer" or author_key["org"] != pub_org),
         "review-independence-failed")
    elevated = r["severity"] >= 3 or r["recommendation"] in ("QUARANTINE", "DENY") or (
        prior is not None and prior["record"]["status"] == "CONTESTED")
    need(status != "ACTIVE" or len(orgs) >= (2 if elevated else 1), "independent-publication-approval-missing")
    signers = [author_key, *keys]
    retroactive = any(k["revoked_at"] is not None and k["revoked_at"] <= trust.now for k in signers)
    state = status
    if retroactive:
        state = "UNTRUSTED"
    elif status != "WITHDRAWN" and r["expires_at"] <= trust.now:
        state = "EXPIRED"
    return {"record": r, "record_sha256": digest("advisory", r), "state": state, "publisher_org": pub_org,
            "approval_orgs": sorted(orgs), "author_signer": author["signer"]}


def read_feed(feed, bundle, checkpoint, at, *, use_accepted=False):
    validate(feed, "feed")
    validate(checkpoint, "checkpoint")
    trust = Trust(bundle, at)
    cap = checkpoint["sequence"]
    need(checkpoint["subscription"] == trust.scope and checkpoint["trust_revision"] <= bundle["revision"],
         "checkpoint-or-trust-scope-mismatch")
    time_value(checkpoint["accepted_at"])
    need(at >= checkpoint["accepted_at"], "subscriber-clock-rollback")
    previous = genesis(trust.scope)
    need(cap != 0 or checkpoint["head"] == previous, "invalid-genesis-checkpoint")
    history = feed["history"]
    need(len(history) >= cap, "rolled-back-snapshot")
    need((len(history) == cap) == use_accepted, "replayed-update-or-wrong-accepted-head")
    trust_digest = digest("subscriber-trust", bundle)
    if cap or "trust_sha256" in checkpoint:
        need("trust_sha256" in checkpoint and (checkpoint["trust_revision"] < bundle["revision"]
             or checkpoint["trust_sha256"] == trust_digest), "changed-trust-without-new-revision")
    records, ownership, audit = {}, {}, []
    previous_date = None
    for seq, envelope in enumerate(history, 1):
        body = envelope["body"]
        need(body["subscription"] == trust.scope and body["sequence"] == seq and body["previous"] == previous,
             "broken-feed-scope-sequence-or-predecessor")
        interval(body["published_at"], body["expires_at"], 7)
        need(body["published_at"] <= at and (previous_date is None or previous_date < body["published_at"]),
             "future-or-unordered-feed")
        final = seq == len(history)
        key = trust.check(envelope["seal"], "distributor", body, body["published_at"], anchored=seq <= cap, current=final)
        if final:
            need(at < body["expires_at"], "expired-feed")
        seen = set()
        changes = []
        for entry in body["entries"]:
            r = entry["record"]
            identifier = r["advisory_id"]
            need(identifier not in seen, "duplicate-advisory-in-frame")
            seen.add(identifier)
            claim_key = (r["publisher"], r["incident_ref"], r["subject"]["principal_id"], r["operation_sha256"])
            need(ownership.setdefault(claim_key, identifier) == identifier, "duplicate-or-reissued-incident")
            records[identifier] = _publication(entry, trust, body, seq <= cap, records.get(identifier))
            changes.append({"id": identifier, "revision": r["revision"], "state": r["status"],
                            "record_sha256": records[identifier]["record_sha256"]})
        previous, previous_date = digest("frame", envelope), body["published_at"]
        if seq == cap:
            need(checkpoint["head"] == previous and body["published_at"] <= checkpoint["accepted_at"], "checkpoint-fork")
        audit.append({"sequence": seq, "head": previous, "signer": key["signer"], "key_revision": key["revision"], "changes": changes})
    # Bound a proposal's lifetime by already-known future trust changes, even on a quiet feed.
    horizons = [bundle["expires"], history[-1]["body"]["expires_at"], key["expires"]]
    horizons.extend(k["revoked_at"] for k in trust.keys.values() if k["revoked_at"] and k["revoked_at"] > at)
    candidate = {"schema": "wolftrap.wolfnet-checkpoint/v1", "subscription": trust.scope, "trust_revision": bundle["revision"],
                 "trust_sha256": trust_digest, "sequence": len(history), "head": previous, "accepted_at": at}
    return trust, records, {"checkpoint": candidate, "audit": audit, "valid_until": min(horizons),
                             "update_state": "CURRENT_PINNED" if use_accepted else "VERIFIED_EXTENSION"}

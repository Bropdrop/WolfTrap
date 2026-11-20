"""Bounded, data-only variations of public fixture publications and subscriber state."""

from copy import deepcopy

from .wolfnet_fixtures import append_frame, basic, checkpoint, public_key, publication, ref_hash, sign, stamp, update
from .wolfprint_fixtures import fixture as workload


def _bad(seal):
    seal["signature"] = ("01" if seal["signature"][:2] == "00" else "00") + seal["signature"][2:]


def case(profile, name):
    kind = {"read-only": "moderate", "unrelated-behavior": "moderate", "static-lookalike": "static",
            "healthy-accused": "healthy"}.get(name, "high")
    x = basic(profile, kind)
    frame = x["feed"]["history"][0]
    body = frame["body"]
    r = body["entries"][0]["record"]
    obs = x["witnesses"]["witnesses"][0]
    p = x["policy"]
    keys = {k["signer"]: k for k in x["trust"]["keys"]}
    if name in ("explicit-deny", "no-deny-consent", "quarantine", "policy-reauth", "human-review", "read-only",
                "extra-reviewer-required", "low-confidence", "higher-local-threshold", "principal-scope-restart",
                "withdrawn", "corrected-and-reviewed", "rotation", "recovered-publisher", "policy-revision-change"):
        p.update(mode="fictional-simulation", permit_deny=True)
    actions = {"quarantine": "QUARANTINE", "policy-reauth": "REAUTHENTICATE", "human-review": "REQUIRE_HUMAN_APPROVAL",
               "policy-revision-change": "REAUTHENTICATE"}
    if name in actions:
        p["actions"][3] = actions[name]
    if name == "policy-revision-change":
        p["revision"] += 1
    if name == "no-deny-consent":
        p.pop("permit_deny")
    elif name == "extra-reviewer-required":
        p["min_reviewers"] = 3
    elif name == "low-confidence":
        r["confidence"] = "LOW"
    elif name == "higher-local-threshold":
        p["min_severity"] = 4
    elif name == "missing-evidence":
        x["witnesses"]["witnesses"] = []
    elif name == "missing-trace":
        x.update(traces=[], witness_registry=None)
    elif name == "contradictory-host-binding":
        x["witness_registry"]["bindings"][0]["operation_sha256"] = "a" * 64
    elif name == "historic-authority-conflict":
        x["witness_registry"]["grants"] = deepcopy(x["registry"]["grants"])
    elif name == "unsigned-custody":
        x["witness_registry"]["revocations"] = [{"principal": profile + 1, "instance": x["request"]["claim"]["instance"], "at": 1}]
    elif name in ("same-build-other-principal", "unrelated-behavior", "benign-upgrade", "different-instance", "principal-scope-restart"):
        r["subject"]["instance_id"] = None if name != "different-instance" else r["subject"]["instance_id"]
        families = {"same-build-other-principal": "other-principal-same-build", "unrelated-behavior": "other-principal-same-build",
                    "benign-upgrade": "changed-build-authorized", "different-instance": "concurrent", "principal-scope-restart": "restart"}
        x["manifest"], x["request"], x["registry"], _ = workload(profile, families[name])
    elif name == "foreign-presentation":
        x["request"]["claim"]["tenant"] += 1
    elif name == "missing-presentation":
        x["request"]["claim"] = None
    elif name == "copied-presentation":
        p.update(mode="fictional-simulation", permit_deny=True, disputed_instances=[r["subject"]["instance_id"]])
    elif name == "wrong-operation":
        r["operation_sha256"] = "a" * 64
    elif name == "wrong-resource":
        r["resource_scope"] += 1
    elif name == "publisher-not-selected":
        p["publishers"] = [6]
    elif name in ("local-appeal", "immutable-legal-hold"):
        p["appeal_holds"] = [r["advisory_id"]]
    elif name == "pending-review":
        r["status"] = "PENDING_REVIEW"
    elif name == "expired-record":
        r["expires_at"] = stamp(59)
    elif name == "expired-observation":
        obs["body"]["expires_at"] = stamp(59)
        obs["seal"] = sign("observer", 5, obs["body"])
        r["evidence_sha256"] = ref_hash("observation", obs["body"])
    elif name == "unauthorized-host-operation":
        x["registry"]["grants"] = []
    elif name == "runtime-claim":
        r.update(evidence_class="AUTHORIZED RUNTIME VERIFIED", identity_assurance="RUNTIME_AUTHENTICATED")
    elif name == "critical-on-simulation":
        r["severity"] = 4
    elif name == "session-assurance-unknown":
        r["identity_assurance"] = "UNKNOWN"
    elif name == "wrong-digest":
        r["evidence_sha256"] = "1" * 64
    elif name == "unlinked-provenance":
        r["provenance_ref"] = "2" * 64
    elif name == "independent-observer-required":
        keys[5]["org"] = keys[2]["org"]
    elif name.startswith("compromised-"):
        signer = {"compromised-publisher": 2, "compromised-distributor": 1, "compromised-reviewer": 4}[name]
        keys[signer]["revoked_at"] = stamp(51)
    elif name == "retired-distributor":
        keys[1]["expires"] = stamp(51)
    elif name == "duplicate-key-material":
        keys[7]["public_key"] = keys[3]["public_key"]
    elif name == "small-order-key":
        keys[2]["public_key"] = "00" * 32
    elif name == "unlinked-rotation":
        x["trust"]["keys"].append({**public_key(2, 2), "predecessor": 0})
    elif name == "stale-trust":
        x["trust"]["expires"] = stamp(50)
    elif name == "trust-downgrade":
        x["checkpoint"]["trust_revision"] = 2
    elif name == "wrong-stream":
        body["subscription"] = {**body["subscription"], "stream": 2}
    elif name in ("wrong-tenant", "wrong-issuer", "wrong-domain"):
        r["subject"][{"wrong-tenant": "tenant", "wrong-issuer": "issuer", "wrong-domain": "trust_domain"}[name]] += 1
    elif name == "publication-without-consent":
        r["sharing_consent"] = False
    elif name == "same-review-org":
        keys[4]["org"] = keys[3]["org"]
    elif name == "publisher-reviews-itself":
        keys[3]["org"] = keys[2]["org"]
    elif name == "attacker-free-text":
        r["operator_instructions"] = "fictional untrusted text"
    elif name == "stale-policy":
        p["expires"] = stamp(50)
    elif name == "invalid-subscriber-scope":
        p["subscription"] = {**p["subscription"], "tenant": 20}
    elif name == "advisory-id-clash":
        r["advisory_id"] = "WN-" + "0" * 64
    reviewers = {"only-one-reviewer": (3,), "duplicate-signoff": (3, 3)}.get(name, (3, 4))
    pub = publication(r, reviewers)
    body["entries"] = [pub]
    if name == "no-published-records":
        body["entries"] = []
    elif name == "duplicated-id":
        body["entries"].append(deepcopy(pub))
    elif name == "changed-advisory":
        pub["record"]["severity"] = 2
    elif name == "forged-approval":
        _bad(pub["approvals"][0])
    elif name == "forged-witness":
        _bad(obs["seal"])
    elif name == "fake-publisher":
        pub["record"].update(publisher=4000, advisory_id="WN-" + ref_hash("advisory-id", [r["subscription"], 4000, 1]))
        pub["author"]["signer"] = 4000
    elif name == "foreign-author":
        pub["author"] = sign("publisher", 6, pub["record"])
    elif name == "expired-feed":
        body["expires_at"] = stamp(59)
    elif name == "future-snapshot":
        body["published_at"] = stamp(70)
    elif name == "missing-frame":
        body["sequence"] = 2
    frame["seal"] = sign("distributor", 1, body)
    if name == "wrong-role":
        frame["seal"] = sign("publisher", 2, body)
    elif name == "forged-feed":
        _bad(frame["seal"])
    elif name == "unknown-schema":
        x["feed"]["schema"] = "wolftrap.wolfnet-feed/v2"
    elif name == "algorithm-substitution":
        frame["seal"]["alg"] = "none"
    elif name == "replayed-witness":
        x["witnesses"]["witnesses"].append(deepcopy(obs))
    elif name in ("withdrawn", "revive-withdrawn", "tombstone-reissue", "withdrawal-disagreement"):
        update(x, "WITHDRAWN", reviewers=())
        if name == "revive-withdrawn":
            update(x, "ACTIVE")
        if name in ("tombstone-reissue", "withdrawal-disagreement"):
            publisher = 6 if name == "withdrawal-disagreement" else 2
            new = {**r, "serial": 2, "publisher": publisher, "advisory_id": "WN-" + ref_hash("advisory-id", [r["subscription"], publisher, 2])}
            append_frame(x, [publication(new)], 40)
    elif name in ("contested", "corrected-and-reviewed", "immutable-legal-hold"):
        update(x, "CONTESTED", reviewers=(), signer=7)
        if name != "contested":
            update(x, "ACTIVE")
    elif name in ("rotation", "recovered-publisher"):
        x["trust"]["keys"].append(public_key(2, 2))
        if name == "recovered-publisher":
            x["checkpoint"] = checkpoint(x, 1, 32)
            x["trust"]["revision"] += 1
            keys[2]["revoked_at"] = stamp(33)
        update(x, "ACTIVE", key=2)
    elif name in ("pinned-reassessment", "replayed-head"):
        x["checkpoint"] = checkpoint(x, 1, 35)
        x["accepted"] = name == "pinned-reassessment"
    elif name == "superseded-downgrade":
        update(x, "ACTIVE", severity=2)
    elif name == "conflicting-publishers":
        different = {**r, "publisher": 6, "advisory_id": "WN-" + ref_hash("advisory-id", [r["subscription"], 6, 1]), "severity": 2}
        append_frame(x, [publication(different)], 40)
    elif name == "rollback":
        x["checkpoint"] = {**x["checkpoint"], "sequence": 2, "head": "c" * 64}
    elif name == "trust-equivocation":
        x["checkpoint"] = checkpoint(x, 1, 32)
        keys[7]["expires"] = stamp(400)
        append_frame(x, [], 36)
    elif name == "checkpoint-fork":
        x["checkpoint"] = {**checkpoint(x, 1, 32), "head": "f" * 64}
        append_frame(x, [], 36)
    elif name in ("old-signature-on-update", "broken-correction", "change-subject"):
        update(x, "ACTIVE")
        last = x["feed"]["history"][-1]
        changed = last["body"]["entries"][0]
        if name == "old-signature-on-update":
            changed["author"] = pub["author"]
        else:
            if name == "change-subject":
                changed["record"]["subject"]["principal_id"] = "a" * 64
            else:
                changed["record"]["supersedes"] = "a" * 64
            last["body"]["entries"] = [publication(changed["record"])]
        last["seal"] = sign("distributor", 1, last["body"])
    return x

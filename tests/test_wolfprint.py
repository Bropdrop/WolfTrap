"""WolfPrint reference vectors, trust boundaries and fictional decision controls."""

import json
import unittest
from copy import deepcopy
from pathlib import Path

from wolftrap.cursorial_trace import Gap
from wolftrap.wolfprint import UNKNOWN, domain_digest, fingerprint, session_id, subject
from wolftrap.wolfprint_challenge import qualify, trace_fixture
from wolftrap.wolfprint_fixtures import fixture, artifact
from wolftrap.wolfprint_identity import ATTESTED, GAP, INVALID, SPOOF, inspect, registry_contract
from wolftrap.wolfprint_trace import inspect_chain

EXAMPLE = Path(__file__).resolve().parents[1] / "examples/wolfprint"


class Architecture(unittest.TestCase):
    def test_published_interoperability_vector(self):
        m = json.loads((EXAMPLE / "architecture.json").read_bytes())
        s = json.loads((EXAMPLE / "request.json").read_bytes())["claim"]
        self.assertEqual(fingerprint(m)["architecture_sha256"], "1eb831471e151d55469c3c49ed25cb699d2c6230fa093499b5935437032629ed")
        self.assertEqual(subject(s), "2c5f894119cc61db92e99020ecc5bdab23e621160edd439e8e8b1f36bddeeb84")
        self.assertEqual(session_id(s), "96dcd5fd6f96b3592135c9aa2a49b860ba5d48a94ea3912dca69450cf8f61cd0")
        self.assertEqual(len({domain_digest(d, []) for d in ("architecture", "instance", "principal", "behavior")}), 4)

    def test_order_and_optional_unknown(self):
        m, *_ = fixture()
        other = dict(reversed(deepcopy(m).items()))
        other["mcp_tools"].reverse()
        other["capabilities"].reverse()
        del other["protected_config_sha256"]
        self.assertEqual(fingerprint(m), fingerprint(other))

    def test_every_architecture_component_changes_fingerprint(self):
        m, *_ = fixture()
        before = fingerprint(m)["architecture_sha256"]
        for k in sorted(m.keys() - {"schema"}):
            with self.subTest(k=k):
                changed = deepcopy(m)
                changed[k] = artifact("new") if k == "protected_config_sha256" else UNKNOWN
                self.assertNotEqual(before, fingerprint(changed)["architecture_sha256"])
        for k in ("server_sha256", "tool_sha256", "schema_sha256"):
            changed = deepcopy(m)
            changed["mcp_tools"][0][k] = artifact("substitute")
            self.assertNotEqual(before, fingerprint(changed)["architecture_sha256"])

    def test_namespace_collision_and_empty_vs_unknown(self):
        m, *_ = fixture()
        self.assertEqual(m["mcp_tools"][0]["tool_sha256"], m["mcp_tools"][1]["tool_sha256"])
        fingerprint(m)
        m["mcp_tools"][0]["server_sha256"] = m["mcp_tools"][1]["server_sha256"]
        with self.assertRaisesRegex(Gap, "ambiguous-namespaced-tool"):
            fingerprint(m)
        self.assertNotEqual(fingerprint({**m, "mcp_tools": []}), fingerprint({**m, "mcp_tools": UNKNOWN}))

    def test_non_ascii_and_schema_ambiguity(self):
        m, *_ = fixture()
        for replace in ({"framework": "r\u043enner"}, {"model_family": "x\n"}, {"model_revision": {"label": "v1"}},
                        {"capabilities": ["read", "read"]}, {"build_sha256": "A" * 64}, {"schema": "unknown"},
                        {"public_key": 1}, {"framework_version": True}):
            with self.subTest(replace=replace), self.assertRaises(Gap):
                fingerprint({**m, **replace})

    def test_claimed_model_coverage(self):
        m, req, r, at = fixture()
        self.assertEqual(inspect(m, None)["coverage"]["model_revision"], "DECLARED")
        self.assertIsNone(inspect(m, None)["policy_proposal"])
        self.assertEqual(inspect(m, req, r, at)["coverage"]["model_revision"], "ATTESTED")
        m, req, r, at = fixture(0, "unknown-model")
        self.assertEqual(inspect(m, req, r, at)["coverage"]["model_revision"], UNKNOWN)


class IdentityAndAuthority(unittest.TestCase):
    def test_same_build_separate_principals_and_restrictions(self):
        a = inspect(*fixture(1, "authorized"))
        b = inspect(*fixture(1, "other-principal-foreign-restriction"))
        c = inspect(*fixture(1, "other-principal-quarantined"))
        self.assertEqual(a["architecture_sha256"], b["architecture_sha256"])
        self.assertNotEqual(a["identity"]["principal_id"], b["identity"]["principal_id"])
        self.assertEqual(b["policy_proposal"]["action"], "ALLOW")
        self.assertEqual(c["policy_proposal"]["action"], "QUARANTINE")
        self.assertEqual(len(c["policy_proposal"]["appeal"]["review_ids"]), 1)

    def test_grant_conflicting_with_attested_capability_needs_review(self):
        m, q, r, at = fixture(2, "attested-capability-exclusion")
        result = inspect(m, q, r, at)
        self.assertEqual(result["identity"]["status"], ATTESTED)
        self.assertEqual(result["policy_proposal"]["reason"], "operation-outside-attested-capabilities")
        r["sessions"][-1]["capabilities"].append(q["operation"]["verb"])
        conflict = inspect(m, q, r, at)
        self.assertEqual(conflict["identity"]["status"], GAP)
        self.assertFalse(conflict["policy_proposal"]["current_scoped_grant"])

    def test_restart_concurrency_and_rotation(self):
        base = inspect(*fixture(1))
        for family in ("restart", "concurrent", "rotation"):
            r = inspect(*fixture(1, family))
            self.assertEqual(base["identity"]["principal_id"], r["identity"]["principal_id"])
            self.assertNotEqual(base["identity"]["instance_id"], r["identity"]["instance_id"])
            self.assertEqual("VERIFIED_KEY_ROTATION" in r["classification"], family == "rotation")
        _, prior_q, _, _ = fixture(1)
        for family, expected in (("restart", INVALID), ("concurrent", ATTESTED)):
            m, _, registry, at = fixture(1, family)
            self.assertEqual(inspect(m, prior_q, registry, at)["identity"]["status"], expected)

    def test_scope_bound_identifiers(self):
        _, req, _, _ = fixture()
        s = req["claim"]
        for k in ("issuer", "trust_domain", "tenant", "principal"):
            self.assertNotEqual(subject(s), subject({**s, k: s[k] + 1}))
        for k in ("instance", "nonce", "expires", "issued", "audience", "key_revision", "policy_revision"):
            self.assertNotEqual(session_id(s), session_id({**s, k: s[k] + 1}))
        self.assertNotEqual(session_id(s), session_id({**s, "delegation": [1]}))

    def test_registry_records_are_not_live_credentials(self):
        r = inspect(*fixture())
        self.assertEqual(r["identity"]["status"], ATTESTED)
        self.assertFalse(r["identity"]["cryptographically_authenticated"])
        self.assertFalse(r["policy_proposal"]["enforced"])
        m, q, _, _ = fixture()
        r = inspect(m, q)
        self.assertEqual(r["identity"]["status"], GAP)
        self.assertIsNone(r["identity"]["principal_id"])

    def test_surrogate_claims_get_no_attributed_principal(self):
        for kind, status in (("wrong-issuer", INVALID), ("forged-schema", SPOOF), ("missing-claim", GAP),
                             ("replay", INVALID), ("foreign-delegation", SPOOF)):
            r = inspect(*fixture(2, kind))
            self.assertEqual(r["identity"]["status"], status)
            self.assertIsNone(r["policy_proposal"]["principal_id"])
            self.assertFalse(r["policy_proposal"]["write_eligible_in_model"])

    def test_issuance_and_key_rotation_boundaries(self):
        m, q, r, at = fixture(1, "rotation")
        r["principals"][0]["keys"][1]["since"] = q["claim"]["issued"] + 1
        self.assertEqual(inspect(m, q, r, at)["identity"]["status"], INVALID)
        r["principals"][0]["keys"][1]["previous"] = 2
        with self.assertRaisesRegex(Gap, "key-lineage"):
            inspect(m, q, r, at)

    def test_registry_rejects_contradictory_independent_evidence(self):
        for field in ("sessions", "principals", "grants"):
            m, q, r, at = fixture()
            r[field].append(deepcopy(r[field][0]))
            with self.subTest(field=field), self.assertRaises(Gap):
                inspect(m, q, r, at)
        m, q, r, at = fixture()
        r["baseline"]["instance"] += 50
        with self.assertRaisesRegex(Gap, "unwitnessed-baseline"):
            registry_contract(r)

    def test_grant_must_still_be_current(self):
        for kind in ("stale-authority-epoch", "stale-policy-revision", "wrong-scope", "wrong-operation",
                     "revoked-grant", "changed-without-new-grant"):
            r = inspect(*fixture(0, kind))
            self.assertEqual(r["identity"]["status"], ATTESTED)
            self.assertEqual(r["policy_proposal"]["action"], "DENY")
            self.assertFalse(r["policy_proposal"]["write_eligible_in_model"])

    def test_expiration_and_review_revision(self):
        m, q, r, at = fixture(0, "quarantined")
        self.assertEqual(inspect(m, q, r, at)["policy_proposal"]["valid_until"], 100)
        self.assertEqual(inspect(m, q, r, 100)["policy_proposal"]["action"], "ALLOW")
        r["restrictions"][0]["since"] = at + 2
        first = inspect(m, q, r, at)["policy_proposal"]
        self.assertEqual((first["action"], first["valid_until"]), ("ALLOW", at + 2))
        later = inspect(m, q, r, at + 2)["policy_proposal"]
        self.assertEqual(later["action"], "QUARANTINE")
        self.assertNotEqual(later["audit_sha256"], first["audit_sha256"])
        r["restrictions"][0]["scope"] += 5
        self.assertEqual(inspect(m, q, r, at + 2)["policy_proposal"]["action"], "ALLOW")

    def test_scheduled_grant_and_session_revocation_bound_advice(self):
        m, q, r, at = fixture()
        r["grants"][0]["since"] = at + 5
        before = inspect(m, q, r, at)["policy_proposal"]
        self.assertEqual((before["action"], before["valid_until"]), ("DENY", at + 5))
        r["revocations"] = [{"principal": q["claim"]["principal"], "instance": q["claim"]["instance"], "at": at + 8}]
        after = inspect(m, q, r, at + 5)["policy_proposal"]
        self.assertEqual((after["action"], after["valid_until"]), ("ALLOW", at + 8))
        self.assertEqual(inspect(m, q, r, at + 8)["identity"]["status"], INVALID)

    def test_all_actions_and_appeal_are_scoped(self):
        for family, action in (("authorized", "ALLOW"), ("reauth-policy", "REAUTHENTICATE"), ("read-only", "READ_ONLY"),
                               ("human-policy", "REQUIRE_HUMAN_APPROVAL"), ("quarantined", "QUARANTINE"), ("denied", "DENY")):
            audit = inspect(*fixture(1, family))["policy_proposal"]
            self.assertEqual(audit["action"], action)
            self.assertTrue(all(audit[k] for k in ("tenant_id", "principal_id", "scope_id", "operation_sha256",
                                                   "policy_revision", "authority_epoch", "valid_until", "appeal")))
            self.assertEqual(audit["write_eligible_in_model"], action == "ALLOW")

    def test_copied_session_known_blind_spot(self):
        self.assertEqual(inspect(*fixture(3)), inspect(*fixture(3, "indistinguishable-presentation")))


class IdentityQualifiedChains(unittest.TestCase):
    def test_independent_join_at_both_boundaries(self):
        _, _, registry, trace = trace_fixture(2, "complete")
        p = inspect_chain(trace, registry)["identity_profile"]
        self.assertEqual(p["status"], "SYNTHETICALLY VERIFIED")
        a = p["attempts"][0]
        self.assertEqual(a["independently_observed_effects"], 1)
        self.assertEqual(set(a["phases"]), {"prepare", "commit"})
        self.assertEqual(a["initiator"]["instance_id"], a["phases"]["prepare"]["instance_id"])
        self.assertTrue(a["phases"]["commit"]["host_delegation_event"])
        self.assertNotEqual(p["behavioral_sha256"], UNKNOWN)

    def test_later_issued_session_cannot_claim_earlier_initiation(self):
        _, _, r, trace = trace_fixture(1, "complete")
        issued = trace["chain"]["sources"]["agent"]["events"][0]["at"] + 1
        r["sessions"][0]["statement"]["issued"] = issued
        for anchor, phase in zip(r["bindings"], trace["identity_witnesses"], strict=True):
            phase["claim"]["issued"] = issued
            anchor["statement_sha256"] = domain_digest("statement", phase["claim"])
        result = inspect_chain(trace, r)["identity_profile"]
        self.assertEqual((result["status"], result["reason"]), ("INCONCLUSIVE", "identity-not-current-at-proposal"))

    def test_revoke_between_prepare_and_effect(self):
        for family, count, status in (("revoked-before-effect", 1, "INCONCLUSIVE"),
                                      ("revocation-observed-denial", 0, "SYNTHETICALLY VERIFIED")):
            _, _, reg, trace = trace_fixture(1, family)
            p = inspect_chain(trace, reg)["identity_profile"]
            a = p["attempts"][0]
            self.assertEqual((p["status"], a["independently_observed_effects"]), (status, count))
            self.assertTrue(a["phases"]["prepare"]["policy_proposal"]["write_eligible_in_model"])
            self.assertFalse(a["phases"]["commit"]["policy_proposal"]["write_eligible_in_model"])

    def test_changed_identity_and_architecture(self):
        _, _, r, trace = trace_fixture(3, "changed-instance-and-build")
        p = inspect_chain(trace, r)["identity_profile"]
        self.assertEqual(p["status"], "INCONCLUSIVE")
        self.assertEqual(p["changes"][0]["changed"], ["instance_id", "architecture_sha256"])
        self.assertEqual(p["behavioral_sha256"], UNKNOWN)

    def test_host_or_ledger_substitution_is_incomplete(self):
        for family in ("missing-ledger", "detached-proposal", "duplicate-witness", "missing-witness", "missing-registry"):
            _, _, reg, trace = trace_fixture(1, family)
            self.assertEqual(inspect_chain(trace, reg)["status"], "INCONCLUSIVE")

    def test_behavior_is_scoped_and_cannot_validate_identity(self):
        _, _, r, trace = trace_fixture(0, "complete")
        _, _, other, equivalent = trace_fixture(3, "complete")
        pa = inspect_chain(trace, r)["identity_profile"]
        pb = inspect_chain(equivalent, other)["identity_profile"]
        self.assertNotEqual(pa["behavioral_sha256"], pb["behavioral_sha256"])
        r["sessions"][0]["statement"]["nonce"] += 5
        self.assertEqual(inspect_chain(trace, r)["identity_profile"]["behavioral_sha256"], UNKNOWN)

    def test_different_payloads_can_have_identical_behavior(self):
        from wolftrap.cursorial_corpus import fixture as schedule
        from wolftrap.cursorial_lab import execute
        from wolftrap.wolfprint_fixtures import anchor_trace
        from wolftrap.wolfprint_reference import operation

        _, req, r, trace = trace_fixture(1, "complete")
        original = inspect_chain(trace, r)["identity_profile"]
        plan = schedule(1)
        proposed = next(e["operation"] for e in plan if e["kind"] == "agent_proposal")
        proposed["value"] += 1
        digest = operation(proposed)
        for event in plan:
            if event["kind"] in ("grant_state", "request_bound"):
                event["digest"] = digest
        r["grants"][0]["operation_sha256"] = digest
        r["bindings"].clear()
        changed = inspect_chain(anchor_trace(execute(plan), req["claim"], r), r)["identity_profile"]
        self.assertEqual(changed["status"], "SYNTHETICALLY VERIFIED")
        self.assertNotEqual(original["trace_sha256"], changed["trace_sha256"])
        self.assertEqual(original["behavioral_sha256"], changed["behavioral_sha256"])

    def test_independent_expectations_and_mutations(self):
        report = qualify()
        s = report["summary"]
        self.assertEqual((s["cases"], s["mismatches"], s["defects_caught"], s["defects"]), (256, 0, 11, 11))
        self.assertGreater(len({row["audit_sha256"] for row in report["cases"]}), 150)
        for defect in report["defective_controls"]:
            self.assertGreater(defect["mismatches"], 0)
            self.assertTrue(defect["first_counterexample"])

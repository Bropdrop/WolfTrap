"""Protocol invariants exercised independently of CLI report generation."""

import unittest
from copy import deepcopy
from unittest.mock import patch

from wolftrap.cursorial_trace import Gap
from wolftrap.wolfprint import domain_digest
from wolftrap.wolfnet_challenge import assess_case
from wolftrap.wolfnet_corpus import case
from wolftrap.wolfnet_crypto import sodium, valid_key, verify
from wolftrap.wolfnet_fixtures import append_frame, basic, checkpoint, public_key, sign, stamp
from wolftrap.wolfnet_format import GAP, STATIC, SYNTHETIC, digest, signing_bytes, time_value, validate
from wolftrap.wolfnet_witness import inspect_feed


def examine(x):
    return inspect_feed(x["feed"], x["trust"], x["checkpoint"], x["witnesses"], x["traces"], x["witness_registry"],
                        x["at"], use_accepted=x["accepted"])


class Signatures(unittest.TestCase):
    def test_rfc8032_7_1_empty_message(self):
        key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(verify(key, b"", sig))
        self.assertFalse(verify(key, b"x", sig))
        self.assertFalse(verify(key, b"", sig[:-1]))
        self.assertFalse(verify(key, b"", sig[:32] + b"\xff" * 32))

    def test_invalid_or_low_order_keys(self):
        for key in (bytes(32), bytes(31), bytes([1]) + bytes(31), b"\xff" * 32):
            self.assertFalse(valid_key(key))
            self.assertFalse(verify(key, b"", bytes(64)))

    def test_unavailable_crypto_blocks(self):
        sodium.cache_clear()
        self.addCleanup(sodium.cache_clear)
        with patch("wolftrap.wolfnet_crypto.platform.machine", return_value="unsupported"):
            with self.assertRaisesRegex(Gap, "BLOCKED-ed25519-backend"):
                sodium()
        with patch("wolftrap.wolfnet_crypto.ctypes.CDLL", side_effect=OSError):
            with self.assertRaisesRegex(Gap, "BLOCKED-ed25519-backend"):
                sodium()

    def test_exact_signed_scope_and_role(self):
        body = {"a": 2, "b": 3}
        seal = sign("publisher", 2, body)
        key = bytes.fromhex(public_key(2)["public_key"])
        sig = bytes.fromhex(seal["signature"])
        self.assertTrue(verify(key, signing_bytes("publisher", 2, 1, dict(reversed(body.items()))), sig))
        for msg in (signing_bytes("reviewer", 2, 1, body), signing_bytes("publisher", 6, 1, body),
                    signing_bytes("publisher", 2, 2, body), signing_bytes("publisher", 2, 1, {"a": 3, "b": 2})):
            self.assertFalse(verify(key, msg, sig))

    def test_distinct_key_coordinates_and_role_lineage(self):
        x = basic()
        x["trust"]["keys"].append({**public_key(2, 2), "org": 3})
        with self.assertRaisesRegex(Gap, "ambiguous-signer-identity"):
            examine(x)
        for family in ("duplicate-key-material", "unlinked-rotation", "small-order-key", "wrong-role"):
            with self.subTest(family=family), self.assertRaises(Gap):
                examine(case(1, family))

    def test_fixed_calendar_and_closed_boolean(self):
        for value in ("2030-02-29T00:00:00Z", "2030-01-01T00:00:60Z", "2030-01-01T00:00:00+00:00"):
            with self.assertRaises(Gap):
                time_value(value)
        p = basic()["policy"]
        with self.assertRaises(Gap):
            validate({**p, "permit_deny": 1}, "policy")


class Feed(unittest.TestCase):
    def test_publisher_reviewers_and_observer_have_separate_custody(self):
        x = basic()
        row, = examine(x)["advisories"]
        self.assertEqual((row["publisher_org"], row["approval_orgs"], row["observer"]["org"]), (2, [3, 4], 5))
        self.assertEqual(row["state"], "ACTIVE")
        self.assertEqual(row["effective_level"], 3)

    def test_forged_layers_fail(self):
        for family in ("forged-feed", "forged-approval", "changed-advisory", "forged-witness", "old-signature-on-update"):
            with self.subTest(family=family), self.assertRaisesRegex(Gap, "invalid-ed25519-signature"):
                examine(case(1, family))

    def test_publish_consent_and_independence(self):
        for family in ("publication-without-consent", "only-one-reviewer", "same-review-org",
                       "duplicate-signoff", "publisher-reviews-itself", "foreign-author"):
            with self.subTest(family=family), self.assertRaises(Gap):
                examine(case(1, family))
        row, = examine(case(1, "independent-observer-required"))["advisories"]
        self.assertEqual((row["basis"], row["effective_level"]), ("observer-not-independent", None))

    def test_checkpoint_reassessment_and_clock(self):
        x = basic()
        report = examine(x)
        x["checkpoint"] = report["checkpoint"]
        with self.assertRaisesRegex(Gap, "replayed-update"):
            examine(x)
        x["accepted"] = True
        self.assertEqual(examine(x)["update_state"], "CURRENT_PINNED")
        x["at"] = stamp(59)
        with self.assertRaisesRegex(Gap, "subscriber-clock-rollback"):
            examine(x)

    def test_foreign_fork_or_truncated_history(self):
        for family in ("rollback", "checkpoint-fork", "missing-frame", "trust-downgrade", "wrong-stream", "trust-equivocation"):
            with self.subTest(family=family), self.assertRaises(Gap):
                examine(case(1, family))

    def test_terminal_withdrawals_and_corrected_disputes(self):
        w = examine(case(1, "withdrawn"))
        first, second = w["audit"]
        row, = w["advisories"]
        self.assertEqual((first["sequence"], second["sequence"], row["state"]), (1, 2, "WITHDRAWN"))
        self.assertEqual(row["record"]["withdraws"], first["changes"][0]["record_sha256"])
        self.assertEqual(assess_case(case(1, "corrected-and-reviewed"))["registry_proposal"], "DENY")
        for family in ("revive-withdrawn", "tombstone-reissue", "change-subject", "broken-correction"):
            with self.assertRaises(Gap):
                examine(case(1, family))

    def test_retroactive_compromise_requires_pinned_history_and_valid_recovery(self):
        recovered = case(1, "recovered-publisher")
        self.assertEqual(examine(recovered)["advisories"][0]["state"], "ACTIVE")
        recovered["checkpoint"] = basic()["checkpoint"]
        with self.assertRaisesRegex(Gap, "revoked-signing-key"):
            examine(recovered)
        for family in ("compromised-distributor", "compromised-reviewer", "compromised-publisher", "retired-distributor"):
            with self.assertRaises(Gap):
                examine(case(1, family))

    def test_revoked_withdrawal_never_supplies_clear(self):
        x = case(1, "withdrawn")
        x["checkpoint"] = checkpoint(x, 2, 40)
        x["trust"]["revision"] += 1
        x["trust"]["keys"][1]["revoked_at"] = stamp(42)
        append_frame(x, [], 45)
        report = examine(x)
        self.assertEqual((report["exit_code"], report["advisories"][0]["state"]), (2, "UNTRUSTED"))
        self.assertIsNone(assess_case(x)["registry_proposal"])

    def test_distributor_rotation_and_scheduled_cutoff(self):
        x = basic()
        x["checkpoint"] = checkpoint(x, 1, 34)
        x["trust"]["revision"] += 1
        x["trust"]["keys"].append(public_key(1, 2))
        x["trust"]["keys"][0]["revoked_at"] = stamp(35)
        x["trust"]["keys"][2]["revoked_at"] = stamp(70)
        append_frame(x, [], 40, key=2)
        report = examine(x)
        self.assertEqual(report["audit"][-1]["key_revision"], 2)
        self.assertEqual(report["valid_until"], stamp(70))
        self.assertLessEqual(assess_case(x)["valid_until"], stamp(70))

    def test_historical_witness_joins_proposal_gate_ledger_and_issuer(self):
        x = basic()
        row, = examine(x)["advisories"]
        obs = row["observation"]
        self.assertEqual((obs["effects"], obs["host_commit"], obs["reference_commit"]), (1, "deny", "deny"))
        self.assertTrue(obs["reproduction_sha256"])
        self.assertEqual(obs["subject"]["instance_id"], domain_digest("instance", x["request"]["claim"]))
        self.assertEqual(row["record"]["evidence_sha256"], digest("observation", x["witnesses"]["witnesses"][0]["body"]))

    def test_mutated_or_absent_ledger_never_confirms(self):
        x = basic()
        x["traces"][0]["chain"]["sources"]["ledger"]["events"][0]["records"] = []
        row, = examine(x)["advisories"]
        self.assertIsNone(row["effective_level"])
        for family in ("healthy-accused", "missing-trace", "missing-evidence", "contradictory-host-binding"):
            row, = examine(case(1, family))["advisories"]
            self.assertEqual(row["classification"], GAP)

    def test_refuses_synthetic_to_runtime_promotion(self):
        for family in ("runtime-claim", "critical-on-simulation"):
            report = examine(case(2, family))
            self.assertEqual((report["exit_code"], report["advisories"][0]["basis"]), (2, "qualified-runtime-witness-unavailable"))

    def test_publication_and_feed_expiration_are_distinct(self):
        x = case(1, "expired-record")
        self.assertEqual(examine(x)["advisories"][0]["state"], "EXPIRED")
        with self.assertRaisesRegex(Gap, "expired-feed"):
            examine(case(1, "expired-feed"))
        self.assertIsNone(examine(case(1, "expired-observation"))["advisories"][0]["effective_level"])


class Subscriber(unittest.TestCase):
    def test_seven_proposals_and_host_ownership(self):
        cases = {"advisory-default": "MONITOR", "explicit-deny": "DENY", "withdrawn": "ALLOW",
                 "quarantine": "QUARANTINE", "read-only": "READ_ONLY", "policy-reauth": "REAUTHENTICATE",
                 "human-review": "REQUIRE_HUMAN_APPROVAL"}
        for family, proposal in cases.items():
            with self.subTest(family=family):
                d = assess_case(case(2, family))
                self.assertEqual(d["registry_proposal"], proposal)
                self.assertFalse(d["enforced"])

    def test_no_mutation_of_subscriber_or_issuer(self):
        x = case(1, "explicit-deny")
        prior = deepcopy(x)
        assess_case(x)
        self.assertEqual(prior, x)

    def test_appeal_and_conflict_suspend_external_restrictions(self):
        for family in ("local-appeal", "immutable-legal-hold", "pending-review", "contested", "withdrawal-disagreement",
                       "conflicting-publishers"):
            d = assess_case(case(1, family))
            self.assertEqual((d["registry_proposal"], d["classification"]), (None, GAP))

    def test_local_authority_and_evidence_requirements(self):
        d = assess_case(case(1, "unauthorized-host-operation"))
        self.assertEqual((d["registry_proposal"], d["proposed_action"], d["current_scoped_grant"]), ("MONITOR", "DENY", False))
        for family in ("low-confidence", "extra-reviewer-required", "no-deny-consent", "higher-local-threshold"):
            self.assertEqual(assess_case(case(1, family))["registry_proposal"], "MONITOR")

    def test_no_inheritance_by_build_behavior_or_different_scope(self):
        for family in ("same-build-other-principal", "unrelated-behavior", "wrong-operation", "wrong-resource",
                       "benign-upgrade", "different-instance", "publisher-not-selected"):
            d = assess_case(case(2, family))
            self.assertEqual((d["registry_proposal"], d["effective_level"], d["advisories"]), ("ALLOW", 0, []))

    def test_restarts_and_copied_sessions_do_not_establish_actor(self):
        d = assess_case(case(1, "principal-scope-restart"))
        self.assertEqual(d["registry_proposal"], "MONITOR")
        self.assertEqual(d["subject_assurance"], "FIXTURE_ISSUER_BOUND")
        copied = assess_case(case(1, "copied-presentation"))
        self.assertEqual((copied["basis"], copied["proposed_action"]), ("operator-disputes-session-custody", "REAUTHENTICATE"))
        for family in ("foreign-presentation", "missing-presentation", "copied-presentation"):
            d = assess_case(case(1, family))
            self.assertEqual((d["principal_id"], d["registry_proposal"], d["subject_assurance"]), (None, None, "UNKNOWN"))

    def test_static_and_synthetic_assurance_remain_separate(self):
        d = assess_case(case(1, "static-lookalike"))
        self.assertEqual((d["classification"], d["subject_assurance"], d["host_proposal"]), (STATIC, "UNKNOWN", "ALLOW"))
        d = assess_case(case(1, "read-only"))
        self.assertEqual((d["classification"], d["effective_level"]), (SYNTHETIC, 2))

    def test_decision_binds_subject_evidence_policy_and_host(self):
        x = case(2, "explicit-deny")
        d = assess_case(x)
        self.assertEqual(d["subscription"], x["trust"]["subscription"])
        self.assertEqual(d["policy_sha256"], digest("local-policy", x["policy"]))
        self.assertEqual(d["publisher_trust_sha256"], digest("subscriber-trust", x["trust"]))
        self.assertEqual(d["host_authority_sha256"], domain_digest("registry", x["registry"]))
        self.assertEqual(d["audit_sha256"], digest("decision", {k: v for k, v in d.items() if k != "audit_sha256"}))
        x["policy"]["revision"] += 1
        self.assertNotEqual(d["audit_sha256"], assess_case(x)["audit_sha256"])

    def test_no_actions_for_null_presentation_and_registry(self):
        x = basic()
        x.update(request=None, registry=None)
        with self.assertRaisesRegex(Gap, "current-workload-presentation"):
            assess_case(x)

    def test_schema_rejects_excessive_histories(self):
        x = basic()
        x["feed"]["history"] *= 17
        with self.assertRaisesRegex(Gap, "invalid-feed-shape"):
            examine(x)

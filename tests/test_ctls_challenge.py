"""Independent hostile controls for the fictional, offline WT-CTLS-001 pack."""
from __future__ import annotations

import copy
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap import ctls_challenge as c


class CTLS001Qualification(unittest.TestCase):
    def test_authored_scenario_matrix(self) -> None:
        cases = c.corpus()
        self.assertEqual(len(cases), 37)
        self.assertEqual(len(set(i["case_id"] for i in cases)), len(cases))
        c.validate_corpus(cases)
        for item in cases:
            with self.subTest(case=item["case_id"]):
                result = c.execute_case(item)
                self.assertTrue(result["passed"], result)
                self.assertEqual(result["expected_effects"], result["observed_effects"])
                self.assertEqual(result["observed_effects"], result["claimed_effects"])
                self.assertTrue(result["audit_valid"])

    def test_mutation_controls_all_detected(self) -> None:
        cases = {i["case_id"]: i for i in c.corpus()}
        self.assertEqual(len(c.SENTINELS), 6)
        for mutant, control in c.SENTINELS.items():
            with self.subTest(mutant=mutant):
                self.assertFalse(c.execute_case(cases[control], fault=mutant)["passed"])
        _, report = c.evaluate()
        self.assertEqual(report["summary"]["sentinels_detected"], 6)
        self.assertEqual(report["summary"]["failed"], 0)

    def test_authorization_checked_before_operation_id_lookup(self) -> None:
        model = c.AuthorityModel()
        self.assertEqual(model.step(c.U(at=1, actor=c.OWNER_A)).code, "APPLIED")
        # Unauthorized actor must not learn whether the operation ID exists.
        self.assertEqual(model.step(c.U(at=2, actor="syn-outsider")).code, "NOT_OWNER")
        self.assertEqual(len(model.effects), 1)

    def test_transfer_atomicity_and_old_owner_fencing(self) -> None:
        m = c.AuthorityModel()
        p = c.P()
        self.assertEqual(m.step(p).code, "PREPARED")
        self.assertEqual(m.step(c.C(p, at=2)).code, "MISSING_WITNESS")
        self.assertEqual(m.owners[c.ORG_A], c.OWNER_A)
        self.assertEqual(m.effects, [])
        self.assertEqual(m.step(c.A(p, at=3)).code, "APPROVED")
        self.assertEqual(m.step(c.C(p, at=4)).code, "COMMITTED")
        self.assertEqual(m.owners[c.ORG_A], c.DEST_A)
        self.assertEqual(m.step(c.U(at=5, actor=c.OWNER_A)).code, "NOT_OWNER")
        self.assertEqual(len(m.effects), 1)
        m.verify_audit()

    def test_lost_ack_and_restart_never_duplicate_transfer(self) -> None:
        m = c.AuthorityModel()
        p = c.P()
        m.step(p)
        m.step(c.A(p))
        self.assertEqual(m.step(c.C(p, lost_reply=True)).code, "ACK_LOST")
        self.assertEqual(m.step(c.X("RESTART", 4)).code, "RESTARTED")
        self.assertEqual(m.step(c.C(p, at=5)).code, "ALREADY_COMMITTED")
        self.assertEqual(len(m.effects), 1)
        self.assertEqual(m.epochs[c.ORG_A], 2)

    def test_cancel_tombstone_cannot_be_resurrected(self) -> None:
        m = c.AuthorityModel()
        p = c.P()
        m.step(p)
        self.assertEqual(m.step(c.X("CANCEL", 2, org=c.ORG_A,
                                  tx=p["tx"], actor=c.OWNER_A)).code, "CLOSED")
        m.step(c.X("RESTART", 3))
        self.assertEqual(m.step(c.P(at=4)).code, "CLOSED")
        self.assertEqual(m.step(c.P(at=5, tx="syn-new-id")).code, "NONCE_REUSED")
        self.assertEqual(m.effects, [])

    def test_two_simulated_racing_transfers_one_winner(self) -> None:
        case = next(x for x in c.corpus() if x["case_id"] == "concurrent-transfer-one-winner")
        result = c.execute_case(case)
        self.assertTrue(result["passed"])
        self.assertEqual([e["kind"] for e in result["observed_effects"]], ["TRANSFER"])
        self.assertEqual(result["observed_decisions"][-1], "STALE_EPOCH")

    def test_unknown_authority_does_not_permit_commit(self) -> None:
        model = c.AuthorityModel()
        p = c.P()
        model.step(p)
        model.step(c.A(p))
        model.step(c.X("LOSE_STATE", 3))
        self.assertEqual(model.step(c.C(p, at=4)).code, "UNKNOWN_SECURITY_STATE")
        self.assertEqual(model.effects, [])

    def test_reviewer_revocation_rejects_previously_approved_transfer(self) -> None:
        model = c.AuthorityModel()
        p = c.P()
        model.step(p)
        model.step(c.A(p))
        model.step(c.X("REVOKE_REVIEWER", 3, org=c.ORG_A,
                       actor=c.OWNER_A, target=c.WITNESS_A))
        self.assertEqual(model.step(c.C(p, at=4)).code, "STALE_EPOCH")
        self.assertEqual(model.effects, [])

    def test_malformed_unknown_or_real_input_rejected(self) -> None:
        p = c.P()
        variants = [dict(p, org="https://hc-sc.gc.ca/ctls"),
                    dict(p, actor="real-email@example.ca"),
                    dict(p, bearer_token="fake"),
                    dict(p, at=True), dict(p, at=-1), dict(p, at=10_001),
                    dict(p, epoch=True), dict(p, epoch=1.5),
                    dict(p, expires=1), dict(p, expires=0),
                    dict(p, nonce=""), dict(p, tx="syn-" + "a" * 100),
                    dict(p, dest="syn-new\nowner"),
                    dict(p, op="POST"), {"op": "PREPARE", "at": 1}]
        for x in variants:
            with self.subTest(x=str(x)[:100]), self.assertRaises(ValueError):
                c.validate_command(x)
        with self.assertRaises(ValueError):
            c.validate_command(dict(c.A(p), binding="sha256:no"))
        with self.assertRaises(ValueError):
            c.validate_command(dict(c.C(p), lost_reply=1))

    def test_unknown_operation_and_untrusted_claim_rejected(self) -> None:
        m = c.AuthorityModel()
        with self.assertRaises(ValueError):
            m.step(dict(c.P(), role="admin"))
        with self.assertRaises(ValueError):
            m.step({"op": "HTTP_REQUEST", "at": 1, "url": "https://example.org"})
        self.assertEqual(m.audit, [])
        self.assertEqual(m.effects, [])

    def test_out_of_order_clock_rejected_without_record(self) -> None:
        m = c.AuthorityModel()
        m.step(c.U(at=4, actor=c.OWNER_A))
        with self.assertRaises(ValueError):
            m.step(c.U(at=3, actor=c.OWNER_A, operation_id="syn-second"))
        self.assertEqual(len(m.effects), 1)
        self.assertEqual(len(m.audit), 1)

    def test_checkpoint_digest_and_audit_chain_tamper(self) -> None:
        m = c.AuthorityModel()
        m.step(c.U(at=1, actor=c.OWNER_A))
        original = m.checkpoint()
        restored = c.AuthorityModel.from_checkpoint(original)
        self.assertEqual(restored.effects, m.effects)
        altered = json.loads(original)
        altered["state"]["owners"][c.ORG_A] = "syn-outsider"
        with self.assertRaises(ValueError):
            c.AuthorityModel.from_checkpoint(c.canonical(altered))
        altered = json.loads(original)
        altered["state"]["audit"][0]["decision"] = "DENIED"
        altered["state_digest"] = c.sha(c.canonical(altered["state"]))
        with self.assertRaises(ValueError):
            c.AuthorityModel.from_checkpoint(c.canonical(altered))

    def test_effect_ledger_divergence_is_detected(self) -> None:
        m = c.AuthorityModel()
        m.step(c.U(at=1, actor=c.OWNER_A))
        m.effects.clear()
        with self.assertRaises(ValueError):
            m.verify_audit()

    def test_deterministic_replay_and_network_block(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / "one", Path(tmp) / "two"
            with patch.object(socket, "socket", side_effect=AssertionError("network forbidden")), \
                 patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")):
                report, code = c.run(a)
                self.assertEqual(code, 0)
                self.assertEqual(c.verify(a), report)
                c.run(b)
                self.assertEqual(c.verify(b), report)
            self.assertEqual({p.name: p.read_bytes() for p in a.iterdir()},
                             {p.name: p.read_bytes() for p in b.iterdir()})

    def test_integrity_detects_corruption_even_with_rewritten_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp) / "evidence"
            c.run(evidence)
            manifest = json.loads((evidence / c.MANIFEST).read_bytes())
            report_path = evidence / c.REPORT
            report = json.loads(report_path.read_bytes())
            report["results"][0]["observed_decisions"][0] = "FORGED_ACCEPT"
            report_path.write_bytes(c.canonical(report))
            manifest["files"][c.REPORT] = {
                "bytes": report_path.stat().st_size, "sha256": c.sha(report_path.read_bytes())}
            (evidence / c.MANIFEST).write_bytes(c.canonical(manifest))
            with self.assertRaisesRegex(ValueError, "replay"):
                c.verify(evidence)

    def test_incomplete_extra_and_symlink_evidence_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            c.run(evidence)
            (evidence / "unexpected.txt").write_text("tampered")
            with self.assertRaises(ValueError):
                c.verify(evidence)
            (evidence / "unexpected.txt").unlink()
            with self.assertRaises(ValueError):
                c.run(evidence)
            original = evidence / c.REPORT
            other = root / "copy.json"
            other.write_bytes(original.read_bytes())
            original.unlink()
            original.symlink_to(other)
            with self.assertRaises(ValueError):
                c.verify(evidence)
            original.unlink()
            with self.assertRaises(ValueError):
                c.verify(evidence)

    def test_cli_run_and_verify(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "new-evidence"
            self.assertEqual(c.main(["run", "--output-dir", str(output)]), 0)
            self.assertEqual(c.main(["verify", "--evidence-dir", str(output)]), 0)
            self.assertEqual(c.main(["run", "--output-dir", str(output)]), 2)

    def test_no_real_system_or_credentials_in_authored_inputs(self) -> None:
        payload = c.canonical(c.corpus())
        for forbidden in [b"https://", b"http://", b"@", b"bearer", b"password",
                          b"hc-sc.gc.ca", b"ctls@"]:
            self.assertNotIn(forbidden, payload.lower())


if __name__ == "__main__":
    unittest.main()

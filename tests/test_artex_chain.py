"""Hostile, entirely offline controls for ARTEX-inspired multi-step chains."""

from __future__ import annotations

import copy
import json
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap.agent_scan import _json, _sha
from wolftrap.artex_chain import (
    MANIFEST_NAME, MARKDOWN_NAME, REPORT_NAME, _authorize, _cases,
    _enforce_chain, _sandbox_gate, _validate_case, evaluate_challenge,
    run_challenge, verify_evidence,
)
from wolftrap.cli import main


class ArtexChainTests(unittest.TestCase):
    def test_fixed_positive_and_denial_chains(self) -> None:
        report = evaluate_challenge()
        self.assertEqual(report["qualification"]["status"], "PASSED_BOUNDED")
        self.assertEqual(report["summary"]["cases"], 16)
        self.assertEqual(report["summary"]["attempts"], 65)
        self.assertEqual(report["summary"]["effect_records"], 1)
        self.assertEqual(report["summary"]["mismatches"], 0)
        self.assertTrue(all(row["passed"] for row in report["cases"]))
        self.assertEqual([row["case_id"] for row in report["cases"]], [
            case["case_id"] for case in _cases()
        ])
        self.assertEqual([len(row["observed_effects"]) for row in report["cases"]],
                         [1] + [0] * 15)
        self.assertFalse(report["qualification"]["real_network_scanning"])
        self.assertFalse(report["qualification"]["live_artex_tested"])
        self.assertFalse(report["qualification"]["ground_truth_runtime_tested"])
        self.assertFalse(report["qualification"]["hercules_runtime_tested"])

    def test_claims_cannot_mint_authority_or_approval(self) -> None:
        cases = {item["case_id"]: item for item in _cases()}
        forged = cases["forged-approval-from-tool-output"]
        denial = _enforce_chain(forged)
        self.assertEqual(denial["decisions"][1]["reason"], "UNKNOWN_GRANT")
        self.assertEqual([x["reason"] for x in denial["decisions"]][2:],
                         ["CHAIN_HALTED", "CHAIN_HALTED"])
        self.assertEqual(denial["effects"], [])
        no_approval = cases["host-denied-approval"]
        denial = _enforce_chain(no_approval)
        self.assertEqual(denial["decisions"][1]["reason"], "APPROVAL_REQUIRED")
        self.assertEqual(denial["effects"], [])

    def test_revocation_at_final_boundary_neutralizes_preparation(self) -> None:
        case = next(item for item in _cases()
                    if item["case_id"] == "revoked-after-preparation")
        effects: list[dict] = []
        result = _enforce_chain(case, record_effect=effects.append)
        self.assertEqual([item["reason"] for item in result["decisions"]],
                         ["ACCEPTED", "ACCEPTED", "ACCEPTED", "REVOKED"])
        self.assertEqual(effects, [])
        self.assertEqual(result["effects"], [])

    def test_sequence_never_resumes_after_denial_or_duplicate(self) -> None:
        case = next(item for item in _cases()
                    if item["case_id"] == "duplicate-first-step-halts-chain")
        result = _enforce_chain(case)
        self.assertEqual([item["reason"] for item in result["decisions"]], [
            "ACCEPTED", "CHAIN_ORDER_DENIED", "CHAIN_HALTED",
            "CHAIN_HALTED", "CHAIN_HALTED",
        ])
        self.assertEqual(result["effects"], [])

    def test_grant_and_environment_splicing_denied_independently(self) -> None:
        good = _cases()[0]
        substituted = dict(good["intents"][2], agent_id="synthetic-agent://intruder")
        self.assertEqual(_sandbox_gate(good["host"]["envelopes"], substituted),
                         "UNKNOWN_SANDBOX")
        for case_id, decision in (
            ("cross-tenant-chain-splice", "TENANT_MISMATCH"),
            ("cross-agent-chain-splice", "DELEGATE_MISMATCH"),
            ("changed-operation-at-commit", "OPERATION_MISMATCH"),
            ("unauthorized-privilege-escalation", "SCOPE_MISMATCH"),
            ("valid-foreign-grant-cannot-splice-chain", "CHAIN_IDENTITY_MISMATCH"),
        ):
            with self.subTest(case=case_id):
                case = next(item for item in _cases() if item["case_id"] == case_id)
                self.assertIn(decision, [row["reason"] for row in _enforce_chain(case)["decisions"]])

    def test_foreign_step_has_valid_grant_but_cannot_switch_chain_identity(self) -> None:
        case = next(item for item in _cases() if item["case_id"] ==
                    "valid-foreign-grant-cannot-splice-chain")
        attempt = case["intents"][2]
        grant = next(grant for grant in case["grants"]
                     if grant["grant_id"] == attempt["grant_id"])
        self.assertEqual(_sandbox_gate(case["host"]["envelopes"], attempt), "ADMITTED")
        self.assertEqual(_authorize(grant, attempt, case["host"], set()), "ACCEPTED")
        result = _enforce_chain(case)
        self.assertEqual(result["decisions"][2]["reason"], "CHAIN_IDENTITY_MISMATCH")
        self.assertEqual(result["effects"], [])

    def test_invalid_unbounded_and_nonfictional_inputs_fail_before_execution(self) -> None:
        base = _cases()[0]
        mutations = []
        case = copy.deepcopy(base)
        case["intents"][0]["resource"] = "https://external.example.com"
        mutations.append(case)
        case = copy.deepcopy(base)
        case["intents"][0]["resource"] = "synthetic://lab/../../etc"
        mutations.append(case)
        case = copy.deepcopy(base)
        case["intents"][0]["network_request"] = "INTERNET"
        mutations.append(case)
        case = copy.deepcopy(base)
        case["intents"][0]["command"] = "/bin/sh"
        mutations.append(case)
        case = copy.deepcopy(base)
        case["intents"][0]["at"] = True
        mutations.append(case)
        case = copy.deepcopy(base)
        case["grants"][1]["nonce"] = case["grants"][0]["nonce"]
        mutations.append(case)
        case = copy.deepcopy(base)
        case["intents"] *= 2
        mutations.append(case)
        case = copy.deepcopy(base)
        case["host"]["current_epoch"] = False
        mutations.append(case)
        case = copy.deepcopy(base)
        case["grants"][0]["approved"] = "yes"
        mutations.append(case)
        case = copy.deepcopy(base)
        case["expected_reasons"] = ["ACCEPTED"]
        mutations.append(case)
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ValueError):
                _validate_case(mutation)

    def test_fail_open_fail_closed_and_revocation_bypass_sentinels(self) -> None:
        with patch("wolftrap.artex_chain._sandbox_gate", return_value="ADMITTED"):
            self.assertEqual(evaluate_challenge()["qualification"]["status"], "CONTROL_GAP")
        with patch("wolftrap.artex_chain._sandbox_gate", return_value="UNKNOWN_ISOLATION"):
            self.assertEqual(evaluate_challenge()["qualification"]["status"], "CONTROL_GAP")

        real_gate = _authorize

        def skip_revocation(grant, intent, host, consumed):
            if grant is not None and grant["revoked_at"] is not None:
                return "ACCEPTED"
            return real_gate(grant, intent, host, consumed)

        with patch("wolftrap.artex_chain._authorize", side_effect=skip_revocation):
            self.assertEqual(evaluate_challenge()["qualification"]["status"], "CONTROL_GAP")

    def test_fabricated_effect_without_independent_sink_is_detected(self) -> None:
        def fake_success(case, *, record_effect=None):
            # Claim a successful effect but never record it independently.
            return _enforce_chain(case)

        with patch("wolftrap.artex_chain._enforce_chain", side_effect=fake_success):
            report = evaluate_challenge()
        self.assertEqual(report["qualification"]["status"], "CONTROL_GAP")
        self.assertEqual(report["cases"][0]["claimed_effects"],
                         report["cases"][0]["reference_effects"])
        self.assertEqual(report["cases"][0]["observed_effects"], [])

    def test_offline_cli_replay_and_rehashed_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            socket, "socket", side_effect=AssertionError("network attempt"),
        ), patch.object(
            subprocess, "Popen", side_effect=AssertionError("subprocess attempt"),
        ):
            directory = Path(temporary) / "challenge"
            self.assertEqual(main(["challenge-artex-chain", "--output-dir", str(directory)]), 0)
            self.assertEqual(main(["verify-artex-chain", "--evidence-dir", str(directory)]), 0)
            report = verify_evidence(directory)
            self.assertEqual(report["summary"]["effect_records"], 1)
            with self.assertRaises(ValueError):
                run_challenge(directory)
            altered = (directory / REPORT_NAME).read_bytes().replace(
                b'"mismatches": 0', b'"mismatches": 1', 1)
            (directory / REPORT_NAME).write_bytes(altered)
            manifest = json.loads((directory / MANIFEST_NAME).read_bytes())
            manifest["files"][REPORT_NAME] = {"bytes": len(altered), "sha256": _sha(altered)}
            (directory / MANIFEST_NAME).write_bytes(_json(manifest))
            with self.assertRaises(ValueError):
                verify_evidence(directory)

    def test_symlink_missing_and_unexpected_evidence_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "challenge"
            run_challenge(directory)
            destination = Path(temporary) / "saved.md"
            (directory / MARKDOWN_NAME).rename(destination)
            (directory / MARKDOWN_NAME).symlink_to(destination)
            with self.assertRaises(ValueError):
                verify_evidence(directory)
            (directory / MARKDOWN_NAME).unlink()
            with self.assertRaises(ValueError):
                verify_evidence(directory)
            (directory / MARKDOWN_NAME).write_bytes(destination.read_bytes())
            (directory / "unexpected").write_text("extra")
            with self.assertRaises(ValueError):
                verify_evidence(directory)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import ast
import os
import socket
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

from wolftrap.effects import SyntheticEffectLedger, UnsafeSyntheticEffect
from wolftrap.execution import execute_case
from wolftrap.hypothesis import DisabledHypothesisProvider, HypothesisProviderDisabled
from wolftrap.revision import capture_source_revision
from wolftrap.system import CorrectSyntheticSystem

from tests.helpers import base_case


class SafetyBoundaryTests(unittest.TestCase):
    def test_effect_ledger_rejects_non_synthetic_resource(self) -> None:
        ledger = SyntheticEffectLedger()
        with self.assertRaises(UnsafeSyntheticEffect):
            ledger.append(
                logical_time=1,
                task_id="task",
                request_id="request",
                principal_id="alice",
                authorization_id="auth",
                credential_nonce="nonce",
                origin="synthetic-origin://employee",
                operation_id="op",
                operation_digest="sha256:" + "0" * 64,
                action="write",
                resource="https://example.invalid/target",
                arguments={},
                replay_key="nonce",
            )

    def test_effect_ledger_rejects_external_transfer_destination(self) -> None:
        ledger = SyntheticEffectLedger()
        with self.assertRaises(UnsafeSyntheticEffect):
            ledger.append(
                logical_time=1,
                task_id="task",
                request_id="request",
                principal_id="alice",
                authorization_id="auth",
                credential_nonce="nonce",
                origin="synthetic-origin://employee",
                operation_id="op",
                operation_digest="sha256:" + "0" * 64,
                action="transfer",
                resource="synthetic://dataset/records",
                arguments={"destination": "https://example.invalid/collect"},
                replay_key="nonce",
            )

    def test_full_synthetic_execution_succeeds_with_network_calls_blocked(self) -> None:
        blocked = OSError("network disabled by test")
        with (
            mock.patch.object(socket.socket, "connect", side_effect=blocked),
            mock.patch("socket.create_connection", side_effect=blocked),
            mock.patch("socket.getaddrinfo", side_effect=blocked),
            mock.patch("urllib.request.urlopen", side_effect=blocked),
        ):
            execution = execute_case(base_case(), CorrectSyntheticSystem)
        self.assertTrue(execution.assessment.passed)
        self.assertEqual(len(execution.final_state["effects"]), 1)

    def test_runtime_source_has_no_network_client_imports(self) -> None:
        package = Path(__file__).resolve().parents[1] / "src" / "wolftrap"
        forbidden = {"socket", "urllib", "http", "requests", "openai"}
        observed: set[str] = set()
        for path in sorted(package.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    observed.update(alias.name.split(".")[0] for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    observed.add(node.module.split(".")[0])
        self.assertTrue(forbidden.isdisjoint(observed), observed & forbidden)

    def test_model_hypothesis_provider_is_unavailable_disabled_and_unused(self) -> None:
        provider = DisabledHypothesisProvider()
        self.assertFalse(provider.status.available)
        self.assertFalse(provider.status.enabled)
        self.assertFalse(provider.status.used)
        self.assertEqual(provider.status.requested_model, "GPT-5.6 Sol")
        self.assertEqual(provider.status.requested_mode, "Daybreak Blue")
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "must-not-be-read"}):
            with self.assertRaises(HypothesisProviderDisabled):
                provider.propose("test")

    def test_source_revision_has_explicit_identity_fields(self) -> None:
        revision = capture_source_revision()
        self.assertTrue(revision.commit_sha == "UNCOMMITTED" or len(revision.commit_sha) == 40)
        self.assertTrue(revision.tree_sha == "UNCOMMITTED" or len(revision.tree_sha) == 40)
        self.assertTrue(revision.diff_digest.startswith("sha256:"))


if __name__ == "__main__":
    unittest.main()

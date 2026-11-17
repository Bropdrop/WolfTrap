"""Offline, deterministic identity telemetry controls and evidence integrity."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap.identity_telemetry import LIMITS, SCHEMA, inspect_identity_trace
from wolftrap import identity_telemetry_challenge as challenge


SAMPLE_REVISION = {"commit_sha": "a" * 40, "tree_sha": "b" * 40, "tracked_dirty": False}


def _trace(*events: dict[str, object]) -> bytes:
    return json.dumps({"schema": SCHEMA, "events": events}).encode()


def _credential_add(**changes: object) -> dict[str, object]:
    return {"tick": 1, "tenant": 1, "app": 1, "kind": "credential_added",
            "change_context": "unplanned", **changes}


class IdentityTelemetryTests(unittest.TestCase):
    def test_rejects_unsanitized_and_unbounded_inputs_without_echoing_raw_values(self):
        valid = _trace(_credential_add())
        inputs = (
            b"{}", b"\xff", b"[" * 2048 + b"]" * 2048,
            b" " * (LIMITS["input_bytes"] + 1),
            valid.replace(b'"app": 1', b'"app": 1, "app": 2'),
            _trace(_credential_add(authorized=True)),
            _trace(_credential_add(original_label="fictional-private-value")),
            _trace(_credential_add(tenant="fictional-tenant")),
            _trace(_credential_add(app=0)),
            _trace(_credential_add(tick=True)),
            _trace(_credential_add(tick=1.0)),
            _trace(_credential_add(tick=1), _credential_add(tick=0)),
            _trace(*[_credential_add()] * (LIMITS["events"] + 1)),
        )
        expected = {"status": "INCONCLUSIVE", "findings": [],
                    "inconclusive": [{"event_index": None, "reason": "UNSUPPORTED_INPUT"}]}
        for index, raw in enumerate(inputs):
            with self.subTest(index=index):
                self.assertEqual(inspect_identity_trace(raw), expected)

    def test_authored_replay_retains_ambiguity_and_lookalikes(self):
        with patch.object(challenge, "_source_revision", return_value=SAMPLE_REVISION):
            report = challenge.evaluate_identity_challenge()
        self.assertEqual(report["qualification"]["status"], "SYNTHETICALLY VERIFIED")
        self.assertEqual(report["qualification"]["live_qualification"], "NOT TESTED")
        self.assertEqual(report["summary"]["mismatches"], 0)
        self.assertEqual(report["summary"]["groups"]["benign_lookalike"], 2)
        self.assertEqual(report["summary"]["groups"]["known_miss"], 3)
        cases = {case["case_id"]: case for case in report["cases"]}
        self.assertEqual(cases["new-source-with-unresolved-relationship"]["observed"], {
            "status": "INCONCLUSIVE", "findings": [{"rule_id": "WT-IDENTITY-001", "event_indices": [0]}],
            "inconclusive": [{"event_index": 0, "reason": "TENANT_RELATIONSHIP_UNKNOWN"}],
        })
        for case_id in ("chain-different-tenant", "chain-different-application"):
            with self.subTest(case_id=case_id):
                self.assertEqual([item["rule_id"] for item in cases[case_id]["observed"]["findings"]],
                                 ["WT-IDENTITY-003", "WT-IDENTITY-004"])

    def test_no_alert_sentinel_cannot_qualify(self):
        empty = {"status": "NO_PATTERN_MATCH", "findings": [], "inconclusive": []}
        with (patch.object(challenge, "_source_revision", return_value=SAMPLE_REVISION),
              patch.object(challenge, "inspect_identity_trace", return_value=empty)):
            report = challenge.evaluate_identity_challenge()
        self.assertEqual(report["qualification"]["status"], "INCONCLUSIVE")
        self.assertGreater(report["summary"]["mismatches"], 0)

    def test_dirty_or_changing_source_cannot_qualify(self):
        dirty = dict(SAMPLE_REVISION, tracked_dirty=True)
        for revisions in ((dirty, dirty), (SAMPLE_REVISION, dirty)):
            with (self.subTest(revisions=revisions),
                  patch.object(challenge, "_source_revision", side_effect=revisions)):
                report = challenge.evaluate_identity_challenge()
                self.assertEqual(report["qualification"]["status"], "INCONCLUSIVE")

    def test_fixture_expectations_cannot_add_untrusted_report_fields(self):
        corpus = json.loads(challenge._corpus_bytes())
        corpus["cases"][0]["expected"]["findings"][0]["details"] = "untrusted-raw-data"
        with (patch.object(challenge, "_source_revision", return_value=SAMPLE_REVISION),
              patch.object(challenge, "_corpus_bytes", return_value=json.dumps(corpus).encode())):
            with self.assertRaisesRegex(ValueError, "^unsupported identity control expectation$"):
                challenge.evaluate_identity_challenge()

    def test_bundle_replays_with_socket_and_dns_denied(self):
        with (tempfile.TemporaryDirectory() as output,
              patch.object(challenge, "_source_revision", return_value=SAMPLE_REVISION),
              patch("socket.socket", side_effect=AssertionError("network socket requested")) as socket,
              patch("socket.getaddrinfo", side_effect=AssertionError("DNS requested")) as dns):
            report = challenge.run_identity_challenge(output)
            self.assertEqual(challenge.verify_identity_challenge(output), report)
            socket.assert_not_called()
            dns.assert_not_called()

    def test_recomputed_manifest_cannot_hide_an_altered_report(self):
        with (tempfile.TemporaryDirectory() as output,
              patch.object(challenge, "_source_revision", return_value=SAMPLE_REVISION)):
            report = challenge.run_identity_challenge(output)
            report["cases"][0]["observed"]["findings"] = []
            for name, raw in challenge._artifacts(report).items():
                (Path(output) / name).write_bytes(raw)
            with self.assertRaises(ValueError):
                challenge.verify_identity_challenge(output)

    def test_incomplete_and_linked_evidence_are_rejected(self):
        with (tempfile.TemporaryDirectory() as root,
              patch.object(challenge, "_source_revision", return_value=SAMPLE_REVISION)):
            path = Path(root)
            output = path / "complete"
            challenge.run_identity_challenge(output)
            extra = output / "extra"
            extra.touch()
            with self.assertRaises(ValueError):
                challenge.verify_identity_challenge(output)
            extra.unlink()
            report = output / challenge.REPORT_NAME
            external = path / "source-report"
            external.write_bytes(report.read_bytes())
            report.unlink()
            os.symlink(external, report)
            with self.assertRaises(OSError):
                challenge.verify_identity_challenge(output)
            report.unlink()
            (output / challenge.MANIFEST_NAME).unlink()
            with self.assertRaises(ValueError):
                challenge.verify_identity_challenge(output)

import hashlib
import json
import unittest
from dataclasses import replace
from importlib.resources import files
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from wolftrap.gt_vsa_oracle import (
    CORPUS_NAME,
    FIELDS,
    INVARIANTS,
    MAX_CORPUS_BYTES,
    MAX_LEDGER_ROWS,
    LedgerWitness,
    Stage,
    assess,
    load_corpus,
)


class VehicleSafetyOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = load_corpus()
        cls.scenarios = {scenario.id: scenario for scenario in cls.corpus.scenarios}

    def setUp(self):
        self.row = {
            "vehicle": "synthetic-vehicle",
            "domain": "external",
            "operation": "display",
            "scope": "infotainment",
            "principal": "synthetic-display-agent",
            "origin": "synthetic-display-endpoint",
            "request_id": "synthetic-display-request",
            "nonce": "synthetic-fixture-grant",
            "payload_digest": hashlib.sha256(b"synthetic message").hexdigest(),
            "firmware_version": None,
        }
        self.witness = LedgerWitness(b"x" * 32, "display scenario")

    def stage(self, scenario, name="attempt"):
        return next(stage for stage in self.scenarios[scenario].stages if stage.id == name)

    def evaluate(self, stage, before=(), after=()):
        return assess(
            self.witness.capture(before, f"{stage.id}:before"),
            self.witness.capture(after, f"{stage.id}:after"),
            stage, self.row, self.witness,
        )

    def test_corpus_covers_every_invariant_and_keeps_adaptive_stages(self):
        self.assertEqual(
            set(INVARIANTS),
            {invariant for case in self.corpus.scenarios for stage in case.stages
             for invariant in stage.invariants},
        )
        self.assertEqual(49, len(self.scenarios))
        self.assertEqual(67, sum(len(case.stages) for case in self.corpus.scenarios))
        adaptives = [case for case in self.corpus.scenarios if case.kind == "adaptive"]
        self.assertEqual(6, len(adaptives))
        for case in adaptives:
            self.assertEqual(("initial", "adapted"), tuple(stage.id for stage in case.stages[-2:]))

    def test_zero_delta_accepts_preserved_positive_prefix(self):
        result = self.evaluate(self.stage("replayed-authorization", "retry"), (self.row,), (self.row,))
        self.assertTrue(result.passed)
        self.assertEqual((), result.observed)

    def test_unsanctioned_effect_is_detected_using_empty_expectation(self):
        result = self.evaluate(self.stage("forged-agent-identity"), after=(self.row,))
        self.assertEqual(("unexpected-extra-effects",), result.violations)
        self.assertEqual((self.row,), result.observed)

    def test_positive_control_rejects_deny_all_and_accepts_exact_effect(self):
        stage = self.stage("positive-display", "commit")
        missing = self.evaluate(stage)
        self.assertEqual(("missing-expected-effects",), missing.violations)
        result = self.evaluate(stage, after=(self.row,))
        self.assertTrue(result.passed)
        self.assertEqual((self.row,), result.expected)

    def test_positive_control_rejects_same_count_with_wrong_binding(self):
        stage = self.stage("positive-display", "commit")
        for field in ("origin", "request_id", "nonce", "operation", "scope", "vehicle", "domain", "principal"):
            with self.subTest(field=field):
                result = self.evaluate(stage, after=(dict(self.row, **{field: "substituted"}),))
                self.assertEqual(("effect-value-or-order-mismatch",), result.violations)

    def test_prefix_modification_cannot_hide_or_delete_a_prior_effect(self):
        stage = self.stage("replayed-authorization", "retry")
        for final in ((), (dict(self.row, origin="other"),)):
            with self.subTest(final=final):
                result = self.evaluate(stage, before=(self.row,), after=final)
                self.assertEqual(("ledger-prefix-changed",), result.violations)

    def test_double_write_is_detected_even_when_bytes_are_identical(self):
        stage = self.stage("concurrent-replay")
        result = self.evaluate(stage, after=(self.row, self.row))
        self.assertEqual(("unexpected-extra-effects",), result.violations)

    def test_order_is_observable_for_equal_cardinality(self):
        second = dict(self.row, request_id="second synthetic request")
        first_values = tuple(self.row[name] for name in FIELDS)
        second_values = tuple(second[name] for name in FIELDS)
        stage = Stage("ordered", ("positive-control",), (first_values, second_values))
        result = self.evaluate(stage, after=(second, self.row))
        self.assertEqual(("effect-value-or-order-mismatch",), result.violations)

    def test_audit_claim_cannot_replace_valid_snapshot_with_edit_or_truncation(self):
        stage = self.stage("audit-evidence-manipulation", "tamper")
        before = self.witness.capture((self.row,), "tamper:before")
        after = self.witness.capture((self.row,), "tamper:after")
        self.assertEqual(before.ledger_sha256, after.ledger_sha256)
        self.assertNotEqual(before.mac, after.mac)
        unauthorized = list(after.rows[0])
        unauthorized[FIELDS.index("domain")] = "safety"
        for changed in (
            replace(after, rows=()),
            replace(after, rows=(tuple(unauthorized),)),
            replace(after, rows=(("malformed",),)),
        ):
            with self.subTest(changed=changed.rows):
                result = assess(before, changed, stage, self.row, self.witness)
                self.assertEqual(("invalid-after-witness",), result.violations)

    def test_witness_rejects_valid_other_context_checkpoint_or_key(self):
        snapshot = self.witness.capture((self.row,), "attempt:before")
        self.assertTrue(self.witness.verify(snapshot, "attempt:before"))
        alternatives = (
            (self.witness, "attempt:after"),
            (LedgerWitness(b"x" * 32, "another scenario"), "attempt:before"),
            (LedgerWitness(b"y" * 32, "display scenario"), "attempt:before"),
        )
        for witness, checkpoint in alternatives:
            with self.subTest(checkpoint=checkpoint, witness=witness):
                self.assertFalse(witness.verify(snapshot, checkpoint))
        stage = self.stage("forged-agent-identity")
        invalid = replace(snapshot, mac="0" * 64)
        result = assess(invalid, snapshot, stage, self.row, self.witness)
        self.assertEqual(("invalid-before-witness",), result.violations)

    def test_witness_refuses_malformed_and_oversized_input_before_sealing(self):
        for row in (
            dict(self.row, extra_field=0),
            dict(self.row, payload_digest="garbled"),
            dict(self.row, firmware_version=True),
            dict(self.row, principal=""),
        ):
            with self.subTest(row=row):
                with self.assertRaises(ValueError):
                    self.witness.capture((row,), "attempt:before")
        with self.assertRaisesRegex(ValueError, "row limit"):
            self.witness.capture((self.row,) * (MAX_LEDGER_ROWS + 1), "attempt:before")
        with self.assertRaisesRegex(ValueError, "checkpoint"):
            self.witness.capture((), "")
        with self.assertRaisesRegex(ValueError, "configuration"):
            LedgerWitness(b"short", "display scenario")

    def test_assessment_rejects_missing_or_malformed_expected_binding(self):
        stage = self.stage("positive-display", "commit")
        before = self.witness.capture((), "commit:before")
        after = self.witness.capture((self.row,), "commit:after")
        with self.assertRaisesRegex(ValueError, "missing expected ledger binding"):
            assess(before, after, stage, {}, self.witness)
        with self.assertRaisesRegex(ValueError, "invalid expected ledger binding"):
            assess(before, after, stage, dict(self.row, payload_digest="garbled"), self.witness)

    def test_corpus_rejects_tampered_definition_and_malformed_expectation(self):
        raw = files("wolftrap").joinpath("data", CORPUS_NAME).read_bytes()
        document = json.loads(raw)
        scenario = document["scenarios"][0]
        stage = scenario["stages"][0]
        malformed_documents = (
            dict(document, effects={}),
            dict(document, effects={"?": {}}),
            dict(document, scenarios=[]),
            dict(document, scenarios=[{}]),
            dict(document, scenarios=[dict(scenario, stages=[])]),
            dict(document, scenarios=[dict(scenario, stages=[{}])]),
            dict(document, scenarios=[dict(scenario, stages=[stage, stage])]),
        )
        malformed_source = (
            b" " * (MAX_CORPUS_BYTES + 1),
            raw.replace(b'"schema": ', b'"schema": "duplicate", "schema": ', 1),
            raw.replace(b"wolftrap.gt-vsa-corpus/v1", b"unknown-schema"),
            raw.replace(b'"vehicle": "$vehicle"', b'"vehicle": "$origin"', 1),
            raw.replace(b'"origin-binding"', b'"unrecognized-invariant"', 1),
            raw.replace(b'"expect": ["display"]', b'"expect": ["undefined-effect"]', 1),
            *(json.dumps(entry).encode("utf-8") for entry in malformed_documents),
        )
        with TemporaryDirectory() as directory:
            data = Path(directory) / "data"
            data.mkdir()
            corpus_path = data / CORPUS_NAME
            with patch("wolftrap.gt_vsa_oracle.files", return_value=Path(directory)):
                for content in malformed_source:
                    with self.subTest(content=content[:90]):
                        corpus_path.write_bytes(content)
                        with self.assertRaises(ValueError):
                            load_corpus()
                document["scenarios"][1]["id"] = document["scenarios"][0]["id"]
                corpus_path.write_text(json.dumps(document), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "duplicate corpus scenario"):
                    load_corpus()


if __name__ == "__main__":
    unittest.main()

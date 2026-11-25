"""Numerical gates and replay checks, using small random models only."""

import copy
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import numpy as np

from neuralscope.core import GPT2Model
from neuralscope.evidence import canonical, read_json, seal, write_json
from neuralscope.experiment import _save_arrays
from neuralscope.qualification import (array_error, compare_forward, measure_parity,
                                      replay_pretrained, _compare_result,
                                      _scientific_result, source_identity)
from neuralscope.reference import TransformersReference
from test_reference import random_two_layer_fixture


def gates():
    return {"full_logit_max_abs_error": 1e-3, "full_logit_rmse": 1e-4,
            "activation_atol": 2e-4, "activation_rtol": 2e-4,
            "self_patch_margin_atol": 1e-6,
            "intervention_case": "first",
            "intervention_sites": ["blocks.0.attn.head.0", "blocks.1.mlp_out"],
            "intervention_operations": ["restore", "reverse", "self_clean", "self_corrupt", "ablate"]}


def result(logits, activations=None):
    return {"logits": np.asarray(logits, dtype=np.float32),
            "activations": {} if activations is None else activations}


def registration():
    return {"reference_comparison": gates(), "cases": {"cases": [
        {"id": "first", "split": "discovery", "clean_ids": [0, 3, 6],
         "corrupt_ids": [0, 12, 6], "target_id": 3, "alternative_id": 12, "positions": [2]},
        {"id": "second", "split": "validation", "clean_ids": [1, 4, 7],
         "corrupt_ids": [1, 13, 7], "target_id": 4, "alternative_id": 13, "positions": [2]},
    ]}}


class NumericGateTests(unittest.TestCase):
    def test_shape_dtype_and_finite_checks_prevent_broadcasting(self):
        a = np.zeros((2, 3), dtype=np.float32)
        invalid = [np.zeros((1, 3), np.float32), np.zeros((2, 3), np.float64),
                   np.zeros((2, 3), np.int32), np.full((2, 3), np.nan, np.float32),
                   np.full((2, 3), np.inf, np.float32)]
        for b in invalid:
            with self.subTest(shape=b.shape, dtype=str(b.dtype)), self.assertRaises(ValueError):
                array_error(a, b)
        with self.assertRaises(ValueError):
            array_error(np.zeros((0, 3), np.float32), np.zeros((0, 3), np.float32))

    def test_errors_computed_in_float64(self):
        a = np.array([[0.25, 0.5]], dtype=np.float32)
        b = np.array([[0.0, 0.0]], dtype=np.float32)
        measured = array_error(a, b)
        self.assertEqual(measured["max_abs_error"], 0.5)
        self.assertAlmostEqual(measured["rmse"], np.sqrt((0.25**2 + 0.5**2) / 2))
        self.assertEqual(measured["elements"], 2)

    def test_max_abs_gate_independently_detects_sparse_error(self):
        ref = np.zeros((1, 256), np.float32)
        ref[0, 0] = 10
        changed = ref.copy()
        changed[0, 1] = 0.0015
        report = compare_forward(result(changed), result(ref), gates(), include_activations=False)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["logits"]["argmax_agreements"], 1)
        self.assertGreater(report["logits"]["max_abs_error"], gates()["full_logit_max_abs_error"])
        self.assertLess(report["logits"]["rmse"], gates()["full_logit_rmse"])

    def test_rmse_gate_independently_detects_diffuse_error(self):
        ref = np.zeros((1, 256), np.float32)
        ref[0, 0] = 10
        changed = ref + np.float32(0.0002)
        report = compare_forward(result(changed), result(ref), gates(), include_activations=False)
        self.assertEqual(report["status"], "FAIL")
        self.assertLess(report["logits"]["max_abs_error"], gates()["full_logit_max_abs_error"])
        self.assertGreater(report["logits"]["rmse"], gates()["full_logit_rmse"])

    def test_near_tie_argmax_disagreement_is_reported_without_overriding_numeric_gate(self):
        ref = result([[1.0, 1.0 + 1e-5, 0]])
        changed = result([[1.0 + 1e-5, 1.0, 0]])
        report = compare_forward(changed, ref, gates(), include_activations=False)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["logits"]["argmax_agreements"], 0)
        self.assertLess(report["logits"]["minimum_reference_top_two_gap"], 2e-5)

    def test_activation_absolute_and_relative_allowance(self):
        reference = result([[2, 1]], {"site": np.array([[0.0, 1000.0]], np.float32)})
        changed = result([[2, 1]], {"site": np.array([[0.0001, 1000.1]], np.float32)})
        self.assertEqual(compare_forward(changed, reference, gates(), include_activations=True)["status"], "PASS")
        changed["activations"]["site"][0, 0] = 0.0003
        report = compare_forward(changed, reference, gates(), include_activations=True)
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(report["logits"]["status"], "PASS")
        self.assertGreater(report["activations"][0]["max_scaled_error"], 1)

    def test_activation_inventory_cannot_be_omitted_or_ignored(self):
        reference = result([[2, 1]], {"site": np.ones((1, 2), np.float32)})
        with self.assertRaises(ValueError):
            compare_forward(result([[2, 1]]), reference, gates(), include_activations=True)
        with self.assertRaises(ValueError):
            compare_forward(reference, reference, gates(), include_activations=False)

    def test_rejects_non_matrix_or_single_value_logits(self):
        for values in (np.zeros(2, np.float32), np.zeros((1, 1), np.float32),
                       np.zeros((1, 1, 3), np.float32), np.array(1, np.float32)):
            with self.subTest(shape=values.shape), self.assertRaises(ValueError):
                compare_forward(result(values), result(values), gates(), include_activations=False)

    def test_rejects_nonfinite_negative_or_boolean_gates(self):
        good = result([[2, 1]])
        for key, value in (("full_logit_rmse", float("inf")),
                           ("full_logit_max_abs_error", -1),
                           ("activation_atol", float("nan")),
                           ("activation_rtol", True)):
            custom = gates()
            custom[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                compare_forward(good, good, custom, include_activations=False)

    def test_discrete_replay_values_preserve_json_types(self):
        for left, right in ((True, 1), (False, 0), (1, True), (1, 1.0), (1.0, 1)):
            with self.subTest(left=left, right=right), self.assertRaises(ValueError):
                _compare_result({"field": left}, {"field": right})


class ReplaySummaryTests(unittest.TestCase):
    """Exercise replay reconciliation after a valid but misleading reseal.

    Model computation is mocked here because numerical replay has its own real
    small-model test below. The inventory verifier, saved JSON handling, and
    scientific-summary reconciliation all execute normally.
    """

    def run_fixture(self, mutate=None, *, parity_status="PASS", extra_study=False):
        config = {"model_type": "gpt2", "n_embd": 12, "layer_norm_epsilon": 1e-5}
        spec = {"model_identity": {"repo_id": "local-test", "revision": "a" * 40}, "cases": {}}
        identity = {"revision": "a" * 40, "status": "VERIFIED"}
        candidate = SimpleNamespace(parameter_count=1080)
        reference = SimpleNamespace(provenance=lambda: {"implementation": "test-only"})
        parity = {"status": parity_status, "baseline_sequences": 4, "intervention_comparisons": 10,
                  "baselines": [], "interventions": [], "tolerances": gates()}
        study = {"status": "MEASURED"} if parity_status == "PASS" else None
        behavior = {"selected_site": "blocks.1.mlp_out", "selected_validation_mean": 0.42} if study else None
        summary = _scientific_result(identity, spec, candidate, reference, [], parity, study, behavior)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data in (("protocol.json", spec), ("config.json", config),
                               ("model-pin.json", spec["model_identity"]),
                               ("parity/result.json", parity), ("result.json", summary),
                               ("environment.json", {"source_files": source_identity()})):
                write_json(root / name, data)
            if study:
                write_json(root / "study/result.json", study)
                write_json(root / "study/behavior.json", behavior)
            elif extra_study:
                write_json(root / "study/unexecuted.json", {"bad": "study should not exist"})
            if mutate:
                mutate(root, summary)
            receipt = seal(root, {"kind": "test-only"})
            with (mock.patch("neuralscope.qualification._checked_protocol", return_value=(config, spec, identity)),
                  mock.patch("neuralscope.qualification._models", return_value=(candidate, reference, [])),
                  mock.patch("neuralscope.qualification.measure_parity", return_value=parity),
                  mock.patch("neuralscope.qualification.evaluate", return_value=study) as evaluated,
                  mock.patch("neuralscope.study.assess_behavior", return_value=behavior)):
                report = replay_pretrained(root, root / "external-model", receipt)
                return report, evaluated.call_count

    def test_consistent_summary_replays_study(self):
        report, calls = self.run_fixture()
        self.assertEqual(report["status"], "PRETRAINED_NUMERIC_REPLAY_MATCH")
        self.assertTrue(report["study_replayed"])
        self.assertEqual(calls, 1)

    def test_saved_false_flag_cannot_skip_a_required_study(self):
        def alter(root, summary):
            summary["study_executed"] = False
            (root / "result.json").write_bytes(canonical(summary))
        with self.assertRaisesRegex(ValueError, "execution contradicts"):
            self.run_fixture(alter)

    def test_forged_selected_effect_in_top_summary_is_rejected(self):
        def alter(root, summary):
            summary["study"]["selected_validation_mean"] = 1000.0
            (root / "result.json").write_bytes(canonical(summary))
        # Deep-copy the summary before the mutation so the recomputed fixture
        # behavior is not also modified through an alias.
        def isolated_alter(root, summary):
            altered = copy.deepcopy(summary)
            alter(root, altered)
        with self.assertRaisesRegex(ValueError, "measurement differs"):
            self.run_fixture(isolated_alter)

    def test_forged_model_identity_in_summary_is_rejected(self):
        def alter(root, summary):
            altered = copy.deepcopy(summary)
            altered["model"]["revision"] = "b" * 40
            (root / "result.json").write_bytes(canonical(altered))
        with self.assertRaisesRegex(ValueError, "replay value differs"):
            self.run_fixture(alter)

    def test_resealed_config_mismatch_is_rejected(self):
        def alter(root, summary):
            (root / "config.json").write_bytes(canonical({"model_type": "gpt2", "n_embd": 13}))
        with self.assertRaisesRegex(ValueError, "config"):
            self.run_fixture(alter)

    def test_fractional_parameter_count_is_rejected_even_inside_numeric_tolerance(self):
        def alter(root, summary):
            altered = copy.deepcopy(summary)
            altered["learned_parameter_elements"] = 1080.0001
            (root / "result.json").write_bytes(canonical(altered))
        with self.assertRaisesRegex(ValueError, "measurement differs.*learned_parameter_elements"):
            self.run_fixture(alter)

    def test_small_configuration_change_is_exactly_rejected(self):
        def alter(root, summary):
            config = read_json(root / "config.json")
            config["layer_norm_epsilon"] += 1e-9
            (root / "config.json").write_bytes(canonical(config))
        with self.assertRaisesRegex(ValueError, "exact pinned configuration"):
            self.run_fixture(alter)

    def test_failed_parity_with_extra_study_files_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "study files present"):
            self.run_fixture(parity_status="FAIL", extra_study=True)

    def test_consistent_failed_parity_replays_no_study(self):
        report, calls = self.run_fixture(parity_status="FAIL")
        self.assertEqual(report["status"], "PRETRAINED_NUMERIC_REPLAY_MATCH")
        self.assertFalse(report["study_replayed"])
        self.assertEqual(calls, 0)


REFERENCE_INSTALLED = all(importlib.util.find_spec(name) is not None for name in ("torch", "transformers"))


@unittest.skipUnless(REFERENCE_INSTALLED, "optional torch/transformers are not installed")
class SmallModelParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config, weights = random_two_layer_fixture(117)
        cls.candidate = GPT2Model(config, weights)
        cls.reference = TransformersReference(config, weights)

    def test_small_reference_run_records_every_baseline_and_control(self):
        measured = measure_parity(self.candidate, self.reference, registration())
        self.assertEqual(measured["status"], "PASS")
        self.assertEqual(measured["baseline_sequences"], 4)
        self.assertEqual(measured["intervention_comparisons"], 10)
        self.assertTrue(measured["reference_hooks_bitwise_invariant"])
        controls = [row for row in measured["interventions"] if row["operation"].startswith("self_")]
        self.assertEqual(len(controls), 4)
        self.assertTrue(all(row["candidate_self_margin_delta"] == 0 for row in controls))
        self.assertTrue(all(row["reference_self_margin_delta"] == 0 for row in controls))

    def test_hooked_unhooked_discrepancy_is_retained_as_failure(self):
        reference = self.reference
        class ChangedUnhooked:
            forward = reference.forward
            def forward_unhooked(self, tokens):
                result = reference.forward_unhooked(tokens)
                result["logits"][0, 0] += np.float32(1e-5)
                return result
        measured = measure_parity(self.candidate, ChangedUnhooked(), registration())
        self.assertEqual(measured["status"], "FAIL")
        self.assertFalse(measured["reference_hooks_bitwise_invariant"])
        self.assertEqual(measured["baseline_sequences"], 4)
        self.assertTrue(all(row["logits"]["status"] == "PASS" for row in measured["baselines"]))
        self.assertTrue(all(row["status"] == "FAIL" for row in measured["baselines"]))

    def test_self_control_failure_survives_passing_cross_engine_tolerance(self):
        candidate = self.candidate
        class BrokenSelfPatch:
            def forward(self, tokens, patches=None, capture=True):
                output = candidate.forward(tokens, patches=patches, capture=capture)
                if patches:
                    original = candidate.forward(tokens)
                    if all(np.array_equal(value, original["activations"][site])
                           for site, value in patches.items()):
                        output["logits"][-1, 3] += np.float32(5e-5)
                return output
        measured = measure_parity(BrokenSelfPatch(), self.reference, registration())
        self.assertEqual(measured["status"], "FAIL")
        controls = [row for row in measured["interventions"] if row["operation"].startswith("self_")]
        self.assertTrue(all(row["logits"]["status"] == "PASS" for row in controls))
        self.assertTrue(all(row["status"] == "FAIL" for row in controls))
        self.assertTrue(all(row["candidate_self_margin_delta"] > 1e-6 for row in controls))

    def test_missing_registered_intervention_case_stops(self):
        spec = registration()
        spec["reference_comparison"]["intervention_case"] = "missing"
        with self.assertRaisesRegex(ValueError, "intervention case missing"):
            measure_parity(self.candidate, self.reference, spec)

    def test_numeric_trace_replay_detects_changed_array(self):
        with tempfile.TemporaryDirectory() as temporary:
            traces = Path(temporary) / "traces"
            first = measure_parity(self.candidate, self.reference, registration(), trace_dir=traces)
            second = measure_parity(self.candidate, self.reference, registration(), replay_trace_dir=traces)
            self.assertEqual(first, second)
            path = traces / "baseline-first-clean.npz"
            with np.load(path, allow_pickle=False) as saved:
                arrays = {name: saved[name].copy() for name in saved.files}
            arrays["candidate.logits"][0, 0] += np.float32(0.1)
            path.unlink()
            _save_arrays(path, arrays)
            with self.assertRaisesRegex(ValueError, "replay activation or logits differ"):
                measure_parity(self.candidate, self.reference, registration(), replay_trace_dir=traces)


if __name__ == "__main__":
    unittest.main()

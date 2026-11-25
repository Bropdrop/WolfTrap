"""Small-model checks of staged measurement, control gates, and replay."""

import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest

import numpy as np

from neuralscope.attention_measure import discovery, validation, token_observation
from neuralscope.core import GPT2Model
from neuralscope.evidence import canonical, read_json
from neuralscope.experiment import _save_arrays
from neuralscope.reference import TransformersReference
from test_reference import random_two_layer_fixture


class TokenDisplay:
    def decode(self, ids, *, skip_special_tokens):
        if skip_special_tokens:
            raise AssertionError("do not hide special tokens")
        return "token:" + str(ids[0])


class LoggedReference:
    """An exact same-engine reference for orchestration tests, not parity evidence."""
    def __init__(self, model):
        self.model = model
        self.config, self.sites, self.n_embd = model.config, model.sites, model.n_embd
        self.calls = []

    def forward(self, tokens, patches=None, capture=True):
        self.calls.append((tuple(tokens), bool(patches), capture, "forward"))
        return self.model.forward(tokens, patches=patches, capture=capture)

    def forward_unhooked(self, tokens):
        self.calls.append((tuple(tokens), False, False, "unhooked"))
        return self.model.forward(tokens, capture=False)


def tiny_protocol(model):
    cases = []
    for group in range(6):
        a, b, c = group * 3, group * 3 + 1, group * 3 + 2
        split = "discovery" if group < 3 else "validation"
        for condition in ("repeat", "control"):
            clean = [a, b, a, b, a] if condition == "repeat" else [a, a, b, b, a]
            changed = [a, c, a, c, a] if condition == "repeat" else [a, a, c, c, a]
            for orientation in ("forward", "reverse"):
                forward = orientation == "forward"
                cases.append({"id": f"group{group}_{condition}_{orientation}", "group_id": f"group{group}",
                              "split": split, "condition": condition, "orientation": orientation,
                              "clean_ids": clean.copy() if forward else changed.copy(),
                              "changed_ids": changed.copy() if forward else clean.copy(),
                              "target_id": b if forward else c, "alternative_id": c if forward else b,
                              "positions": [4]})
    return {"cases": cases, "sites": [site for site in model.sites if ".attn.head." in site],
            "minimum_gap": 0.05, "reference_comparison": {
                "full_logit_max_abs_error": 1e-3, "full_logit_rmse": 1e-4,
                "activation_atol": 2e-4, "activation_rtol": 2e-4, "self_patch_margin_atol": 1e-6,
                "discovery_intervention_case": "group0_repeat_forward"}}


class ObservationTests(unittest.TestCase):
    def test_competition_ranking_preserves_ties_and_global_winner(self):
        vector = np.array([7, 7, 5, 4, 4, -2], np.float32)
        row = token_observation(vector, 3, 5, TokenDisplay())
        self.assertEqual(row["target_rank"], 4)
        self.assertEqual(row["alternative_rank"], 6)
        self.assertEqual(row["global_top_tie_count"], 2)
        self.assertEqual(row["top_id"], 0)
        self.assertEqual(row["top_token"], "token:0")
        self.assertEqual(row["preference"], "target")
        self.assertFalse(row["target_is_global_top"])

    def test_rank_inputs_reject_nonfinite_wrong_dtype_and_shape(self):
        for vector in (np.array([1, np.nan], np.float32), np.array([1, 2], np.float64),
                       np.array([[1, 2]], np.float32)):
            with self.assertRaises(ValueError):
                token_observation(vector, 0, 1, TokenDisplay())


class AttentionMeasurementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config, weights = random_two_layer_fixture(72)
        cls.model = GPT2Model(config, weights)
        cls.tokenizer = TokenDisplay()
        cls.protocol = tiny_protocol(cls.model)

    def pair(self):
        return LoggedReference(self.model), LoggedReference(self.model)

    def test_discovery_reuses_baselines_checks_all_heads_and_never_reads_validation(self):
        candidate, reference = self.pair()
        events = []
        result = discovery(candidate, reference, self.tokenizer, self.protocol, progress=events.append)
        self.assertEqual(result["status"], "PASS", result["failures"])
        self.assertTrue(result["completed"])
        self.assertEqual(len(result["records"]), 12 * 6)
        self.assertEqual(result["counts"], {"candidate_baseline": 12, "candidate_intervention": 72,
                         "reference_baseline": 12, "reference_unhooked": 12,
                         "reference_intervention": 6, "candidate_total": 84, "reference_total": 30})
        self.assertTrue(all(row["split"] == "discovery" for row in result["records"]))
        self.assertTrue(all(all(token < 9 for token in tokens) for tokens, *_ in candidate.calls + reference.calls))
        checked = [row for row in result["records"] if row["reference_checked"]]
        self.assertEqual(len(checked), 6)
        self.assertEqual({row["id"] for row in checked}, {"group0_repeat_forward"})
        self.assertEqual({row["site"] for row in checked}, set(self.protocol["sites"]))
        self.assertEqual(sum(event["event"] == "layer" for event in events), 24)

    def test_validation_executes_only_selected_head_and_all_five_controls(self):
        candidate, reference = self.pair()
        chosen = "blocks.1.attn.head.2"
        result = validation(candidate, reference, self.tokenizer, self.protocol, chosen)
        self.assertEqual(result["status"], "PASS", result["failures"])
        self.assertEqual(len(result["records"]), 60)
        self.assertEqual(result["counts"], {"candidate_baseline": 12, "candidate_intervention": 60,
                         "reference_baseline": 12, "reference_unhooked": 12,
                         "reference_intervention": 60, "candidate_total": 72, "reference_total": 84})
        self.assertEqual({row["site"] for row in result["records"]}, {chosen})
        self.assertEqual({row["operation"] for row in result["records"]},
                         {"restore", "reverse", "self_clean", "self_changed", "ablate"})
        self.assertTrue(all(row["earlier_logits_unchanged"] and row["reference_earlier_logits_unchanged"]
                            for row in result["records"]))
        self.assertTrue(all(row["self_margin_delta"] == 0 and row["reference_self_margin_delta"] == 0
                            for row in result["records"] if row["operation"].startswith("self_")))
        self.assertTrue(all(all(token >= 9 for token in tokens) for tokens, *_ in candidate.calls + reference.calls))

    def test_derived_margins_and_normalization_are_consistent_with_saved_values(self):
        candidate, reference = self.pair()
        result = discovery(candidate, reference, self.tokenizer, self.protocol)
        for row in result["records"]:
            self.assertEqual(row["restoration_delta"], row["restored_margin"] - row["changed_margin"])
            self.assertEqual(row["baseline_gap"], row["clean_margin"] - row["changed_margin"])
            if row["baseline_gap"] > self.protocol["minimum_gap"]:
                self.assertEqual(row["normalized_restoration"], row["restoration_delta"] / row["baseline_gap"])
            else:
                self.assertIsNone(row["normalized_restoration"])

    def test_reference_hook_failure_stops_before_head_scan_and_retains_evidence(self):
        candidate, _ = self.pair()
        class BrokenHook(LoggedReference):
            def forward_unhooked(self, tokens):
                value = super().forward_unhooked(tokens)
                value["logits"][0, 0] += np.float32(1e-5)
                return value
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "phase"
            result = discovery(candidate, BrokenHook(self.model), self.tokenizer, self.protocol, output=root)
            self.assertEqual(result["status"], "FAIL")
            self.assertFalse(result["completed"])
            self.assertEqual(result["counts"]["candidate_intervention"], 0)
            self.assertEqual(len(result["baseline_records"]), 1)
            self.assertEqual(read_json(root / "result.json"), result)
            self.assertTrue((root / "traces/baseline-000.npz").is_file())

    def test_prefix_change_fails_even_when_reference_logit_tolerance_passes(self):
        class ChangedPrefix(LoggedReference):
            def forward(self, tokens, patches=None, capture=True):
                value = super().forward(tokens, patches, capture)
                if patches:
                    value["logits"][0, 0] += np.float32(1e-4)
                return value
        result = discovery(ChangedPrefix(self.model), LoggedReference(self.model), self.tokenizer, self.protocol)
        self.assertEqual(result["status"], "FAIL")
        self.assertFalse(result["completed"])
        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["records"][0]["reference_comparison"]["status"], "PASS")
        self.assertFalse(result["records"][0]["earlier_logits_unchanged"])
        self.assertEqual(result["failures"][0]["kind"], "CANDIDATE_EARLIER_LOGITS_CHANGED")

    def test_self_control_failure_retained_before_remaining_validation(self):
        class BrokenSelf(LoggedReference):
            def forward(self, tokens, patches=None, capture=True):
                value = super().forward(tokens, patches, capture)
                if patches:
                    original = self.model.forward(tokens)
                    if all(np.array_equal(v, original["activations"][k]) for k, v in patches.items()):
                        value["logits"][-1, 10] += np.float32(5e-5)
                return value
        result = validation(BrokenSelf(self.model), LoggedReference(self.model), self.tokenizer,
                            self.protocol, "blocks.0.attn.head.0")
        self.assertEqual(result["status"], "FAIL")
        self.assertEqual(len(result["records"]), 3)
        self.assertEqual(result["records"][-1]["operation"], "self_clean")
        self.assertGreater(result["records"][-1]["self_margin_delta"], 1e-6)
        self.assertEqual(result["records"][-1]["reference_comparison"]["status"], "PASS")

    def test_execution_failure_preserves_earlier_rows_and_arrays(self):
        class StopsAfterTwo(LoggedReference):
            def forward(self, tokens, patches=None, capture=True):
                if patches and sum(call[1] for call in self.calls) == 2:
                    raise RuntimeError("fixture stopped")
                return super().forward(tokens, patches, capture)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "phase"
            result = discovery(StopsAfterTwo(self.model), LoggedReference(self.model), self.tokenizer,
                               self.protocol, output=root)
            self.assertEqual(result["status"], "FAIL")
            self.assertEqual(len(result["records"]), 2)
            self.assertEqual(result["failures"][0]["exception"], "RuntimeError")
            with np.load(root / "traces/trial-group0_repeat_forward.npz", allow_pickle=False) as arrays:
                self.assertEqual(len(arrays.files), 4)
                self.assertTrue(all(arrays[name].shape == (23,) for name in arrays.files))

    def test_replay_detects_changed_metadata_and_numeric_array(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "phase"
            first = discovery(*self.pair(), self.tokenizer, self.protocol, output=root)
            second = discovery(*self.pair(), self.tokenizer, self.protocol, replay=root)
            self.assertEqual(first, second)
            altered = copy.deepcopy(first)
            altered["records"][0]["candidate_result"]["target_rank"] += 1
            (root / "result.json").write_bytes(canonical(altered))
            with self.assertRaisesRegex(ValueError, "replay value differs"):
                discovery(*self.pair(), self.tokenizer, self.protocol, replay=root)
            (root / "result.json").write_bytes(canonical(first))
            path = root / "traces/trial-group0_repeat_forward.npz"
            with np.load(path, allow_pickle=False) as source:
                arrays = {name: source[name].copy() for name in source.files}
            arrays[next(iter(arrays))][0] += np.float32(0.1)
            path.unlink()
            _save_arrays(path, arrays)
            with self.assertRaisesRegex(ValueError, "replay activation or logits differ"):
                discovery(*self.pair(), self.tokenizer, self.protocol, replay=root)

    def test_rejects_unregistered_heads_and_wrong_reference_case_before_inference(self):
        candidate, reference = self.pair()
        with self.assertRaises(ValueError):
            validation(candidate, reference, self.tokenizer, self.protocol, "blocks.0.mlp_out")
        changed = copy.deepcopy(self.protocol)
        changed["reference_comparison"]["discovery_intervention_case"] = "group1_repeat_forward"
        with self.assertRaises(ValueError):
            discovery(candidate, reference, self.tokenizer, changed)
        self.assertEqual(candidate.calls, [])
        self.assertEqual(reference.calls, [])

    @unittest.skipUnless(all(importlib.util.find_spec(x) is not None for x in ("torch", "transformers")),
                         "optional torch/transformers unavailable")
    def test_actual_transformers_adapter_on_small_random_model(self):
        reference = TransformersReference(self.model.config, self.model.weights)
        result = discovery(self.model, reference, self.tokenizer, self.protocol)
        self.assertEqual(result["status"], "PASS", result["failures"])
        self.assertTrue(result["parity"]["reference_hooks_bitwise_invariant"])
        self.assertEqual(result["parity"]["intervention_comparisons"], 6)


if __name__ == "__main__":
    unittest.main()

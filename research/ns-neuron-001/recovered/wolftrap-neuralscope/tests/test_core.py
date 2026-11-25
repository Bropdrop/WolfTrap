"""Behavioral and mathematical checks for the instrumented inference core."""
import unittest

import numpy as np

from neuralscope.core import GPT2Model, ModelError, make_demo_model


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.model, self.demo = make_demo_model()
        self.clean = self.demo["clean_tokens"]
        self.corrupt = self.demo["corrupt_tokens"]

    def gap(self, run):
        logits = run["logits"][-1]
        return float(logits[self.demo["target_token"]] - logits[self.demo["alternative_token"]])

    def test_known_donor_patch_restores_output(self):
        clean = self.model.forward(self.clean)
        corrupt = self.model.forward(self.corrupt)
        head = self.demo["causal_head"]
        patched = self.model.forward(self.corrupt, {head: clean["activations"][head]})
        self.assertGreater(self.gap(clean), 1.0)
        self.assertLess(self.gap(corrupt), -1.0)
        np.testing.assert_allclose(patched["logits"][-1], clean["logits"][-1], atol=1e-7)
        self.assertEqual(int(np.argmax(clean["logits"][-1])), self.demo["target_token"])
        self.assertEqual(int(np.argmax(corrupt["logits"][-1])), self.demo["alternative_token"])

    def test_self_patch_and_negative_control_have_no_effect(self):
        clean = self.model.forward(self.clean)
        corrupt = self.model.forward(self.corrupt)
        for site in self.model.sites:
            patched = self.model.forward(self.corrupt, {site: corrupt["activations"][site]})
            np.testing.assert_array_equal(patched["logits"], corrupt["logits"])
        head = self.demo["negative_control_head"]
        patched = self.model.forward(self.corrupt, {head: clean["activations"][head]})
        np.testing.assert_array_equal(patched["logits"], corrupt["logits"])

    def test_zero_ablation_removes_known_signal(self):
        clean = self.model.forward(self.clean)
        head = self.demo["causal_head"]
        ablated = self.model.forward(self.clean, {head: np.zeros_like(clean["activations"][head])})
        self.assertAlmostEqual(self.gap(ablated), 0.0, places=6)

    def test_causal_mask_blocks_future_tokens(self):
        # Randomized nonzero attention and MLP ensure this checks the mask rather
        # than only the particularly sparse, constructed demonstration circuit.
        rng = np.random.default_rng(19)
        weights = {}
        for name, array in self.model.weights.items():
            weights[name] = (rng.normal(0, 0.08, size=array.shape).astype(np.float32)
                             if "weight" in name else np.zeros_like(array))
            if "ln_" in name and name.endswith("weight"):
                weights[name] = np.ones_like(array)
        model = GPT2Model(self.model.config, weights)
        short = model.forward([0, 1, 3])
        longer = model.forward([0, 1, 3, 5, 6])
        np.testing.assert_allclose(short["logits"], longer["logits"][:3], atol=2e-7, rtol=1e-6)
        for site in model.sites:
            np.testing.assert_allclose(short["activations"][site], longer["activations"][site][:3],
                                       atol=2e-7, rtol=1e-6)

    def test_projected_head_sum_matches_attention_output(self):
        run = self.model.forward(self.clean)
        a = run["activations"]
        summed = a["blocks.0.attn.head.0"] + a["blocks.0.attn.head.1"]
        summed += self.model.weights["transformer.h.0.attn.c_proj.bias"]
        np.testing.assert_array_equal(summed, a["blocks.0.attn_out"])

    def test_known_attention_matches_independent_scalar_expression(self):
        run = self.model.forward(self.clean)
        # RED's normalized first coordinate is 1/sqrt(2/8 + epsilon).
        normalized_signal = 1.0 / np.sqrt(0.25 + self.model.epsilon)
        # Last query averages the values of three tokens and projects by 8.
        expected = normalized_signal / 3.0 * 8.0
        self.assertAlmostEqual(float(run["activations"]["blocks.0.attn.head.0"][-1, 4]),
                               expected, places=5)

    def test_rejects_unknown_shapes_nonfinite_patches(self):
        for patches in ({"not.a.site": np.zeros((3, 8))},
                        {self.demo["causal_head"]: np.zeros((1, 8))},
                        {self.demo["causal_head"]: np.full((3, 8), np.nan)}):
            with self.subTest(patches=list(patches)):
                with self.assertRaises(ModelError):
                    self.model.forward(self.clean, patches)

    def test_rejects_invalid_tokens(self):
        for ids in ([], [8], [-1], [True], [1.1], [0] * 17, "013"):
            with self.subTest(ids=ids):
                with self.assertRaises(ModelError):
                    self.model.forward(ids)

    def test_rejects_unsupported_config(self):
        for change in ({"model_type": "llama"}, {"activation_function": "relu"},
                       {"n_head": 3}, {"add_cross_attention": True},
                       {"scale_attn_by_inverse_layer_idx": True},
                       {"layer_norm_epsilon": float("nan")},
                       {"quantization_config": {"bits": 4}}, {"n_layer": True},
                       {"n_inner": 0}):
            with self.subTest(change=change):
                with self.assertRaises(ModelError):
                    GPT2Model({**self.model.config, **change}, self.model.weights)

    def test_rejects_bad_inventory_shape_nonfinite_and_tying(self):
        variants = []
        missing = dict(self.model.weights)
        missing.pop("transformer.wpe.weight")
        variants.append(missing)
        variants.append({**self.model.weights, "unrecognized": np.zeros(1)})
        variants.append({**self.model.weights, "transformer.wpe.weight": np.zeros((1, 8))})
        variants.append({**self.model.weights, "transformer.wpe.weight": np.full((16, 8), np.inf)})
        variants.append({**self.model.weights, "lm_head.weight": np.ones((8, 8))})
        for weights in variants:
            with self.subTest(keys=list(weights)):
                with self.assertRaises(ModelError):
                    GPT2Model(self.model.config, weights)

    def test_unprefixed_checkpoint_and_capture_off(self):
        weights = {name.removeprefix("transformer."): value for name, value in self.model.weights.items()}
        model = GPT2Model(self.model.config, weights)
        actual = model.forward(self.clean, capture=False)
        self.assertEqual(actual["activations"], {})
        np.testing.assert_array_equal(actual["logits"], self.model.forward(self.clean)["logits"])

    def test_no_mutation_of_weights_or_donor_activations(self):
        before = {name: value.copy() for name, value in self.model.weights.items()}
        run = self.model.forward(self.clean)
        donors = {name: value.copy() for name, value in run["activations"].items()}
        self.model.forward(self.corrupt, {self.demo["causal_head"]: run["activations"][self.demo["causal_head"]]})
        for name in before:
            np.testing.assert_array_equal(before[name], self.model.weights[name])
        for name in donors:
            np.testing.assert_array_equal(donors[name], run["activations"][name])

    def test_last_position_patch_for_all_demo_prefix_lengths(self):
        site = self.demo["causal_site"]
        for prefix_length in range(6):
            prefix = [self.demo["neutral_id"]] * prefix_length
            clean = self.model.forward(prefix + self.demo["clean_ids"])
            corrupt = self.model.forward(prefix + self.demo["corrupt_ids"])
            patch = corrupt["activations"][site].copy()
            patch[-1] = clean["activations"][site][-1]
            patched = self.model.forward(prefix + self.demo["corrupt_ids"], {site: patch})
            np.testing.assert_array_equal(patched["logits"][-1], clean["logits"][-1])
            self.assertEqual(int(np.argmax(clean["logits"][-1])), self.demo["target_id"])
            self.assertEqual(int(np.argmax(corrupt["logits"][-1])), self.demo["alternative_id"])


if __name__ == "__main__":
    unittest.main()

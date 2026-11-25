"""Optional cross-implementation and hook-lifecycle tests.

These small random-weight cases test the reference adapter itself. The separately
recorded pinned-checkpoint experiment supplies pretrained-model evidence.
"""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import numpy as np

from neuralscope.core import GPT2Model, ModelError
from neuralscope.evidence import write_json
from neuralscope.reference import TransformersReference, compare_outputs
from neuralscope.weights import write_safetensors
from test_reference import random_two_layer_fixture


REFERENCE_INSTALLED = all(importlib.util.find_spec(name) is not None
                          for name in ("torch", "transformers"))


@unittest.skipUnless(REFERENCE_INSTALLED, "optional torch/transformers are not installed")
class TransformersReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config, cls.weights = random_two_layer_fixture(20261124)
        cls.reference = TransformersReference(cls.config, cls.weights)
        cls.core = GPT2Model(cls.config, cls.weights)
        cls.clean_ids = [0, 3, 6, 9, 8, 2, 22]
        cls.changed_ids = [0, 3, 12, 9, 8, 2, 22]

    def assertNoHooks(self):
        for module in self.reference._model.modules():
            self.assertFalse(module._forward_hooks)
            self.assertFalse(module._forward_pre_hooks)

    def assertClose(self, actual, expected):
        result = compare_outputs(actual, expected, atol=3e-6, rtol=1e-5)
        self.assertEqual(result["status"], "PASS", result)

    def test_provenance_roundtrip_uses_plain_json_types(self):
        from neuralscope.qualification import _compare_result
        current = self.reference.provenance()
        self.assertIs(type(current["torch"]), str)
        self.assertIs(type(current["transformers"]), str)
        _compare_result(json.loads(json.dumps(current)), current)

    def test_dense_two_layer_baseline_and_all_captures_match(self):
        for ids in ([7], self.clean_ids):
            with self.subTest(ids=ids):
                self.assertClose(self.core.forward(ids), self.reference.forward(ids))

    def test_unhooked_baseline_is_bitwise_preserved_and_hooks_removed(self):
        expected = self.reference.forward_unhooked(self.clean_ids)["logits"]
        captured = self.reference.forward(self.clean_ids)
        uncaptured = self.reference.forward(self.clean_ids, capture=False)
        np.testing.assert_array_equal(captured["logits"], expected)
        np.testing.assert_array_equal(uncaptured["logits"], expected)
        self.assertEqual(uncaptured["activations"], {})
        self.assertEqual(set(captured["activations"]), set(self.reference.sites))
        self.assertNoHooks()

    def test_projected_heads_match_under_identical_donor_interventions(self):
        donor = self.reference.forward(self.clean_ids)
        recipient = self.reference.forward(self.changed_ids)
        for site in self.reference.sites:
            if ".attn.head." not in site:
                continue
            patch = recipient["activations"][site].copy()
            patch[-1] = donor["activations"][site][-1]
            with self.subTest(site=site):
                self.assertClose(self.core.forward(self.changed_ids, {site: patch}),
                                 self.reference.forward(self.changed_ids, {site: patch}))
        self.assertNoHooks()

    def test_mlp_residual_and_attention_outputs_match_under_identical_patches(self):
        donor = self.reference.forward(self.clean_ids)
        for site in self.reference.sites:
            if ".attn.head." in site:
                continue
            patch = donor["activations"][site].copy()
            patch[-1] += np.float32(0.03)
            with self.subTest(site=site):
                self.assertClose(self.core.forward(self.changed_ids, {site: patch}),
                                 self.reference.forward(self.changed_ids, {site: patch}))
        self.assertNoHooks()

    def test_all_self_patches_preserve_reference_bitwise(self):
        baseline = self.reference.forward(self.clean_ids)
        for site, value in baseline["activations"].items():
            with self.subTest(site=site):
                result = self.reference.forward(self.clean_ids, {site: value})
                np.testing.assert_array_equal(result["logits"], baseline["logits"])
        self.assertNoHooks()

    def test_simultaneous_head_ablation_adds_shared_projection_bias_once(self):
        baseline = self.reference.forward(self.clean_ids)
        sites = [site for site in self.reference.sites if site.startswith("blocks.0.attn.head.")]
        patches = {site: np.zeros_like(baseline["activations"][site]) for site in sites}
        result = self.reference.forward(self.clean_ids, patches)
        expected_bias = np.broadcast_to(self.weights["transformer.h.0.attn.c_proj.bias"],
                                        (len(self.clean_ids), self.reference.n_embd))
        # Subtracting separately projected contributions from a concatenated GEMM
        # can leave roundoff, but must not omit or multiply the shared bias.
        np.testing.assert_allclose(result["activations"]["blocks.0.attn_out"],
                                   expected_bias, atol=3e-6, rtol=1e-5)
        self.assertClose(self.core.forward(self.clean_ids, patches), result)

    def test_tied_untied_and_unscaled_attention_variants(self):
        for tied, scaled in ((False, True), (True, False), (False, False)):
            with self.subTest(tied=tied, scaled=scaled):
                config, weights = random_two_layer_fixture(71, tied=tied, scaled=scaled)
                reference = TransformersReference(config, weights)
                self.assertClose(GPT2Model(config, weights).forward(self.clean_ids),
                                 reference.forward(self.clean_ids))

    def test_rejects_invalid_inputs_before_installing_hooks(self):
        for ids in ([], [True], [1.0], [-1], [self.reference.vocab_size], "013"):
            with self.subTest(ids=ids), self.assertRaises(ModelError):
                self.reference.forward(ids)
        site = self.reference.sites[0]
        for patch in ({"unknown.site": np.zeros((7, 12))},
                      {site: np.zeros((1, 12))}, {site: np.full((7, 12), np.nan)}):
            with self.subTest(patch=list(patch)), self.assertRaises(ModelError):
                self.reference.forward(self.clean_ids, patch)
        self.assertNoHooks()
        self.assertClose(self.core.forward(self.clean_ids), self.reference.forward(self.clean_ids))

    def test_hooks_removed_after_mid_forward_exception(self):
        block = self.reference._model.transformer.h[1]
        with mock.patch.object(block.mlp, "forward", side_effect=RuntimeError("fixture failure")):
            with self.assertRaisesRegex(RuntimeError, "fixture failure"):
                self.reference.forward(self.clean_ids)
        self.assertNoHooks()
        self.assertClose(self.core.forward(self.clean_ids), self.reference.forward(self.clean_ids))

    def test_strict_weight_inventory_and_no_remote_config_selection(self):
        with self.assertRaises(ModelError):
            TransformersReference(self.config, {**self.weights, "extra": np.zeros(1, np.float32)})
        with self.assertRaises(ModelError):
            TransformersReference({**self.config, "auto_map": {"AutoModel": "remote.Model"}},
                                  self.weights)

    def test_local_numeric_loading_matches_and_never_opens_a_socket(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_json(root / "config.json", self.config)
            write_safetensors(root / "weights.safetensors", self.weights)
            with mock.patch("socket.socket", side_effect=AssertionError("unexpected network")):
                reference = TransformersReference.from_local(root / "config.json",
                                                             root / "weights.safetensors")
                self.assertClose(reference.forward(self.clean_ids), self.reference.forward(self.clean_ids))
            self.assertEqual(reference.provenance()["attention_implementation"], "eager")

    def test_rejects_foreign_hooks_and_concurrent_call(self):
        hook = self.reference._model.transformer.h[0].register_forward_hook(lambda *args: None)
        try:
            with self.assertRaisesRegex(ModelError, "already has forward hooks"):
                self.reference.forward_unhooked(self.clean_ids)
        finally:
            hook.remove()
        self.reference._run_lock.acquire()
        try:
            with self.assertRaisesRegex(ModelError, "concurrent"):
                self.reference.forward(self.clean_ids)
        finally:
            self.reference._run_lock.release()
        self.assertNoHooks()


class ReferenceComparisonTests(unittest.TestCase):
    def result(self, values):
        return {"logits": np.asarray(values, dtype=np.float32), "activations": {}}

    def test_full_array_error_detected_despite_identical_winning_token(self):
        good = self.result([[10, 2, 1]])
        changed = self.result([[10, 2.1, 1]])
        self.assertEqual(int(np.argmax(good["logits"])), int(np.argmax(changed["logits"])))
        result = compare_outputs(changed, good, atol=1e-3, rtol=1e-5)
        self.assertEqual(result["status"], "FAIL")
        self.assertGreater(result["arrays"][0]["max_scaled_error"], 1)

    def test_rejects_wrong_inventory_shape_nonfinite_and_tolerance(self):
        good = self.result([[1, 2]])
        for changed in (self.result([[1, np.nan]]), self.result([1, 2]),
                        {"logits": good["logits"], "activations": {"extra": good["logits"]}}):
            with self.assertRaises(ValueError):
                compare_outputs(changed, good, atol=1e-3, rtol=1e-5)
        with self.assertRaises(ValueError):
            compare_outputs(good, good, atol=True, rtol=1e-5)

    def test_relative_only_zero_comparison_reports_failure_without_nonfinite_json(self):
        result = compare_outputs(self.result([[0.1, 2]]), self.result([[0, 2]]), atol=0, rtol=1e-5)
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(result["arrays"][0]["zero_tolerance_mismatch"])
        self.assertIsNone(result["arrays"][0]["max_scaled_error"])


if __name__ == "__main__":
    unittest.main()

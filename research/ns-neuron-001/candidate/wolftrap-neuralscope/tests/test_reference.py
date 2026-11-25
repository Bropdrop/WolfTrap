"""Compare the instrumented core with an independently organized reference.

Reference equations: OpenAI's original GPT-2 implementation,
https://github.com/openai/gpt-2/blob/master/src/model.py
(layer normalization, tanh GELU, causal attention, concatenated heads, pre-LN
residual blocks, and tied output embeddings). The untied output projection and
disabled attention scaling cases exercise supported configuration alternatives.

This is a random-weight mathematical cross-check, not a Transformers/PyTorch
comparison or validation of an external pretrained checkpoint. No core helper,
captured activation, or projected-head decomposition is reused by the reference.
"""

import math
import unittest

import numpy as np

from neuralscope.core import GPT2Model


def scalar_norm(matrix, gain, bias, epsilon):
    """Population variance, evaluated independently per row in Python float."""
    result = np.empty_like(matrix, dtype=np.float64)
    for token, row in enumerate(matrix):
        values = [float(value) for value in row]
        center = math.fsum(values) / len(values)
        variance = math.fsum((value - center) ** 2 for value in values) / len(values)
        denominator = math.sqrt(variance + epsilon)
        for feature, value in enumerate(values):
            result[token, feature] = ((value - center) / denominator * float(gain[feature])
                                       + float(bias[feature]))
    return result


def flat_head_reference(config, weights, token_ids):
    """Compute logits without hooks using sequential scalar attention loops."""
    tensors = {name: value.astype(np.float64) for name, value in weights.items()}
    width = config["n_embd"]
    heads = config["n_head"]
    head_width = width // heads
    length = len(token_ids)
    epsilon = config["layer_norm_epsilon"]
    x = tensors["transformer.wte.weight"][token_ids] + tensors["transformer.wpe.weight"][:length]
    for layer in range(config["n_layer"]):
        p = f"transformer.h.{layer}."
        z = scalar_norm(x, tensors[p + "ln_1.weight"], tensors[p + "ln_1.bias"], epsilon)
        projected = z @ tensors[p + "attn.c_attn.weight"] + tensors[p + "attn.c_attn.bias"]
        # Q, K, and V stay as flat matrices here; there is no reshape/transpose
        # shared with the batched implementation under test.
        query = projected[:, :width]
        key = projected[:, width:2 * width]
        value = projected[:, 2 * width:]
        concatenated = np.zeros((length, width), dtype=np.float64)
        for destination in range(length):
            for head in range(heads):
                begin, end = head * head_width, (head + 1) * head_width
                scores = []
                # Only causal prefix positions exist in this calculation.
                for source in range(destination + 1):
                    score = math.fsum(float(query[destination, col]) * float(key[source, col])
                                      for col in range(begin, end))
                    if config.get("scale_attn_weights", True):
                        score /= math.sqrt(head_width)
                    scores.append(score)
                maximum = max(scores)
                exp_scores = [math.exp(score - maximum) for score in scores]
                denominator = math.fsum(exp_scores)
                for col in range(begin, end):
                    concatenated[destination, col] = math.fsum(
                        weight / denominator * float(value[source, col])
                        for source, weight in enumerate(exp_scores))
        # A single projection after concatenation is independent of per-head
        # projected contribution summation in the instrumented implementation.
        x = x + concatenated @ tensors[p + "attn.c_proj.weight"] + tensors[p + "attn.c_proj.bias"]
        z = scalar_norm(x, tensors[p + "ln_2.weight"], tensors[p + "ln_2.bias"], epsilon)
        hidden = z @ tensors[p + "mlp.c_fc.weight"] + tensors[p + "mlp.c_fc.bias"]
        for row in range(hidden.shape[0]):
            for col in range(hidden.shape[1]):
                h = float(hidden[row, col])
                hidden[row, col] = 0.5 * h * (1 + math.tanh(math.sqrt(2 / math.pi) * (
                    h + 0.044715 * h ** 3)))
        x = x + hidden @ tensors[p + "mlp.c_proj.weight"] + tensors[p + "mlp.c_proj.bias"]
    x = scalar_norm(x, tensors["transformer.ln_f.weight"], tensors["transformer.ln_f.bias"], epsilon)
    output = tensors.get("lm_head.weight", tensors["transformer.wte.weight"])
    return x @ output.T


def random_two_layer_fixture(seed, *, tied=True, scaled=True):
    """Small, dense weights with nonzero biases and nonsquare MLP projections."""
    rng = np.random.default_rng(seed)
    width, inner, vocabulary, positions = 12, 17, 23, 16
    config = {"model_type": "gpt2", "n_embd": width, "n_inner": inner,
              "n_head": 3, "n_layer": 2, "n_positions": positions,
              "vocab_size": vocabulary, "activation_function": "gelu_new",
              "layer_norm_epsilon": 3e-5, "tie_word_embeddings": tied,
              "scale_attn_weights": scaled}
    shapes = {"transformer.wte.weight": (vocabulary, width),
              "transformer.wpe.weight": (positions, width),
              "transformer.ln_f.weight": (width,),
              "transformer.ln_f.bias": (width,)}
    for layer in range(2):
        p = f"transformer.h.{layer}."
        shapes.update({
            p + "ln_1.weight": (width,), p + "ln_1.bias": (width,),
            p + "ln_2.weight": (width,), p + "ln_2.bias": (width,),
            p + "attn.c_attn.weight": (width, 3 * width),
            p + "attn.c_attn.bias": (3 * width,),
            p + "attn.c_proj.weight": (width, width),
            p + "attn.c_proj.bias": (width,),
            p + "mlp.c_fc.weight": (width, inner), p + "mlp.c_fc.bias": (inner,),
            p + "mlp.c_proj.weight": (inner, width), p + "mlp.c_proj.bias": (width,),
        })
    if not tied:
        shapes["lm_head.weight"] = (vocabulary, width)
    weights = {}
    for name, shape in shapes.items():
        if ".ln_" in name and name.endswith("weight"):
            weights[name] = rng.uniform(0.7, 1.3, size=shape).astype(np.float32)
        else:
            weights[name] = rng.normal(0, 0.15, size=shape).astype(np.float32)
    return config, weights


class ReferenceParityTests(unittest.TestCase):
    def test_dense_two_layer_forward_matches_independent_reference(self):
        # These alternatives catch wrong output-embedding selection and ignored
        # attention scaling in addition to head ordering, residual and bias bugs.
        for tied, scaled in ((True, True), (False, True), (True, False), (False, False)):
            with self.subTest(tied=tied, scaled=scaled):
                config, weights = random_two_layer_fixture(20261123, tied=tied, scaled=scaled)
                model = GPT2Model(config, weights)
                ids = [0, 3, 6, 9, 8, 2, 22]
                expected = flat_head_reference(config, weights, ids)
                actual = model.forward(ids)["logits"]
                np.testing.assert_allclose(actual, expected, rtol=1e-5, atol=3e-6)

    def test_single_token_attention_matches_independent_reference(self):
        # The length-one boundary reduces attention to its value projection and
        # exercises scalar-population normalization, nonzero biases and both MLPs.
        config, weights = random_two_layer_fixture(816, tied=False)
        expected = flat_head_reference(config, weights, [7])
        actual = GPT2Model(config, weights).forward([7])["logits"]
        np.testing.assert_allclose(actual, expected, rtol=1e-5, atol=3e-6)


if __name__ == "__main__":
    unittest.main()

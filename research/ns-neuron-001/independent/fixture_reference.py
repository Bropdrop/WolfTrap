"""Independent float64 CPU forward pass for this specific two-block fixture."""
import json
import struct

import numpy as np
from scipy.special import ndtr, softmax


class ReferenceFixture:
    def __init__(self, path):
        raw = path.read_bytes()
        offset = 8 + struct.unpack("<Q", raw[:8])[0]
        metadata = json.loads(raw[8:offset])
        self.weights = {}
        for key, tensor in metadata.items():
            if tensor["dtype"] != "F32":
                raise ValueError(f"Unexpected tensor type for {key}")
            start, stop = tensor["data_offsets"]
            view = np.frombuffer(raw[offset + start:offset + stop], dtype="<f4")
            weight = view.reshape(tensor["shape"]).astype(np.float64)
            weight.setflags(write=False)
            self.weights[key] = weight
        if sum(w.size for w in self.weights.values()) != 19035:
            raise ValueError("Unexpected fixture parameter count")

    def norm(self, values, prefix):
        centered = values - values.mean(axis=-1, keepdims=True)
        variance = np.mean(centered ** 2, axis=-1, keepdims=True)
        return (centered / np.sqrt(variance + 1e-5) * self.weights[prefix + ".weight"]
                + self.weights[prefix + ".bias"])

    def attention(self, normalized, prefix):
        n, length, _ = normalized.shape
        packed = (normalized @ self.weights[prefix + ".in_proj_weight"].T
                  + self.weights[prefix + ".in_proj_bias"])
        q, k, v = [part.reshape(n, length, 4, 8).transpose(0, 2, 1, 3)
                   for part in np.split(packed, 3, axis=-1)]
        affinity = (q @ k.swapaxes(-2, -1)) / np.sqrt(8)
        affinity[:, :, np.triu_indices(length, 1)[0], np.triu_indices(length, 1)[1]] = -np.inf
        context = softmax(affinity, axis=-1) @ v
        context = context.transpose(0, 2, 1, 3).reshape(n, length, 32)
        return context @ self.weights[prefix + ".out_proj.weight"].T + self.weights[prefix + ".out_proj.bias"]

    def row_matrix(self, layer):
        return self.weights[f"transformer.h.{layer}.mlp.c_proj.weight"]

    def forward(self, ids, *, layer=None, zero=None, inject=None, trace=False):
        """Inputs are fresh each call. Edits operate only on the final sequence position."""
        if zero is not None and inject is not None:
            raise ValueError("Provide a single intervention")
        x = self.weights["tok.weight"][ids] + self.weights["pos.weight"][np.arange(ids.shape[1])]
        arrays = {}
        for i in range(2):
            key = f"transformer.h.{i}"
            x = x + self.attention(self.norm(x, key + ".ln1"), key + ".attn")
            hidden = (self.norm(x, key + ".ln2") @ self.weights[key + ".mlp.c_fc.weight"]
                      + self.weights[key + ".mlp.c_fc.bias"])
            activation = hidden * ndtr(hidden)
            if layer == i and zero is not None:
                activation[:, -1, zero] = 0
            projected = activation @ self.row_matrix(i) + self.weights[key + ".mlp.c_proj.bias"]
            if layer == i and inject is not None:
                projected[:, -1] += inject
            x = x + projected
            if trace:
                arrays[f"L{i}.activation"] = activation
                arrays[f"L{i}.projected"] = projected
                arrays[f"L{i}.residual"] = x
        arrays["logits"] = self.norm(x, "ln") @ self.weights["head.weight"].T + self.weights["head.bias"]
        return arrays


def margin(trace):
    return trace["logits"][:, -1, 25] - trace["logits"][:, -1, 26]


def projection_gradient(model, ids, layer):
    """Central differences on each residual dimension, independent of Torch/autograd."""
    step = 1e-4
    gradients = []
    for perturb in np.eye(32) * step:
        positive = margin(model.forward(ids, layer=layer, inject=perturb))
        negative = margin(model.forward(ids, layer=layer, inject=-perturb))
        gradients.append((positive - negative) / (2 * step))
    return np.stack(gradients, axis=1)

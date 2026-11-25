"""A deliberately small, inspectable NumPy implementation of GPT-2 inference.

This module loads no files and executes no model-supplied code. Callers supply
already validated arrays and a GPT-2 configuration. Inference is single-example,
without dropout or KV caching. Activations are values from actual forward passes.
Patches replace entire named activation tensors, including every token position.

The bundled model is a hand-constructed validation circuit, not a pretrained LLM.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np


MAX_PARAMETERS = 150_000_000
MAX_FORWARD_TOKENS = 256


class ModelError(ValueError):
    """The checkpoint, configuration, input, or intervention is unsupported."""


def _integer(value: Any, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, np.integer)):
        raise ModelError(f"{name} must be an integer")
    value = int(value)
    if not low <= value <= high:
        raise ModelError(f"{name} must be between {low} and {high}")
    return value


def _finite(array: np.ndarray) -> bool:
    # Chunk to avoid a tensor-sized temporary boolean array for checkpoint intake.
    iterator = np.nditer(array, flags=["external_loop", "buffered", "zerosize_ok"],
                         op_flags=["readonly"], buffersize=262_144)
    return all(bool(np.isfinite(chunk).all()) for chunk in iterator)


def _layer_norm(x: np.ndarray, weight: np.ndarray, bias: np.ndarray,
                epsilon: float) -> np.ndarray:
    mean = np.mean(x, axis=-1, keepdims=True, dtype=np.float32)
    centered = x - mean
    variance = np.mean(centered * centered, axis=-1, keepdims=True,
                       dtype=np.float32)
    return centered / np.sqrt(variance + np.float32(epsilon)) * weight + bias


def _gelu_new(x: np.ndarray) -> np.ndarray:
    # GPT-2's tanh-approximate GELU, not the erf variant.
    return np.float32(0.5) * x * (
        np.float32(1.0) + np.tanh(np.float32(math.sqrt(2.0 / math.pi)) * (
            x + np.float32(0.044715) * x * x * x)))


class GPT2Model:
    """Supported GPT-2 inference and precisely named internal interventions.

    ``weights`` uses Hugging Face GPT2LMHeadModel names (``transformer.wte.weight``
    etc.). Consistently unprefixed GPT2Model names are also accepted. Float16,
    float32, and float64 arrays are converted to float32. Other storage dtypes,
    model families, quantization, cross-attention, and alternate activations are
    rejected explicitly. At most 150 million parameters and 256 tokens per
    forward pass are accepted. These are resource bounds, not a sandbox.

    Each attention-head site is the head's contribution *after* its slice of the
    attention output projection, shape ``(tokens, n_embd)``. The shared output
    projection bias is added once after summing heads and is not part of a head.
    """

    def __init__(self, config: Mapping[str, Any], weights: Mapping[str, np.ndarray],
                 *, max_context: int = MAX_FORWARD_TOKENS) -> None:
        if not isinstance(config, Mapping) or not isinstance(weights, Mapping):
            raise ModelError("config and weights must be mappings")
        if config.get("model_type") != "gpt2":
            raise ModelError("only model_type='gpt2' is supported")
        for flag in ("add_cross_attention", "is_encoder_decoder",
                     "scale_attn_by_inverse_layer_idx", "reorder_and_upcast_attn"):
            if config.get(flag, False) is not False:
                raise ModelError(f"unsupported configuration: {flag}")
        if config.get("auto_map") or config.get("quantization_config") or config.get("pruned_heads"):
            raise ModelError("remote-code, quantized, and pruned-head configurations are unsupported")
        if config.get("activation_function", "gelu_new") != "gelu_new":
            raise ModelError("only activation_function='gelu_new' is supported")
        scale_attention = config.get("scale_attn_weights", True)
        tie_embeddings = config.get("tie_word_embeddings", True)
        if not isinstance(scale_attention, bool) or not isinstance(tie_embeddings, bool):
            raise ModelError("attention scaling and embedding tying flags must be boolean")

        self.n_embd = _integer(config.get("n_embd"), "n_embd", 2, 2048)
        self.n_head = _integer(config.get("n_head"), "n_head", 1, 32)
        self.n_layer = _integer(config.get("n_layer"), "n_layer", 1, 24)
        self.n_positions = _integer(config.get("n_positions"), "n_positions", 1, 8192)
        self.vocab_size = _integer(config.get("vocab_size"), "vocab_size", 2, 262144)
        n_inner_value = config.get("n_inner")
        self.n_inner = _integer(4 * self.n_embd if n_inner_value is None else n_inner_value,
                                "n_inner", 1, 16384)
        if self.n_embd % self.n_head:
            raise ModelError("n_embd must be divisible by n_head")
        self.head_dim = self.n_embd // self.n_head
        self.max_context = min(self.n_positions,
                               _integer(max_context, "max_context", 1,
                                        MAX_FORWARD_TOKENS))
        try:
            self.epsilon = float(config.get("layer_norm_epsilon", 1e-5))
        except (TypeError, ValueError) as exc:
            raise ModelError("invalid layer_norm_epsilon") from exc
        if not math.isfinite(self.epsilon) or not 0 < self.epsilon <= 0.1:
            raise ModelError("layer_norm_epsilon must be finite and in (0, 0.1]")
        self.scale_attention = scale_attention
        self.config = dict(config)
        self.config.update(n_inner=self.n_inner, activation_function="gelu_new",
                           layer_norm_epsilon=self.epsilon,
                           scale_attn_weights=scale_attention,
                           tie_word_embeddings=tie_embeddings)

        d, inner = self.n_embd, self.n_inner
        expected: dict[str, tuple[int, ...]] = {
            "transformer.wte.weight": (self.vocab_size, d),
            "transformer.wpe.weight": (self.n_positions, d),
            "transformer.ln_f.weight": (d,),
            "transformer.ln_f.bias": (d,),
        }
        for layer in range(self.n_layer):
            p = f"transformer.h.{layer}."
            expected.update({
                p + "ln_1.weight": (d,), p + "ln_1.bias": (d,),
                p + "attn.c_attn.weight": (d, 3 * d),
                p + "attn.c_attn.bias": (3 * d,),
                p + "attn.c_proj.weight": (d, d),
                p + "attn.c_proj.bias": (d,),
                p + "ln_2.weight": (d,), p + "ln_2.bias": (d,),
                p + "mlp.c_fc.weight": (d, inner),
                p + "mlp.c_fc.bias": (inner,),
                p + "mlp.c_proj.weight": (inner, d),
                p + "mlp.c_proj.bias": (d,),
            })
        normalized: dict[str, np.ndarray] = {}
        for name, value in weights.items():
            if not isinstance(name, str):
                raise ModelError("weight names must be strings")
            key = name if name.startswith("transformer.") or name == "lm_head.weight" else "transformer." + name
            if key in normalized:
                raise ModelError(f"duplicate normalized weight name: {key}")
            normalized[key] = value
        if "lm_head.weight" in normalized or not tie_embeddings:
            expected["lm_head.weight"] = (self.vocab_size, d)
        missing = sorted(set(expected) - set(normalized))
        extra = sorted(set(normalized) - set(expected))
        if missing or extra:
            raise ModelError(f"weight inventory mismatch; missing={missing[:5]}, unsupported={extra[:5]}")
        total = sum(math.prod(shape) for shape in expected.values())
        if total > MAX_PARAMETERS:
            raise ModelError(f"checkpoint exceeds {MAX_PARAMETERS:,} parameter limit")
        self.weights: dict[str, np.ndarray] = {}
        for name, shape in expected.items():
            source = normalized[name]
            if not isinstance(source, np.ndarray) or source.shape != shape:
                raise ModelError(f"wrong array or shape for {name}; expected {shape}")
            if source.dtype.kind != "f" or source.dtype.itemsize not in (2, 4, 8):
                raise ModelError(f"unsupported dtype for {name}: {source.dtype}")
            with np.errstate(over="ignore", invalid="ignore"):
                converted = np.asarray(source, dtype=np.float32)
            if not _finite(converted):
                raise ModelError(f"nonfinite or float32-overflowing weights: {name}")
            self.weights[name] = converted
        if tie_embeddings and "lm_head.weight" in self.weights:
            if not np.array_equal(self.weights["lm_head.weight"], self.weights["transformer.wte.weight"]):
                raise ModelError("tied lm_head and token embeddings differ")
        self.unembed = self.weights.get("lm_head.weight", self.weights["transformer.wte.weight"])
        self.parameter_count = total
        self.sites = tuple(site for layer in range(self.n_layer) for site in (
            f"blocks.{layer}.resid_pre",
            *(f"blocks.{layer}.attn.head.{head}" for head in range(self.n_head)),
            f"blocks.{layer}.attn_out", f"blocks.{layer}.mlp_out",
            f"blocks.{layer}.resid_post"))

    def forward(self, token_ids: Sequence[int],
                patches: Mapping[str, np.ndarray] | None = None,
                capture: bool = True) -> dict[str, Any]:
        """Return token logits and optional activation copies for one sequence.

        Patches are full ``(sequence_length, n_embd)`` replacements. Their values
        must be finite, and their site names and shapes must match exactly. No
        gradients or claim about the semantic meaning of a feature are supplied.
        """
        if isinstance(token_ids, (str, bytes)):
            raise ModelError("token_ids must be an integer sequence")
        try:
            ids_list = list(token_ids)
        except TypeError as exc:
            raise ModelError("token_ids must be an integer sequence") from exc
        if not 1 <= len(ids_list) <= self.max_context:
            raise ModelError(f"input must contain 1..{self.max_context} tokens")
        ids = np.array([_integer(value, "token ID", 0, self.vocab_size - 1)
                        for value in ids_list], dtype=np.int64)
        if patches is None:
            patches = {}
        if not isinstance(patches, Mapping):
            raise ModelError("patches must be a mapping")
        unknown = set(patches) - set(self.sites)
        if unknown:
            raise ModelError(f"unknown patch sites: {sorted(map(str, unknown))}")
        n = len(ids)
        validated: dict[str, np.ndarray] = {}
        for site, value in patches.items():
            try:
                with np.errstate(over="ignore", invalid="ignore"):
                    arr = np.asarray(value, dtype=np.float32)
            except (TypeError, ValueError) as exc:
                raise ModelError(f"patch {site} must be a finite numeric tensor") from exc
            if arr.shape != (n, self.n_embd) or not _finite(arr):
                raise ModelError(f"patch {site} must have finite shape {(n, self.n_embd)}")
            validated[site] = arr
        activations: dict[str, np.ndarray] = {}

        def tap(site: str, value: np.ndarray) -> np.ndarray:
            result = validated.get(site, value)
            if capture:
                activations[site] = result.copy()
            return result

        w = self.weights
        x = w["transformer.wte.weight"][ids] + w["transformer.wpe.weight"][:n]
        causal_mask = np.triu(np.ones((n, n), dtype=bool), k=1)
        with np.errstate(over="raise", invalid="raise", divide="raise"):
            try:
                for layer in range(self.n_layer):
                    p, s = f"transformer.h.{layer}.", f"blocks.{layer}."
                    x = tap(s + "resid_pre", x)
                    norm = _layer_norm(x, w[p + "ln_1.weight"], w[p + "ln_1.bias"], self.epsilon)
                    qkv = norm @ w[p + "attn.c_attn.weight"] + w[p + "attn.c_attn.bias"]
                    q, k, v = (part.reshape(n, self.n_head, self.head_dim).transpose(1, 0, 2)
                               for part in np.split(qkv, 3, axis=-1))
                    attention_scores = q @ k.transpose(0, 2, 1)
                    if self.scale_attention:
                        attention_scores = attention_scores / np.float32(math.sqrt(self.head_dim))
                    attention_scores[:, causal_mask] = -np.inf
                    attention_scores -= np.max(attention_scores, axis=-1, keepdims=True)
                    attention = np.exp(attention_scores)
                    attention /= np.sum(attention, axis=-1, keepdims=True)
                    heads = attention @ v
                    projected = np.zeros((n, self.n_embd), dtype=np.float32)
                    for head in range(self.n_head):
                        lo, hi = head * self.head_dim, (head + 1) * self.head_dim
                        contribution = heads[head] @ w[p + "attn.c_proj.weight"][lo:hi]
                        projected += tap(s + f"attn.head.{head}", contribution)
                    projected += w[p + "attn.c_proj.bias"]
                    x = x + tap(s + "attn_out", projected)
                    norm = _layer_norm(x, w[p + "ln_2.weight"], w[p + "ln_2.bias"], self.epsilon)
                    hidden = _gelu_new(norm @ w[p + "mlp.c_fc.weight"] + w[p + "mlp.c_fc.bias"])
                    mlp = hidden @ w[p + "mlp.c_proj.weight"] + w[p + "mlp.c_proj.bias"]
                    x = tap(s + "resid_post", x + tap(s + "mlp_out", mlp))
                final = _layer_norm(x, w["transformer.ln_f.weight"], w["transformer.ln_f.bias"], self.epsilon)
                logits = final @ self.unembed.T
            except FloatingPointError as exc:
                raise ModelError("nonfinite numerical result during inference") from exc
        if not _finite(logits):
            raise ModelError("nonfinite logits")
        return {"logits": logits, "activations": activations}


def make_demo_model() -> tuple[GPT2Model, dict[str, Any]]:
    """Construct a tiny GPT-2-shaped circuit with a known causal attention head.

    Head 0 copies a RED/BLUE signal into the answer subspace. Head 1 has a zero
    output projection and is a known negative control. The MLP is a no-op. This
    is purpose-built instrumentation validation, not trained language behavior,
    discovery of an unknown circuit, or a backdoor detector validation.
    """
    d, inner, vocab, positions = 8, 32, 8, 16
    config = {"model_type": "gpt2", "n_embd": d, "n_head": 2,
              "n_layer": 1, "n_positions": positions, "vocab_size": vocab,
              "n_inner": inner, "activation_function": "gelu_new",
              "layer_norm_epsilon": 1e-5, "tie_word_embeddings": True}
    w: dict[str, np.ndarray] = {
        "transformer.wte.weight": np.zeros((vocab, d), dtype=np.float32),
        "transformer.wpe.weight": np.zeros((positions, d), dtype=np.float32),
        "transformer.ln_f.weight": np.ones(d, dtype=np.float32),
        "transformer.ln_f.bias": np.zeros(d, dtype=np.float32),
    }
    p = "transformer.h.0."
    for ln in ("ln_1", "ln_2"):
        w[p + ln + ".weight"] = np.ones(d, dtype=np.float32)
        w[p + ln + ".bias"] = np.zeros(d, dtype=np.float32)
    for name, shape in {
        "attn.c_attn.weight": (d, 3 * d), "attn.c_attn.bias": (3 * d,),
        "attn.c_proj.weight": (d, d), "attn.c_proj.bias": (d,),
        "mlp.c_fc.weight": (d, inner), "mlp.c_fc.bias": (inner,),
        "mlp.c_proj.weight": (inner, d), "mlp.c_proj.bias": (d,),
    }.items():
        w[p + name] = np.zeros(shape, dtype=np.float32)
    embedding = w["transformer.wte.weight"]
    embedding[1, :2] = [1, -1]
    embedding[2, :2] = [-1, 1]
    embedding[3, 2:4] = [1, -1]
    embedding[4, 4:6] = [1, -1]
    embedding[5, 4:6] = [-1, 1]
    embedding[6, 6:8] = [1, -1]
    # Q and K remain zero, so each query attends uniformly to its causal prefix.
    w[p + "attn.c_attn.weight"][0, 2 * d] = 0.5
    w[p + "attn.c_attn.weight"][1, 2 * d] = -0.5
    w[p + "attn.c_proj.weight"][0, 4:6] = [8, -8]
    demo = {
        "kind": "constructed_untrained_validation_circuit",
        "description": "One-layer, two-head transformer with a planted RED/BLUE copying circuit.",
        "clean_tokens": [0, 1, 3], "corrupt_tokens": [0, 2, 3],
        "clean_ids": [0, 1, 3], "corrupt_ids": [0, 2, 3],
        "clean_token_ids": [0, 1, 3], "corrupt_token_ids": [0, 2, 3],
        "target_token": 4, "alternative_token": 5,
        "target_id": 4, "alternative_id": 5,
        "target_token_id": 4, "alternative_token_id": 5,
        "token_labels": ["BOS", "red", "blue", "query", "RED", "BLUE", "filler", "EOS"],
        "causal_head": "blocks.0.attn.head.0",
        "causal_site": "blocks.0.attn.head.0",
        "negative_control_head": "blocks.0.attn.head.1",
        "control_site": "blocks.0.attn.head.1", "neutral_id": 0,
        "scope": "Known positive and negative controls for instrumentation only; no external LLM was tested.",
    }
    return GPT2Model(config, w), demo

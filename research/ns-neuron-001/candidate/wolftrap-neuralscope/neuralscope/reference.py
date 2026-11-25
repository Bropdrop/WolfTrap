"""Optional local Transformers reference for the supported GPT-2 computation.

The reference executes the installed Hugging Face ``GPT2LMHeadModel`` in CPU
float32 evaluation mode with eager attention. It does not call ``from_pretrained``,
fetch files, execute repository code, or load pickle. Input validation and numeric
file intake are shared with NeuralScope; the forward computation is provided by
Transformers/PyTorch. This is a cross-implementation check, not independent human
review or a claim that either implementation is generally correct.

Hooks observe the real HF computation. A projected-head patch adds the difference
between the requested contribution and the original head contribution to HF's
normal concatenated-head projection. With no patches, hooks return no replacement
and therefore preserve HF's original operations and rounding. Hooks are removed in
``finally`` even after an exception. Concurrent calls on one adapter are rejected.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import hashlib
import inspect
from pathlib import Path
import threading
from typing import Any

import numpy as np

from .core import GPT2Model, MAX_FORWARD_TOKENS, ModelError


class ReferenceUnavailable(ValueError):
    """The optional, locally installed reference dependencies are unavailable."""


def _dependencies():
    try:
        import torch
        import transformers
        from transformers import GPT2Config, GPT2LMHeadModel
    except ImportError as exc:
        raise ReferenceUnavailable(
            "reference mode requires locally installed torch and transformers; "
            "see requirements-reference.txt") from exc
    return torch, transformers, GPT2Config, GPT2LMHeadModel


def compare_outputs(actual: Mapping[str, Any], expected: Mapping[str, Any], *,
                    atol: float, rtol: float) -> dict[str, Any]:
    """Compare full logits and the exact captured activation inventory.

    Tolerances must be chosen before interpreting measurements. Every array must
    be finite and have exactly the expected shape. ``max_scaled_error <= 1`` is
    equivalent to passing the elementwise ``atol + rtol * abs(expected)`` bound.
    The function never substitutes top-token agreement for numerical agreement.
    """
    for name, value in (("atol", atol), ("rtol", rtol)):
        if type(value) not in (int, float) or not np.isfinite(value) or value < 0:
            raise ValueError(f"{name} must be a finite nonnegative number")
    if atol == 0 and rtol == 0:
        raise ValueError("at least one comparison tolerance must be positive")
    if not isinstance(actual, Mapping) or not isinstance(expected, Mapping):
        raise ValueError("forward results must be mappings")
    if set(actual) != {"logits", "activations"} or set(expected) != set(actual):
        raise ValueError("forward result inventory differs")
    aa, ea = actual["activations"], expected["activations"]
    if not isinstance(aa, Mapping) or not isinstance(ea, Mapping) or set(aa) != set(ea):
        raise ValueError("captured activation inventory differs")
    pairs = [("logits", actual["logits"], expected["logits"])]
    pairs.extend(("activation:" + name, aa[name], ea[name]) for name in sorted(ea))
    records = []
    for name, left, right in pairs:
        if (not isinstance(left, np.ndarray) or not isinstance(right, np.ndarray)
                or left.shape != right.shape or not left.size
                or left.dtype.kind != "f" or right.dtype.kind != "f"
                or not np.isfinite(left).all() or not np.isfinite(right).all()):
            raise ValueError("invalid comparison array: " + name)
        a, e = left.astype(np.float64), right.astype(np.float64)
        difference = np.abs(a - e)
        allowance = float(atol) + float(rtol) * np.abs(e)
        # rtol-only comparisons require exact agreement at zero-valued references.
        scaled = np.divide(difference, allowance, out=np.zeros_like(difference),
                           where=allowance != 0)
        impossible = (allowance == 0) & (difference != 0)
        scaled[impossible] = np.inf
        passed = bool(np.all(difference <= allowance))
        maximum = float(scaled.max())
        records.append({"array": name, "shape": list(e.shape), "elements": int(e.size),
                        "max_abs_error": float(difference.max()),
                        "rms_error": float(np.sqrt(np.mean(difference * difference))),
                        "max_scaled_error": maximum if np.isfinite(maximum) else None,
                        "zero_tolerance_mismatch": bool(impossible.any()),
                        "status": "PASS" if passed else "FAIL"})
    return {"status": "PASS" if all(r["status"] == "PASS" for r in records) else "FAIL",
            "atol": float(atol), "rtol": float(rtol),
            "reference_side": "expected", "arrays": records,
            "max_abs_error": max(r["max_abs_error"] for r in records),
            "array_count": len(records),
            "elements_compared": sum(r["elements"] for r in records)}


class TransformersReference:
    """Strict local reference matching the NeuralScope ``forward`` interface.

    Construct with an already decoded supported numeric weight mapping. The
    ``from_local`` convenience constructor accepts local config JSON and a
    supported numeric safetensors file. Neither constructor has a network path.
    The model and inputs stay on the CPU; caching, training, dropout, and custom
    attention kernels are disabled. Attention-head sites exclude the shared
    projection bias, just as documented for :class:`neuralscope.core.GPT2Model`.
    """

    def __init__(self, config: Mapping[str, Any], weights: Mapping[str, np.ndarray], *,
                 max_context: int = MAX_FORWARD_TOKENS) -> None:
        from .pretrained import normalize_gpt2_weights

        # Share only structural/numeric intake. Never call the NumPy forward path.
        cleaned, exclusions = normalize_gpt2_weights(config, weights)
        validated = GPT2Model(config, cleaned, max_context=max_context)
        torch, transformers, Config, Model = _dependencies()
        self._torch = torch
        self._transformers = transformers
        self._run_lock = threading.Lock()
        self._excluded_buffers = exclusions
        self.config = dict(validated.config)
        for name in ("n_embd", "n_head", "head_dim", "n_layer", "n_positions",
                     "vocab_size", "n_inner", "max_context", "parameter_count", "sites"):
            setattr(self, name, getattr(validated, name))
        # Explicit construction prevents unrelated config metadata from selecting
        # custom code, devices, attention kernels, or unsupported model features.
        hf_config = Config(
            vocab_size=self.vocab_size, n_positions=self.n_positions,
            n_ctx=self.n_positions, n_embd=self.n_embd, n_layer=self.n_layer,
            n_head=self.n_head, n_inner=self.n_inner, activation_function="gelu_new",
            layer_norm_epsilon=validated.epsilon,
            scale_attn_weights=self.config["scale_attn_weights"],
            tie_word_embeddings=self.config["tie_word_embeddings"],
            attn_pdrop=0.0, embd_pdrop=0.0, resid_pdrop=0.0,
            use_cache=False, add_cross_attention=False,
            reorder_and_upcast_attn=False, scale_attn_by_inverse_layer_idx=False,
            bos_token_id=None, eos_token_id=None,
        )
        hf_config._attn_implementation = "eager"
        with torch.random.fork_rng(devices=[]), torch.device("cpu"):
            model = Model(hf_config).to(device="cpu", dtype=torch.float32)
        state = {name: torch.from_numpy(np.ascontiguousarray(value))
                 for name, value in validated.weights.items()}
        if self.config["tie_word_embeddings"] and "lm_head.weight" not in state:
            state["lm_head.weight"] = state["transformer.wte.weight"]
        expected_keys = set(model.state_dict())
        if set(state) != expected_keys:
            raise ModelError("installed reference weight inventory differs from supported GPT-2: "
                             f"missing={sorted(expected_keys - set(state))[:5]}, "
                             f"extra={sorted(set(state) - expected_keys)[:5]}")
        model.load_state_dict(state, strict=True)
        model.eval()
        model.requires_grad_(False)
        if model.config._attn_implementation != "eager":
            raise ModelError("installed reference did not retain eager attention")
        self._model = model
        self._source = Path(inspect.getfile(Model))

    @classmethod
    def from_local(cls, config_path, weights_path, *, expected_sha256=None,
                   max_context=MAX_FORWARD_TOKENS):
        from .evidence import read_json
        from .weights import load_weights

        config = read_json(config_path, limit=1024 * 1024)
        weights = load_weights(weights_path, expected_sha256=expected_sha256)
        return cls(config, weights, max_context=max_context)

    def provenance(self) -> dict[str, Any]:
        return {"implementation": "transformers.GPT2LMHeadModel",
                "torch": str(self._torch.__version__), "transformers": str(self._transformers.__version__),
                "numpy": np.__version__, "device": "cpu", "dtype": "float32",
                "evaluation_mode": True, "attention_implementation": "eager",
                "cache_enabled": False, "model_downloads": False,
                "model_repository_code_executed": False,
                "validated_excluded_buffers": self._excluded_buffers,
                "modeling_gpt2_sha256": hashlib.sha256(self._source.read_bytes()).hexdigest(),
                "validation_shared_with": "neuralscope.core.GPT2Model (no forward reuse)",
                "head_intervention": "HF c_proj output + (replacement - original head contribution)",
                "baseline_instrumentation": "observing hooks; no replacement when unpatched"}

    def _validate(self, token_ids, patches, capture):
        if type(capture) is not bool:
            raise ModelError("capture must be boolean")
        if isinstance(token_ids, (str, bytes)):
            raise ModelError("token_ids must be an integer sequence")
        try:
            ids = list(token_ids)
        except TypeError as exc:
            raise ModelError("token_ids must be an integer sequence") from exc
        if (not 1 <= len(ids) <= self.max_context or any(
                isinstance(x, (bool, np.bool_)) or not isinstance(x, (int, np.integer))
                or not 0 <= x < self.vocab_size for x in ids)):
            raise ModelError("token IDs must be a bounded nonempty integer vocabulary sequence")
        if patches is None:
            patches = {}
        if not isinstance(patches, Mapping):
            raise ModelError("patches must be a mapping")
        if set(patches) - set(self.sites):
            raise ModelError("unknown patch site")
        validated = {}
        for site, value in patches.items():
            try:
                with np.errstate(over="ignore", invalid="ignore"):
                    array = np.asarray(value, dtype=np.float32)
            except (TypeError, ValueError) as exc:
                raise ModelError("patch must be a finite numeric array") from exc
            if array.shape != (len(ids), self.n_embd) or not np.isfinite(array).all():
                raise ModelError("patch must have finite shape (tokens, n_embd)")
            validated[site] = self._torch.from_numpy(np.array(array, copy=True)).unsqueeze(0)
        return [int(x) for x in ids], validated

    def _ensure_clean_model(self):
        if any(m._forward_hooks or m._forward_pre_hooks for m in self._model.modules()):
            raise ModelError("reference model already has forward hooks")
        if any(m.training for m in self._model.modules()):
            raise ModelError("reference model left evaluation mode")
        if any(p.device.type != "cpu" or p.dtype != self._torch.float32
               for p in self._model.parameters()):
            raise ModelError("reference model must remain CPU float32")

    def forward_unhooked(self, token_ids: Sequence[int]) -> dict[str, Any]:
        """Run the same HF model with no observation or intervention hooks."""
        ids, _ = self._validate(token_ids, None, False)
        if not self._run_lock.acquire(blocking=False):
            raise ModelError("concurrent reference calls are unsupported")
        try:
            self._ensure_clean_model()
            with self._torch.inference_mode():
                output = self._model(input_ids=self._torch.tensor([ids], dtype=self._torch.long,
                                                                 device="cpu"),
                                     use_cache=False, return_dict=True).logits[0]
                logits = output.detach().cpu().numpy().copy()
            if not np.isfinite(logits).all():
                raise ModelError("nonfinite reference logits")
            return {"logits": logits, "activations": {}}
        finally:
            self._run_lock.release()

    def forward(self, token_ids: Sequence[int], patches: Mapping[str, np.ndarray] | None = None,
                capture: bool = True) -> dict[str, Any]:
        ids, replacements = self._validate(token_ids, patches, capture)
        if not self._run_lock.acquire(blocking=False):
            raise ModelError("concurrent reference calls are unsupported")
        handles = []
        activations = {}
        torch = self._torch
        shape = (1, len(ids), self.n_embd)

        def tap(site, value):
            if not torch.is_tensor(value) or tuple(value.shape) != shape:
                raise ModelError("installed reference activation shape differs at " + site)
            result = replacements.get(site, value)
            if capture:
                activations[site] = result.detach().cpu().numpy()[0].copy()
            return result

        def pre_hook(site):
            def hook(module, inputs):
                if not inputs:
                    raise ModelError("installed reference block did not provide positional hidden states")
                value = tap(site, inputs[0])
                if site in replacements:
                    return (value, *inputs[1:])
                return None
            return hook

        def tensor_hook(site):
            def hook(module, inputs, output):
                value = tap(site, output)
                return value if site in replacements else None
            return hook

        def first_hook(site):
            def hook(module, inputs, output):
                if torch.is_tensor(output):
                    value = tap(site, output)
                    return value if site in replacements else None
                if not isinstance(output, tuple) or not output:
                    raise ModelError("installed reference block output structure differs")
                value = tap(site, output[0])
                return (value, *output[1:]) if site in replacements else None
            return hook

        def projection_hook(layer):
            prefix = f"blocks.{layer}.attn.head."
            def hook(module, inputs, output):
                if len(inputs) != 1 or tuple(inputs[0].shape) != shape or tuple(output.shape) != shape:
                    raise ModelError("installed reference c_proj input/output differs")
                projected = output
                for head in range(self.n_head):
                    site = prefix + str(head)
                    if not capture and site not in replacements:
                        continue
                    lo, hi = head * self.head_dim, (head + 1) * self.head_dim
                    contribution = inputs[0][..., lo:hi] @ module.weight[lo:hi, :]
                    replacement = tap(site, contribution)
                    if site in replacements:
                        projected = projected + (replacement - contribution)
                return projected if projected is not output else None
            return hook

        try:
            self._ensure_clean_model()
            for layer, block in enumerate(self._model.transformer.h):
                prefix = f"blocks.{layer}."
                handles.append(block.register_forward_pre_hook(pre_hook(prefix + "resid_pre")))
                handles.append(block.attn.c_proj.register_forward_hook(projection_hook(layer)))
                handles.append(block.attn.register_forward_hook(first_hook(prefix + "attn_out")))
                handles.append(block.mlp.register_forward_hook(tensor_hook(prefix + "mlp_out")))
                handles.append(block.register_forward_hook(first_hook(prefix + "resid_post")))
            with torch.inference_mode():
                output = self._model(input_ids=torch.tensor([ids], dtype=torch.long, device="cpu"),
                                     use_cache=False, return_dict=True).logits[0]
                logits = output.detach().cpu().numpy().copy()
            if (not np.isfinite(logits).all()
                    or any(not np.isfinite(value).all() for value in activations.values())):
                raise ModelError("nonfinite reference result")
            if capture and set(activations) != set(self.sites):
                raise ModelError("installed reference did not execute every expected capture site")
            return {"logits": logits, "activations": activations}
        finally:
            for handle in reversed(handles):
                handle.remove()
            self._run_lock.release()

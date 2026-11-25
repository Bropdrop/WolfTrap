"""Compare the frozen protocol with two independent unpadded forward implementations."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import sys

import numpy as np


REGISTRATION_SHA = "dfb0f67bd4d8722a44e86aee76cbf911e66dc8fd9abec3fc40717e5e20a25f7d"
SOURCE_SHA = {
    "neuralscope/core.py": "1e1db1505c6a3baaf682edfb890d7d0271821943c6cfb8d3edfb7c6e97168e87",
    "neuralscope/pretrained.py": "4bb55bf5a312bc9671214a4352fb5fee6e3992916fe043407c61a6aacd170c48",
    "neuralscope/weights.py": "9fe4a08ab02c059d4dee111e5fcc96ad0fd345abc85e53aa0e8a26f0e01739df",
    "neuralscope/evidence.py": "4370e8acff85f91fe401fc15415f3d3950a6915080e517c6f1b99be9e2c6ab9d",
    "examples/pretrained-protocol.json": "47215ccf548bd3c612b9349e3ba816d8ad8939016e28cbe402d364717bd3abeb",
}
ORIGINAL_LIMITS = {
    "hooked_baseline_max_abs": 1e-5,
    "zero_direction_max_abs": 1e-5,
    "projection_reconstruction_max_abs": 1e-4,
    "ablation_vs_subtraction_max_abs": 5e-4,
    "gradient_vs_central_difference_max_abs": .04,
    "restored_baseline_max_abs": 1e-5,
}
GROUPS = ("validation_positive", "validation_control")


def sha(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def load(path):
    return json.loads(path.read_bytes())


def save(path, value):
    with path.open("x") as handle:
        json.dump(value, handle, indent=2, allow_nan=False)
        handle.write("\n")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def array_hash(data):
    return hashlib.sha256(np.ascontiguousarray(data)).hexdigest()


def errors(candidate, reference):
    require(candidate.shape == reference.shape and candidate.dtype == reference.dtype == np.float32,
            "Compared tensors need equal shapes and float32 dtype")
    delta = candidate.astype(np.float64) - reference
    require(np.isfinite(delta).all(), "Non-finite value in measured arrays")
    absolute = abs(delta)
    index = np.unravel_index(absolute.argmax(), absolute.shape)
    return {
        "shape": list(candidate.shape),
        "max_abs": float(absolute[index]),
        "max_abs_index": [int(i) for i in index],
        "numpy_value_at_max": float(candidate[index]),
        "reference_value_at_max": float(reference[index]),
        "rmse": float(np.sqrt(np.mean(np.square(delta)))),
        "numpy_sha256": array_hash(candidate),
        "reference_sha256": array_hash(reference),
    }


def measured_logits(candidate, reference, gates):
    summary = errors(candidate, reference)
    summary["passed"] = (summary["max_abs"] <= gates["full_logit_max_abs_error"]
                         and summary["rmse"] <= gates["full_logit_rmse"])
    summary["argmax_agreement_positions"] = int((candidate.argmax(1) == reference.argmax(1)).sum())
    return summary


def hidden_numpy(model, layer, acts):
    # Independently reconstruct the post-GELU coordinates from the recovered
    # engine's own residual and attention arrays. Its public API taps MLP outputs.
    prefix = f"transformer.h.{layer}."
    w = model.weights
    x = acts[f"blocks.{layer}.resid_pre"] + acts[f"blocks.{layer}.attn_out"]
    centered = x - x.mean(axis=-1, keepdims=True)
    norm = centered / np.sqrt(np.mean(centered**2, axis=-1, keepdims=True) + np.float32(model.epsilon))
    norm = norm * w[prefix + "ln_2.weight"] + w[prefix + "ln_2.bias"]
    fc = norm @ w[prefix + "mlp.c_fc.weight"] + w[prefix + "mlp.c_fc.bias"]
    return .5 * fc * (1 + np.tanh(np.float32(np.sqrt(2 / np.pi)) * (fc + np.float32(.044715) * fc * fc * fc)))


def intermediate_numpy(model, acts):
    data = {}
    for l in range(model.n_layer):
        for name in ("resid_pre", "attn_out", "mlp_out", "resid_post"):
            key = f"blocks.{l}.{name}"
            data[key] = acts[key]
        data[f"blocks.{l}.hidden_before_edit"] = hidden_numpy(model, l, acts)
    return data


def hf_forward(model, ids, capture=False, *, layer=None, neuron=None, add=None):
    import torch

    data = {}

    def tap(key, value):
        tensor = value[0] if isinstance(value, (list, tuple)) else value
        data[key] = tensor.detach()[0].cpu().numpy().copy()

    def pre_tap(key):
        def inspect(_, args):
            tap(key, args[0])
        return inspect

    def post_tap(key):
        def inspect(_, __, out):
            tap(key, out)
        return inspect

    with torch.no_grad(), ExitStack() as hooks:
        for l, block in enumerate(model.transformer.h):
            p = block.mlp.c_proj
            if capture:
                hooks.callback(block.register_forward_pre_hook(pre_tap(f"blocks.{l}.resid_pre")).remove)
                hooks.callback(block.attn.c_proj.register_forward_hook(post_tap(f"blocks.{l}.attn_out")).remove)
                hooks.callback(p.register_forward_pre_hook(pre_tap(f"blocks.{l}.hidden_before_edit")).remove)
            if l == layer and neuron is not None:
                def zero(_, args):
                    x = args[0].clone()
                    x[0, -1, neuron] = 0
                    return (x,)
                hooks.callback(p.register_forward_pre_hook(zero).remove)
            if l == layer and add is not None:
                def inject(_, __, out):
                    y = out.clone()
                    y[0, -1] += torch.from_numpy(add)
                    return y
                hooks.callback(p.register_forward_hook(inject).remove)
            if capture:
                hooks.callback(p.register_forward_hook(post_tap(f"blocks.{l}.mlp_out")).remove)
                hooks.callback(block.register_forward_hook(post_tap(f"blocks.{l}.resid_post")).remove)
        y = model(input_ids=ids, use_cache=False).logits
        return y.detach()[0].cpu().numpy().copy(), data


def compare_intermediates(ours, theirs, gates):
    require(set(ours) == set(theirs), "Intermediate site inventory changed")
    stats = {}
    for site, reference in theirs.items():
        actual = ours[site]
        summary = errors(actual, reference)
        allowance = gates["intermediate_atol"] + gates["intermediate_rtol"] * abs(reference.astype(np.float64))
        scaled = float(np.max(abs(actual.astype(np.float64) - reference) / allowance))
        summary.update(max_scaled_error=scaled, passed=scaled <= 1.)
        stats[site] = summary
    return stats


def verify_frozen(run):
    result = load(run / "results.json")
    if result["status"] != "MEASURED" or result.get("mechanism_checks_passed") is not True:
        return None, None, result
    for key in GROUPS:
        checks = result["validation"][key]["mechanism_checks"]
        require(checks["limits"] == ORIGINAL_LIMITS, "Original numerical limits changed")
        require(checks["passed"] and all(0 <= checks[k] <= v for k, v in ORIGINAL_LIMITS.items()),
                "Original numeric gate failed")
    selection = load(run / "selection.json")
    require(selection["status"] == "SELECTED", "Selection unavailable")
    require(result["selection_sha256"] == sha(run / "selection.json"), "Result to selection binding")
    require(selection["protocol_sha256"] == sha(run / "protocol.json"), "Selection to protocol binding")
    require(selection["discovery_sha256"] == sha(run / "discovery.json"), "Selection to discovery binding")
    return load(run / "protocol.json"), selection, result


def run_case(numpy_model, hf, ids, index, group, selection, original, target, foil, out, gates, text):
    import torch

    tensor = torch.tensor([ids], dtype=torch.long)
    layer, selected = selection["layer"], selection["neuron"]
    site = f"blocks.{layer}.mlp_out"
    w = numpy_model.weights[f"transformer.h.{layer}.mlp.c_proj.weight"]
    bias = numpy_model.weights[f"transformer.h.{layer}.mlp.c_proj.bias"]
    data = numpy_model.forward(ids)
    baseline, acts = data["logits"], data["activations"]
    intermediate = intermediate_numpy(numpy_model, acts)
    plain, _ = hf_forward(hf, tensor)
    baseline_hf, intermediate_hf = hf_forward(hf, tensor, capture=True)

    def margin(x):
        return float(x[-1, target] - x[-1, foil])

    def summarize(x, y, expected, ablation=False):
        stats = measured_logits(x, y, gates)
        m1, m2 = margin(x), margin(y)
        if ablation:
            e1, e2 = margin(baseline) - m1, margin(baseline_hf) - m2
        else:
            e1, e2 = m1 - margin(baseline), m2 - margin(baseline_hf)
        diff = max(abs(e1 - expected), abs(e2 - expected))
        stats.update(numpy_margin=m1, hf_margin=m2, numpy_effect=e1, hf_effect=e2, original_effect=expected,
                     max_effect_error_vs_original=diff,
                     passed=stats["passed"] and diff <= gates["margin_effect_vs_original_max_abs_error"])
        return stats

    stats = measured_logits(baseline, baseline_hf, gates)
    original_base = original["baseline_margin"][index]
    base_error = max(abs(margin(baseline) - original_base), abs(margin(baseline_hf) - original_base))
    stats.update(numpy_margin=margin(baseline), hf_margin=margin(baseline_hf), original_margin=original_base,
                 max_abs_margin_error_vs_original=base_error,
                 passed=stats["passed"] and base_error <= gates["margin_effect_vs_original_max_abs_error"])
    measured = {"group": group, "index": index, "text": text, "token_ids": ids, "baseline": stats,
                "baseline_intermediates": compare_intermediates(intermediate, intermediate_hf, gates)}
    baseline_noop_np = numpy_model.forward(ids, {site: acts[site].copy()}, capture=False)["logits"]
    baseline_noop_hf, _ = hf_forward(hf, tensor, layer=layer, add=np.zeros(768, dtype=np.float32))
    no_ops = {"torch_observation": float(abs(plain - baseline_hf).max()),
              "torch_zero": float(abs(plain - baseline_noop_hf).max()),
              "numpy_self_patch": float(abs(baseline - baseline_noop_np).max())}
    raw = {"numpy_baseline_logits": baseline, "hf_baseline_logits": baseline_hf}
    for prefix, arrays in (("numpy_base", intermediate), ("hf_base", intermediate_hf)):
        raw.update({prefix + "_" + k: v for k, v in arrays.items()})
    hidden = intermediate[f"blocks.{layer}.hidden_before_edit"]
    measured["ablations"] = []
    for n, neuron in enumerate([selected, *selection["random_neurons_same_layer"]]):
        proj = acts[site].copy()
        proj[-1] -= hidden[-1, neuron] * w[neuron]
        zero_hidden = hidden.copy()
        zero_hidden[-1, neuron] = 0.
        recomputed = zero_hidden @ w + bias
        desired = (original["exact_ablation_margin_decrease"][index] if n == 0 else
                   original["random_neuron_margin_decrease"][n - 1][index])
        modified = numpy_model.forward(ids, {site: proj}, capture=n == 0)
        y, traces = hf_forward(hf, tensor, capture=n == 0, layer=layer, neuron=neuron)
        row = summarize(modified["logits"], y, desired, ablation=True)
        projection_error = float(abs(recomputed - proj).max())
        row.update(neuron=neuron, numpy_activation=float(hidden[-1, neuron]),
                   hf_activation=float(intermediate_hf[f"blocks.{layer}.hidden_before_edit"][-1, neuron]),
                   within_numpy_projection_max_abs_error=projection_error,
                   passed=row["passed"] and projection_error <= gates["same_numpy_projection_max_abs_error"])
        measured["ablations"].append(row)
        if n == 0:
            np_traces = intermediate_numpy(numpy_model, modified["activations"])
            measured["selected_ablation_intermediates"] = compare_intermediates(np_traces, traces, gates)
            raw.update(numpy_ablation_logits=modified["logits"], hf_ablation_logits=y)
            for prefix, arrays in (("numpy_ablated", np_traces), ("hf_ablated", traces)):
                raw.update({prefix + "_" + k: v for k, v in arrays.items()})
    measured["direction_additions"] = []
    for layer_index in range(numpy_model.n_layer):
        injection_site = f"blocks.{layer_index}.mlp_out"
        original_layer = original["cross_layer"][layer_index]
        require(original_layer["layer"] == layer_index, "Original cross-layer record out of order")
        for vector_number, vec in enumerate([selection["direction"], *selection["random_directions"]]):
            vector = np.asarray(vec, dtype=np.float32)
            replacement = acts[injection_site].copy()
            replacement[-1] += vector
            x = numpy_model.forward(ids, {injection_site: replacement}, capture=False)["logits"]
            y, _ = hf_forward(hf, tensor, layer=layer_index, add=vector)
            expected = (original_layer["chosen_delta"][index] if vector_number == 0
                        else original_layer["random_delta"][vector_number - 1][index])
            row = summarize(x, y, expected)
            row.update(layer=layer_index, direction=vector_number,
                       input_vector_sha256=array_hash(vector))
            measured["direction_additions"].append(row)
    restored_hf, _ = hf_forward(hf, tensor)
    restored_np = numpy_model.forward(ids, capture=False)["logits"]
    no_ops.update(torch_restored=float(abs(plain - restored_hf).max()),
                  numpy_restored=float(abs(baseline - restored_np).max()))
    measured["no_op_errors"] = no_ops
    measured["passed"] = (
        stats["passed"] and all(row["passed"] for row in measured["ablations"] + measured["direction_additions"])
        and all(row["passed"] for row in [*measured["baseline_intermediates"].values(),
                                          *measured["selected_ablation_intermediates"].values()])
        and all(v == 0. for v in no_ops.values())
    )
    trace_file = out / f"{group}-{index}.npz"
    np.savez_compressed(trace_file, **raw)
    measured["trace_sha256"] = sha(trace_file)
    save(out / f"{group}-{index}.json", measured)
    return measured


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(exist_ok=False)
    registration = Path(__file__).with_name("protocol.json")
    require(sha(registration) == REGISTRATION_SHA, "Cross-engine registration changed")
    gates = load(registration)
    protocol, selection, result = verify_frozen(args.run)
    if protocol is None:
        save(args.out / "summary.json", {"status": "SKIPPED_ORIGINAL_GATE", "source_status": result["status"],
                                         "heldout_engine_calls": 0, "registration_sha256": REGISTRATION_SHA})
        return 2
    for file, expected in SOURCE_SHA.items():
        require(sha(args.release / file) == expected, f"Recovered implementation differs: {file}")
    sys.path.insert(0, str(args.release.resolve()))
    from neuralscope.pretrained import load_pinned_model
    from neuralscope.core import GPT2Model
    import torch
    import transformers
    from transformers import GPT2LMHeadModel

    require(os.environ.get("HF_HUB_OFFLINE") == "1", "Offline execution required")
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    config, weights, provenance = load_pinned_model(args.model)
    numpy_model = GPT2Model(config, weights)
    require(numpy_model.parameter_count == protocol["model_parameters"] == 81912576, "Parameter count")
    for name, identity in provenance["files"].items():
        require(protocol["metadata"]["model_file_sha256"][name] == identity["sha256"], "Protocol pins")
    require(protocol["metadata"]["revision"] == provenance["revision"], "Protocol model revision")
    hf = GPT2LMHeadModel.from_pretrained(str(args.model), local_files_only=True, use_safetensors=True,
                                         attn_implementation="eager").float().eval()
    require(sum(p.numel() for p in hf.parameters()) == 81912576, "HF model parameter count")
    from tokenizers import Tokenizer
    tokenizer = Tokenizer.from_file(str(args.model / "tokenizer.json"))
    target, foil = protocol["target"], protocol["foil"]
    require([tokenizer.encode(s, add_special_tokens=False).ids for s in (" Paris", " Berlin")] == [[target], [foil]],
            "Target or foil token ID mismatch")
    inputs = {"registration_sha256": REGISTRATION_SHA, "recovered_source_sha256": SOURCE_SHA,
              "script_sha256": sha(Path(__file__)), "model": provenance, "numpy_version": np.__version__,
              "torch_version": torch.__version__, "transformers_version": transformers.__version__,
              "run_artifact_sha256": {f: sha(args.run / f) for f in
                                      ("protocol.json", "discovery.json", "selection.json", "results.json")}}
    save(args.out / "inputs.json", inputs)
    cases = []
    for group in GROUPS:
        batch = protocol["batches"][group]
        texts = protocol["metadata"]["texts"][group]
        require(len(texts) == 4, "Unexpected held-out template count")
        for i, text in enumerate(texts):
            ids = tokenizer.encode(text, add_special_tokens=False).ids
            padding = len(batch["input_ids"][i]) - len(ids)
            mask = batch["attention_mask"][i]
            pos = batch["position_ids"][i]
            require(mask == [0] * padding + [1] * len(ids), "Attention mask mismatch")
            require(pos == [0] * padding + list(range(len(ids))), "Position IDs mismatch")
            require(batch["input_ids"][i] == [config["eos_token_id"]] * padding + ids, "Input IDs mismatch")
            print(group, i, flush=True)
            measured = run_case(numpy_model, hf, ids, i, group, selection, result["validation"][group],
                                target, foil, args.out, gates, text)
            traces = [measured["baseline"], *measured["ablations"], *measured["direction_additions"]]
            intermediates = [*measured["baseline_intermediates"].values(),
                             *measured["selected_ablation_intermediates"].values()]
            cases.append({"group": group, "index": i, "passed": measured["passed"],
                          "intermediate_arrays": len(intermediates), "logit_arrays": len(traces),
                          "maximum_logit_error": max(r["max_abs"] for r in traces),
                          "maximum_logit_rmse": max(r["rmse"] for r in traces),
                          "maximum_intermediate_scaled_error": max(r["max_scaled_error"] for r in intermediates),
                          "max_effect_error_vs_original": max(r["max_effect_error_vs_original"] for r in traces[1:]),
                          "max_within_numpy_projection_error": max(r["within_numpy_projection_max_abs_error"]
                                                                  for r in measured["ablations"]),
                          "selected_numpy_effect": measured["ablations"][0]["numpy_effect"],
                          "selected_reference_effect": measured["ablations"][0]["hf_effect"],
                          "selected_original_effect": measured["ablations"][0]["original_effect"]})
    passed = all(c["passed"] for c in cases)
    save(args.out / "summary.json", {"status": "CROSS_ENGINE_AGREEMENT" if passed else "CROSS_ENGINE_MISMATCH",
                                     "registration_sha256": REGISTRATION_SHA, "cases": cases,
                                     "compared_logit_arrays": sum(c["logit_arrays"] for c in cases),
                                     "compared_intermediate_arrays": sum(c["intermediate_arrays"] for c in cases)})
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())

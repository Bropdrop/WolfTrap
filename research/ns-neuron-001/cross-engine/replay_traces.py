"""Replay complete baseline and selected arrays in a new process and compare stored bytes."""
from pathlib import Path
import argparse
import os
import sys
import numpy as np
from compare import (
    GROUPS, REGISTRATION_SHA, SOURCE_SHA, array_hash, hf_forward, intermediate_numpy,
    load, require, save, sha, verify_frozen,
)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--release", type=Path, required=True)
    ap.add_argument("--original", type=Path, required=True)
    ap.add_argument("--measured", type=Path, required=True)
    ap.add_argument("--model", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    out = args.out
    out.mkdir(exist_ok=False)
    require(os.environ.get("HF_HUB_OFFLINE") == "1", "Offline execution required")
    frozen, sel, _ = verify_frozen(args.original)
    require(frozen is not None, "Original numerical checks incomplete")
    measurements = load(args.measured / "inputs.json")
    require(sha(Path(__file__).with_name("compare.py")) == measurements["script_sha256"], "Measurement source changed")
    require(sha(Path(__file__).with_name("protocol.json")) == REGISTRATION_SHA, "Registration changed")
    require(all(sha(args.release / p) == expected for p, expected in SOURCE_SHA.items()), "Release changed")
    require(all(sha(args.original / p) == expected for p, expected in measurements["run_artifact_sha256"].items()),
            "Original run inputs changed")
    sys.path.insert(0, str(args.release.resolve()))
    import torch
    from transformers import GPT2LMHeadModel
    from neuralscope.core import GPT2Model
    from neuralscope.pretrained import load_pinned_model

    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    config, weights, provenance = load_pinned_model(args.model)
    require(provenance == measurements["model"], "Model custody mismatch")
    reference = GPT2LMHeadModel.from_pretrained(str(args.model), local_files_only=True, use_safetensors=True,
                                                attn_implementation="eager").float().eval()
    candidate = GPT2Model(config, weights)
    layer, neuron = sel["layer"], sel["neuron"]
    weight = candidate.weights[f"transformer.h.{layer}.mlp.c_proj.weight"][neuron]
    site = f"blocks.{layer}.mlp_out"
    summaries = []
    matched = True
    for group in GROUPS:
        for i, mask in enumerate(frozen["batches"][group]["attention_mask"]):
            ids = [x for x, real in zip(frozen["batches"][group]["input_ids"][i], mask, strict=True) if real]
            tensor = torch.tensor([ids])
            key = f"{group}-{i}"
            print(key, flush=True)
            baselines = candidate.forward(ids)
            traces = intermediate_numpy(candidate, baselines['activations'])
            original = baselines['activations'][site]
            sub = original.copy()
            sub[-1] -= traces[f"blocks.{layer}.hidden_before_edit"][-1, neuron] * weight
            adjusted = candidate.forward(ids, patches={site: sub})
            hf_base, base_taps = hf_forward(reference, tensor, capture=True)
            hf_changed, edit_taps = hf_forward(reference, tensor, capture=True, layer=layer, neuron=neuron)
            data = {'numpy_baseline_logits': baselines['logits'], 'hf_baseline_logits': hf_base,
                    'numpy_ablation_logits': adjusted['logits'], 'hf_ablation_logits': hf_changed}
            replay_acts = intermediate_numpy(candidate, adjusted['activations'])
            for prefix, values in (('numpy_base', traces), ('hf_base', base_taps),
                                   ('numpy_ablated', replay_acts), ('hf_ablated', edit_taps)):
                data.update({prefix + '_' + k: v for k, v in values.items()})
            record = load(args.measured / f"{key}.json")
            saved = args.measured / f"{key}.npz"
            require(sha(saved) == record["trace_sha256"], "Saved trace digest mismatch")
            records = {}
            with np.load(saved, allow_pickle=False) as archived:
                require(set(archived.files) == set(data), "Trace array inventory changed")
                for name, actual in data.items():
                    stored = archived[name]
                    same_structure = actual.shape == stored.shape and actual.dtype == stored.dtype
                    maximum = float(abs(actual.astype(np.float64) - stored).max()) if same_structure else None
                    equal = same_structure and array_hash(actual) == array_hash(stored)
                    records[name] = {"same_float32_bytes": equal, "shape": list(actual.shape),
                                     "max_abs": maximum, "replayed_sha256": array_hash(actual)}
                    matched = matched and equal
            summaries.append({"case": key, "compared": len(records),
                              "same_float32_bytes": all(r["same_float32_bytes"] for r in records.values())})
            save(out / f"{key}.json", records)
    save(out / "summary.json", {"all_arrays_bitwise_equal": matched, "cases": summaries,
                                "arrays_compared": sum(row["compared"] for row in summaries),
                                "script_sha256": sha(Path(__file__)), "registration_sha256": REGISTRATION_SHA,
                                "scope": "Both engines' complete unpadded baseline and selected-ablation logits and observed intermediates; same deterministic runtime in a separate process."})
    return 0 if matched else 2


if __name__ == "__main__":
    sys.exit(main())

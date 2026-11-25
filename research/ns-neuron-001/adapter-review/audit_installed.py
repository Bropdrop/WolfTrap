"""Inspect the installed adapter and verify the pinned model on discovery data."""

import argparse
import hashlib
import inspect
import json
import platform
import sys
from pathlib import Path

import torch
import transformers
from safetensors import safe_open
from transformers import AutoTokenizer


def digest(path):
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def method_origin(method):
    method = inspect.unwrap(method)
    path = inspect.getsourcefile(method)
    lines, line_no = inspect.getsourcelines(method)
    return {
        "method": method.__qualname__,
        "file": path.split("/site-packages/")[-1],
        "file_sha256": digest(path),
        "first_line": line_no,
        "method_sha256": hashlib.sha256("".join(lines).encode()).hexdigest(),
    }


def emit(out, name, data):
    (out / name).write_text(json.dumps(data, indent=2, sort_keys=True, allow_nan=False) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out
    out.mkdir(exist_ok=False)
    pilot = Path(__file__).resolve().parents[1] / "pilot"
    sys.path.insert(0, str(pilot))
    source_hash = digest(pilot / "neuron_probe.py")
    if source_hash != "6372d218768d98f487bf89e41230da111bcb16532a8d95818796043f962ef8ce":
        raise ValueError("Unexpected adapter digest")
    import neuron_probe as n
    n.configure()
    model, batches, target, foil, metadata = n.pretrained_batches(args.model_dir)
    projections = n.projections(model)
    block = model.transformer.h[0]
    methods = [model.forward, model.transformer.forward, block.forward, block.mlp.forward, projections[0].forward]
    emit(out, "loaded.json", {
        "adapter_sha256": source_hash, "python": sys.version, "platform": platform.platform(),
        "transformers": transformers.__version__, "torch": torch.__version__,
        "class": type(model).__name__, "architecture": model.config.model_type,
        "parameter_count": sum(p.numel() for p in model.parameters()), "training": model.training,
        "parameter_dtypes": sorted({str(p.dtype) for p in model.parameters()}),
        "attn_implementation": model.config._attn_implementation,
        "projection_classes": [type(p).__name__ for p in projections],
        "weight_shapes": [list(p.weight.shape) for p in projections],
        "methods": [method_origin(f) for f in methods],
    })
    assert len(projections) == 6 and all(tuple(p.weight.shape) == (3072, 768) for p in projections)
    assert not model.training and all(p.dtype == torch.float32 and p.device.type == "cpu" for p in model.parameters())
    with safe_open(str(args.model_dir / "model.safetensors"), framework="pt", device="cpu") as checkpoint:
        state = model.state_dict(keep_vars=True)
        checked, unbound = {}, []
        for name, value in model.named_parameters():
            aliases = [alias for alias, other in state.items() if other is value]
            match = next((key for key in [name, *aliases] if key in checkpoint.keys()), None)
            if match is None:
                unbound.append(name)
            else:
                checked[name] = {"checkpoint_key": match, "equal": torch.equal(value, checkpoint.get_tensor(match))}
    emit(out, "parameter-bindings.json", {"checked": checked, "unbound": unbound})
    if unbound or not all(row["equal"] for row in checked.values()):
        raise ValueError("Unable to bind all loaded trainable parameters to checkpoint arrays")
    tokenizer = AutoTokenizer.from_pretrained(str(args.model_dir), local_files_only=True, trust_remote_code=False)
    tokens = {}
    for group, texts in metadata["texts"].items():
        rows = []
        for idx, text in enumerate(texts):
            expected = tokenizer(text, add_special_tokens=False)["input_ids"]
            batch = batches[group]
            take = len(expected)
            pad_n = batch["input_ids"].shape[1] - take
            ids = batch["input_ids"][idx].tolist()
            mask = batch["attention_mask"][idx].tolist()
            pos = batch["position_ids"][idx].tolist()
            rows.append({"text": text, "single_ids": expected, "batch_token_ids": ids, "mask": mask,
                         "position_ids": pos, "aligned": ids == [tokenizer.eos_token_id] * pad_n + expected
                         and mask == [0] * pad_n + [1] * take and pos == [0] * pad_n + list(range(take))})
        tokens[group] = rows
    targets = {text: tokenizer(text, add_special_tokens=False)["input_ids"] for text in [" Paris", " Berlin"]}
    emit(out, "tokenization.json", {"tokenizer": type(tokenizer).__name__, "eos_token_id": tokenizer.eos_token_id,
         "targets": targets, "target": target, "foil": foil, "groups": tokens})
    assert targets == {" Paris": [target], " Berlin": [foil]} and target != foil
    assert all(row["aligned"] for group in tokens.values() for row in group)
    _, activation, projected = n.capture(model, batches["discovery_positive"])
    records = []
    for layer, p in enumerate(projections):
        predicted = torch.nn.functional.linear(activation[layer], p.weight.detach().T, p.bias.detach())
        records.append({"layer": layer, "input_shape": list(activation[layer].shape),
                        "output_shape": list(projected[layer].shape),
                        "max_abs": (projected[layer] - predicted).abs().max().item()})
    emit(out, "discovery-projections.json", {"limit_from_pilot": 1e-4, "layers": records})
    assert all(row["max_abs"] <= 1e-4 for row in records)
    n.verify_pins(args.model_dir)
    print("Installed-source locations, loaded parameters, tokenizer alignment and six discovery projections verified.")


if __name__ == "__main__":
    main()

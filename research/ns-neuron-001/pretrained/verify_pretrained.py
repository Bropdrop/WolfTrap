"""Supplemental offline parity audit for a frozen run of the original NS-NEURON-001 pilot."""
import argparse
import ast
from contextlib import ExitStack, contextmanager
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import random
import shutil
import statistics
import sys
import tempfile
import traceback

HERE = Path(__file__).resolve().parent
SOURCE = {
    "neuron_probe.py": "6372d218768d98f487bf89e41230da111bcb16532a8d95818796043f962ef8ce",
    "review_evidence.py": "64d04f7f40bc98f149d3fdd7ee38e7c9feba3a8ea4192f1a1408e7d0428233fe",
    "test_neuron_probe.py": "1d3e38d115f4c954318b66611565a8d63f99b9402f9763d37cfd1284c3aa2027",
}
REV = "2290a62682d06624634c1f46a6ad5be0f47f38aa"
SEED = 17023
LIMITS = {  # absolute max over every compared element; established before access to the model
    "batch_singleton": 5e-4, "ablation_subtraction": 5e-4, "projection": 1e-4,
    "noop": 1e-5, "reported_effect": 5e-4, "score": 1e-4, "direction": 1e-6,
    "gradient_fd": 0.04,
}
TEMPLATES = {
    "discovery": ["The capital of {} is", "The national capital of {} is", "{} has its capital in", "The capital city of {} is"],
    "validation": ["What is the capital of {}? It is", "The seat of government in {} is in", "The capital city located in {} is", "If asked to name the capital of {}, I would say"],
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def save(path, obj):
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, allow_nan=False) + "\n")


def pin_model(path, pins):
    require(path.is_dir(), f"Missing pinned model directory: {path}")
    require({f.name for f in path.iterdir()} == set(pins), "Model inventory differs from the seven pinned files")
    for name, digest in pins.items():
        require((path / name).is_file() and sha(path / name) == digest, f"Model hash mismatch: {name}")


def verify_source(path):
    require(all((path / n).is_file() and sha(path / n) == v for n, v in SOURCE.items()), "Pilot source hash mismatch")
    tree = ast.parse((path / "neuron_probe.py").read_text())
    literals = {stmt.targets[0].id: ast.literal_eval(stmt.value) for stmt in tree.body
                if isinstance(stmt, ast.Assign) and isinstance(stmt.targets[0], ast.Name)
                and stmt.targets[0].id in ("PINS", "PIN_REV")}
    require(literals["PIN_REV"] == REV and len(literals["PINS"]) == 7, "Unexpected pilot model pin metadata")
    return literals["PINS"]


@contextmanager
def local_copy(model_dir, pins):
    with tempfile.TemporaryDirectory(prefix="ns-neuron-pinned-") as tmp:
        stage = Path(tmp)
        try:
            for n in pins:
                shutil.copyfile(model_dir / n, stage / n)
                (stage / n).chmod(0o444)
            stage.chmod(0o555)
            pin_model(stage, pins)
            yield stage
            pin_model(stage, pins)
        finally:
            stage.chmod(0o700)


def frozen_inputs(args):
    require(args.run_dir and args.selection_sha256 and args.results_sha256,
            "Verification requires the original run and independently recorded selection and results SHA-256 values")
    names = ["protocol", "discovery", "selection", "results"]
    blobs = {n: (args.run_dir / f"{n}.json").read_bytes() for n in names}
    hashes = {n: hashlib.sha256(blob).hexdigest() for n, blob in blobs.items()}
    require(hashes["selection"] == args.selection_sha256 and hashes["results"] == args.results_sha256,
            "Frozen selection or results hash differs from the supplied digest")
    p, d, s, r = (json.loads(blobs[n]) for n in names)
    require(s["status"] == "SELECTED", f"Pilot has no eligible selection: {s['status']}")
    require(s["protocol_sha256"] == hashes["protocol"] and s["discovery_sha256"] == hashes["discovery"] and
            r["selection_sha256"] == hashes["selection"], "Broken protocol/discovery/selection/results hash binding")
    require(r["status"] == "MEASURED" and r["validation_executed"] and r["mechanism_checks_passed"],
            "Pilot reported a negative result or failed mechanistic checks; stop qualification")
    return p, d, s, r, hashes


class Audit:
    def __init__(self, out, data, torch):
        self.out, self.data, self.torch = out, data, torch
        self.trace = {}
        self.errors = []
        self.worst = {}
        self.cases = {}

    def compare(self, name, actual, expected, kind):
        t = self.torch
        expected = t.as_tensor(expected, dtype=actual.dtype)
        require(actual.shape == expected.shape, f"Shape mismatch: {name}")
        diff = (actual.detach() - expected.detach()).abs()
        error = float(diff.max())
        if not t.isfinite(diff).all():
            self.errors.append({"comparison": name, "nonfinite": True})
            raise ArithmeticError(f"Nonfinite values at {name}")
        if kind not in self.worst or self.worst[kind]["error"] < error:
            self.worst[kind] = {"comparison": name, "error": error}
        self.data["comparison_count"] += 1
        if error > LIMITS[kind]:
            self.errors.append({"comparison": name, "error": error, "limit": LIMITS[kind]})

    def capture(self, name, tensor):
        value = tensor.detach().cpu().contiguous().numpy()
        self.trace[name] = {"shape": list(value.shape), "dtype": str(value.dtype),
                            "sha256": hashlib.sha256(memoryview(value).cast("B")).hexdigest()}

    def flush(self):
        self.data.update(worst_absolute_error=self.worst, failed_comparisons=self.errors)
        save(self.out / "tensor-trace.json", self.trace)
        save(self.out / "per-case.json", self.cases)


def hook_counts(model):
    return [(len(m._forward_pre_hooks), len(m._forward_hooks)) for m in model.modules()]


def model_state(model):
    inventory = {}
    for k, v in model.state_dict().items():
        a = v.detach().cpu().contiguous().numpy()
        inventory[k] = [str(a.dtype), list(a.shape), hashlib.sha256(memoryview(a).cast("B")).hexdigest()]
    return inventory


def forward(model, inputs, proj=None, neuron=None, mode="observe", direction=None):
    """Capture the effective projection input and output after any intervention, removing every hook."""
    record = {}
    def before(module, args):
        activation = args[0]
        if mode == "zero":
            activation = activation.clone()
            activation[:, -1, neuron] = 0
        record["input"] = activation.detach()
        return (activation,) if mode == "zero" else None

    def after(module, args, output):
        if mode in ("subtract", "inject"):
            output = output.clone()
            if mode == "subtract":
                output[:, -1] -= args[0][:, -1, neuron, None] * module.weight[neuron]
            else:
                output[:, -1] += direction
        record["output"] = output.detach()
        return output if mode in ("subtract", "inject") else None

    counts = hook_counts(model)
    try:
        with ExitStack() as stack:
            if proj is not None:
                stack.callback(proj.register_forward_pre_hook(before).remove)
                stack.callback(proj.register_forward_hook(after).remove)
            logits = model(**inputs, use_cache=False).logits.detach()
            return logits, record
    finally:
        require(hook_counts(model) == counts, "Forward hook inventory changed")


def gradients(model, batch, modules, target, foil, torch):
    activations = {}
    def remember(i):
        def pre(module, args):
            activations[i] = args[0]
        return pre
    with torch.enable_grad(), ExitStack() as stack:
        for i, m in enumerate(modules):
            stack.callback(m.register_forward_pre_hook(remember(i)).remove)
        y = model(**batch, use_cache=False).logits[:, -1]
        inputs = [activations[i] for i in range(len(modules))]
        derivatives = torch.autograd.grad((y[:, target] - y[:, foil]).sum(), inputs)
        return [(a[:, -1] * g[:, -1]).detach() for a, g in zip(inputs, derivatives)]


def tokenize(tok, p, torch):
    ids = [tok.encode(x, add_special_tokens=False) for x in [" Paris", " Berlin"]]
    require(ids == [[p["target"]], [p["foil"]]] and p["target"] != p["foil"], "Target or foil token mismatch")
    expected_groups = {f"{split}_{group}" for split in TEMPLATES for group in ("positive", "control")}
    require(set(p["batches"]) == expected_groups and set(p["metadata"]["texts"]) == expected_groups, "Group inventory changed")
    batches = {}
    for split, patterns in TEMPLATES.items():
        for group, country in [("positive", "France"), ("control", "Germany")]:
            key = f"{split}_{group}"
            text = [pattern.format(country) for pattern in patterns]
            require(text == p["metadata"]["texts"][key], f"Prompts changed: {key}")
            tokens = [tok.encode(row, add_special_tokens=False) for row in text]
            width = max(map(len, tokens))
            require(tok.eos_token_id is not None and all(tokens), "Missing EOS or empty token sequence")
            raw = {"input_ids": [], "attention_mask": [], "position_ids": []}
            for row in tokens:
                n = width - len(row)
                raw["input_ids"].append([tok.eos_token_id] * n + row)
                raw["attention_mask"].append([0] * n + [1] * len(row))
                raw["position_ids"].append([0] * n + list(range(len(row))))
            require(raw == p["batches"][key], f"Token IDs, left padding, mask or position mismatch: {key}")
            batches[key] = ({k: torch.tensor(v, dtype=torch.long) for k, v in raw.items()}, tokens)
    return batches


def selection_check(d, s):
    scores = d["all_first_order_scores"]
    require(len(scores) == 18432 and {(i,j) for _,i,j in scores} ==
            {(i,j) for i in range(6) for j in range(3072)}, "Incomplete discovery inventory")
    require(scores == sorted(scores, key=lambda x: (-x[0], x[1], x[2])), "Incorrect discovery ranking")
    exact = d["exact_shortlist"]
    require(len(exact) == 8 and {(v["layer"], v["neuron"]) for v in exact} ==
            {(i,j) for _,i,j in scores[:8]}, "Exact shortlist disagrees with discovery")
    for v in exact:
        require(len(v["per_prompt"]) == 4 and abs(statistics.mean(v["per_prompt"])-v["exact_mean"]) < 1e-5,
                "Incorrect discovery exact mean")
    winner = min(exact, key=lambda v: (-v["exact_mean"], v["layer"], v["neuron"]))
    require(winner["exact_mean"] > 1e-4 and (winner["layer"], winner["neuron"], winner["exact_mean"]) ==
            (s["layer"], s["neuron"], s["discovery_exact_mean"]), "Frozen neuron differs from discovery winner")
    rng = random.Random(SEED + 2)
    expected_controls = rng.sample([j for j in range(3072) if j != s["neuron"]], 6)
    require(expected_controls == s["random_neurons_same_layer"], "Control neuron draw differs from fixed seed")
    return {(v["layer"], v["neuron"]): v for v in exact}


def audit_group(a, model, modules, key, batch, rows, s, p, d, report, shortlist):
    t = a.torch
    l, j = s["layer"], s["neuron"]
    target, foil = p["target"], p["foil"]
    def margin(logits):
        return logits[:, -1, target] - logits[:, -1, foil]
    base, _ = forward(model, batch)
    bm = margin(base)
    a.capture(f"{key}/baseline", base)
    singles = [{"input_ids": t.tensor([row])} for row in rows]  # default causal mask and positions
    case = {"baseline_margin": bm.tolist(), "exact_margin_decreases": {}}
    a.cases[key] = case
    for n, inp in enumerate(singles):
        y, _ = forward(model, inp)
        a.compare(f"{key}/baseline/{n}", y[0], base[n, -len(rows[n]):], "batch_singleton")
        a.capture(f"{key}/baseline/singleton-{n}", y)
    cases = {(l, j)}
    is_val = key.startswith("validation")
    if key == "discovery_positive":
        a.compare(f"{key}/reported-baseline", bm, d["baseline_margin"], "reported_effect")
        cases.update(shortlist)
    if is_val:
        expected = report["validation"][key]
        a.compare(f"{key}/reported-baseline", bm, expected["baseline_margin"], "reported_effect")
        expected_id = target if key.endswith("positive") else foil
        require(int((base[:,-1].argmax(-1)==expected_id).sum()) == expected["baseline_expected_token_top1_count"],
                f"Baseline label count differs: {key}")
        cases.update((l, n) for n in s["random_neurons_same_layer"])
    if key == "discovery_positive" or is_val:
        scores = gradients(model, batch, modules, target, foil, t)
        a.capture(f"{key}/scores", t.stack(scores))
        if is_val:
            a.compare(f"{key}/first-order", scores[l][:,j], expected["first_order_prediction"], "score")
        else:
            means = t.stack([x.mean(0) for x in scores])
            historical = t.empty_like(means)
            for score, i, n in d["all_first_order_scores"]:
                historical[i,n] = score
            a.compare(f"{key}/score-inventory", means, historical, "score")
            save(a.out / "review-discovery-scores.json", means.tolist())
            ranking = sorted(((v, i, n) for i, layer in enumerate(means.tolist()) for n, v in enumerate(layer)),
                             key=lambda x: (-x[0], x[1], x[2]))
            require([(i, n) for _, i, n in ranking[:8]] == [(i, n) for _, i, n in d["all_first_order_scores"][:8]],
                    "Fresh first-order shortlist differs")
    for i, n in sorted(cases):
        name = f"{key}/L{i}N{n}"
        proj = modules[i]
        observed, clean = forward(model, batch, proj)
        a.compare(f"{name}/hooked-baseline", observed, base, "noop")
        a.compare(f"{name}/projection", clean["input"] @ proj.weight + proj.bias, clean["output"], "projection")
        zero, z = forward(model, batch, proj, n, "zero")
        sub, sub_record = forward(model, batch, proj, n, "subtract")
        changed = clean["input"].clone()
        changed[:, -1, n] = 0
        a.compare(f"{name}/zeroed-input", z["input"], changed, "noop")
        a.compare(f"{name}/subtraction-input", sub_record["input"], clean["input"], "noop")
        a.compare(f"{name}/projection-parity", z["output"], sub_record["output"], "projection")
        a.compare(f"{name}/logit-parity", zero, sub, "ablation_subtraction")
        for label, tensor in [("input", clean["input"]), ("output", clean["output"]), ("zero-output", z["output"]),
                              ("subtract-output", sub_record["output"]), ("zero-logits", zero), ("subtract-logits", sub)]:
            a.capture(f"{name}/{label}", tensor)
        for k, inp in enumerate(singles):
            y, values = forward(model, inp, proj, n, "zero")
            for field, value in [("input", values["input"]), ("output", values["output"]), ("logits", y)]:
                wanted = zero if field == "logits" else z[field]
                a.compare(f"{name}/singleton-{k}/{field}", value[0], wanted[k, -len(rows[k]):], "batch_singleton")
                a.capture(f"{name}/singleton-{k}/{field}", value)
        actual = bm - margin(zero)
        case["exact_margin_decreases"][f"{i},{n}"] = actual.tolist()
        if key == "discovery_positive":
            a.compare(f"{name}/effects", actual, shortlist[i,n]["per_prompt"], "reported_effect")
            if (i,n) == (l,j):
                w = proj.weight[n]
                act = clean["input"][:, -1, n]
                sign = 1 if float(act.mean()) >= 0 else -1
                norm = act.abs().median() * w.norm()
                require(sign == s["sign"], "Direction sign disagrees with discovery")
                a.compare("direction-norm", norm, s["direction_norm"], "direction")
                a.compare("chosen-direction", sign * norm * w / w.norm(), s["direction"], "direction")
                gen = t.Generator().manual_seed(SEED + 3)
                directions = t.randn((6, 768), generator=gen)
                directions = directions / directions.norm(dim=1, keepdim=True) * norm
                a.compare("control-directions", directions, s["random_directions"], "direction")
        if is_val:
            row = expected["exact_ablation_margin_decrease"] if n == j else expected["random_neuron_margin_decrease"][s["random_neurons_same_layer"].index(n)]
            a.compare(f"{name}/effects", actual, row, "reported_effect")
    if key == "discovery_positive":
        measured = [(statistics.mean(case["exact_margin_decreases"][f"{i},{n}"]), i, n) for i, n in cases]
        winner = min(measured, key=lambda x: (-x[0], x[1], x[2]))
        require(winner[0] > 1e-4 and winner[1:] == (l,j), "Fresh exact discovery selection differs")
    if is_val:
        original_m = expected["mechanism_checks"]
        require(original_m["finite_difference_epsilon"] == 0.002, "Unexpected finite difference step")
        w = modules[l].weight[j]
        unit = w / w.norm()
        with t.enable_grad():
            scale = t.zeros(len(rows), requires_grad=True)
            def perturb(_, args, output):
                out = output.clone()
                out[:, -1] += scale[:, None] * unit
                return out
            with ExitStack() as stack:
                stack.callback(modules[l].register_forward_hook(perturb).remove)
                perturbed = model(**batch, use_cache=False).logits
                grad, = t.autograd.grad(margin(perturbed).sum(), scale)
        plus, _ = forward(model, batch, modules[l], mode="inject", direction=0.002 * unit)
        minus, _ = forward(model, batch, modules[l], mode="inject", direction=-0.002 * unit)
        fd = (margin(plus) - margin(minus)) / 0.004
        a.compare(f"{key}/gradient-vs-finite-difference", grad, fd, "gradient_fd")
        a.compare(f"{key}/reported-gradient", grad, original_m["gradient"], "score")
        a.compare(f"{key}/reported-finite-difference", fd, original_m["central_difference"], "gradient_fd")
        case["gradient"] = grad.tolist()
        case["central_difference"] = fd.tolist()
        case["cross_layer"] = {}
        dirs = [s["direction"], *s["random_directions"]]
        require(len(expected["cross_layer"]) == 6 and len(dirs) == 7, "Wrong layer or vector inventory")
        for i, proj in enumerate(modules):
            item = expected["cross_layer"][i]
            require(item["layer"] == i, "Cross-layer record in wrong position")
            effects = []
            for k, vector in enumerate(dirs):
                y, _ = forward(model, batch, proj, mode="inject", direction=t.tensor(vector, dtype=t.float32))
                a.capture(f"{key}/layer-{i}/direction-{k}", y)
                effects.append(margin(y) - bm)
            table = t.stack(effects)
            mean = table[1:].mean(0)
            for column, obs in [("chosen_delta", table[0]), ("random_delta", table[1:]), ("random_mean_delta", mean),
                                ("chosen_minus_random_mean", table[0] - mean)]:
                a.compare(f"{key}/layer-{i}/{column}", obs, item[column], "reported_effect")
            case["cross_layer"][str(i)] = table.tolist()
    no_op, _ = forward(model, batch, modules[l], mode="inject", direction=t.zeros(768))
    a.compare(f"{key}/no-op", no_op, base, "noop")
    a.compare(f"{key}/restored", forward(model, batch)[0], base, "noop")


def verify(args, data, pins):
    from transformers import AutoTokenizer, GPT2LMHeadModel
    from transformers.pytorch_utils import Conv1D
    import torch
    torch.set_num_threads(1)
    torch.manual_seed(SEED)
    torch.use_deterministic_algorithms(True)
    p, d, s, r, hashes = frozen_inputs(args)
    data["pilot_artifact_hashes"] = hashes
    require(p["schema"] == "NS-NEURON-001/protocol-v1" and p["seed"] == SEED and p["selection_floor"] == 1e-4
            and p["model_parameters"] == 81912576 and p["metadata"]["revision"] == REV
            and p["metadata"]["model_file_sha256"] == pins and p["metadata"]["model"] == "distilbert/distilgpt2",
            "Original protocol metadata differs from the approved pilot")
    require(p["torch"] == torch.__version__ and p["metadata"]["transformers"] == data["versions"]["transformers"],
            "Reviewer runtime differs from the runtime recorded in the frozen run")
    shortlist = selection_check(d, s)
    audit = Audit(args.out, data, torch)
    try:
        with local_copy(args.model_dir, pins) as local:
            data["phase"] = "load"
            tok = AutoTokenizer.from_pretrained(str(local), trust_remote_code=False, local_files_only=True)
            model, diagnostics = GPT2LMHeadModel.from_pretrained(
                str(local), local_files_only=True, use_safetensors=True, attn_implementation="eager", output_loading_info=True,
            )
            data["load_diagnostics"] = {k: list(v) if isinstance(v, set) else v for k, v in diagnostics.items()}
            require(not any(diagnostics.get(k) for k in ("missing_keys", "mismatched_keys", "error_msgs")),
                    "The loader reported missing or mismatched weights or a loading error")
            model = model.cpu().float().eval()
            modules = [b.mlp.c_proj for b in model.transformer.h]
            require(model.config.model_type == "gpt2" and sum(x.numel() for x in model.parameters()) == 81912576
                    and len(modules) == 6 and all(isinstance(m, Conv1D) and tuple(m.weight.shape) == (3072,768)
                    and tuple(m.bias.shape) == (768,) for m in modules), "Unexpected architecture or projection layout")
            original = model_state(model)
            save(args.out / "model-state-hashes.json", original)
            counts = hook_counts(model)
            batches = tokenize(tok, p, torch)
            with torch.no_grad():
                for key, (batch, rows) in batches.items():
                    data["phase"] = key
                    audit_group(audit, model, modules, key, batch, rows, s, p, d, r, shortlist)
                    audit.flush()
                    if audit.errors:
                        raise ArithmeticError(f"Measurement checks exceeded fixed limits during {key}")
            require(counts == hook_counts(model), "Hook state differs after review")
            require(original == model_state(model), "In-memory model state changed during measurement")
        require(frozen_inputs(args)[-1] == hashes, "Frozen inputs changed during measurement")
        require(verify_source(args.pilot_dir) == pins, "Pilot source changed during measurement")
        pin_model(args.model_dir, pins)
        if args.compare_with:
            previous = json.loads((args.compare_with / "tensor-trace.json").read_text())
            previous_report = json.loads((args.compare_with / "audit.json").read_text())
            require(previous_report["status"] == "MEASUREMENT_MATCH" and previous_report["reviewer_sha256"] == data["reviewer_sha256"]
                    and previous_report["pilot_artifact_hashes"] == hashes and previous_report["model_sha256"] == pins,
                    "Fresh-process comparison target is incompatible")
            changes = [k for k in sorted(previous.keys() | audit.trace.keys()) if previous.get(k) != audit.trace.get(k)]
            data["fresh_process_trace_comparison"] = {"arrays": len(audit.trace), "changed": changes,
                                                    "prior_trace_sha256": sha(args.compare_with / "tensor-trace.json")}
            require(not changes, "Fresh-process complete-array digests differ")
        data["phase"] = "complete"
    finally:
        audit.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--pilot-dir", type=Path, default=HERE.parent / "pilot")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--selection-sha256")
    parser.add_argument("--results-sha256")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--compare-with", type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=False)
    versions = {}
    for name in ["torch", "safetensors", "transformers", "tokenizers", "numpy"]:
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    data = {"phase": "input_preflight", "comparison_count": 0, "limits_absolute": LIMITS, "versions": versions,
            "python": sys.version, "platform": platform.platform(), "executable": sys.executable,
            "argv": sys.argv, "reviewer_sha256": sha(Path(__file__)), "source_sha256": SOURCE, "model_revision": REV}
    try:
        pins = verify_source(args.pilot_dir)
        data["model_sha256"] = pins
        pin_model(args.model_dir, pins)
        require(all(versions.values()), "Missing reviewed runtime dependencies")
        require(os.environ.get("HF_HUB_OFFLINE") == "1" and os.environ.get("TRANSFORMERS_OFFLINE") == "1",
                "Launch through the supplied offline runner in an isolated environment")
        # Loading modes alone do not isolate OS network access. Require the launcher's socket policy.
        import errno
        import socket
        try:
            sock = socket.socket()
        except OSError as exc:
            require(exc.errno == errno.EPERM, f"Unexpected socket probe errno: {exc.errno}")
        else:
            sock.close()
            raise ValueError("OS socket probe succeeded; use the offline launcher")
        if args.preflight:
            data["status"] = "INPUT_PREFLIGHT_ONLY"
        else:
            data["phase"] = "frozen_evidence"
            verify(args, data, pins)
            data["status"] = "MEASUREMENT_MATCH"
        return 0
    except Exception as exc:
        data["status"] = "BLOCKED"
        data["failure_type"] = type(exc).__name__
        data["failure"] = str(exc)
        (args.out / "failure.txt").write_text(traceback.format_exc())
        return 2
    finally:
        save(args.out / "audit.json", data)
        print(data.get("status"), data["phase"], data.get("failure", ""))


if __name__ == "__main__":
    sys.exit(main())

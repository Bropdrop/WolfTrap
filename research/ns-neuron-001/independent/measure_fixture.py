"""Discovery, frozen selection and subsequent measurement, without importing pilot code."""
import argparse
import hashlib
import json
import platform
import random
from pathlib import Path

import numpy as np
import scipy

from control_draws import generate_controls
from fixture_reference import ReferenceFixture, margin, projection_gradient


HERE = Path(__file__).resolve().parent
PILOT = HERE.parent / "pilot"
HIST = PILOT / "evidence" / "fixture-run-001"
SEED = 17023
PIN_SOURCE = "6372d218768d98f487bf89e41230da111bcb16532a8d95818796043f962ef8ce"
PIN_WEIGHTS = "04270ba8a80677b53e08219936971a6a9e1aeb3f0ece2f42f18af3db0d8129aa"
PIN_PROTOCOL = "4cf16e607fd33278732e3a3e6323552d22323f8b91cdc225808f64da4184cbea"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n")


def check(value, message):
    if not value:
        raise ValueError(message)


def effect(trace, changed):
    return margin(trace) - margin(changed)


def discover(model, rows, arrays, out):
    baseline = model.forward(rows, trace=True)
    for name, values in baseline.items():
        arrays[f"discovery.baseline.{name}"] = values
    ranked = []
    for layer in (0, 1):
        gradients = projection_gradient(model, rows, layer)
        activation = baseline[f"L{layer}.activation"][:, -1]
        scores = activation * (gradients @ model.row_matrix(layer).T)
        arrays[f"discovery.L{layer}.first_order"] = scores
        arrays[f"discovery.L{layer}.gradient"] = gradients
        for neuron, score in enumerate(scores.mean(axis=0)):
            ranked.append([float(score), layer, neuron])
    ranked.sort(key=lambda entry: (-entry[0], entry[1:]))
    shortlist = []
    for pred, layer, neuron in ranked[:8]:
        edited = model.forward(rows, layer=layer, zero=neuron)
        delta = effect(baseline, edited)
        arrays[f"discovery.ablate.L{layer}N{neuron}.logits"] = edited["logits"]
        shortlist.append(dict(layer=layer, neuron=neuron, predicted_mean=pred,
                              exact_mean=float(delta.mean()), per_prompt=delta.tolist()))
    shortlist.sort(key=lambda item: (-item["exact_mean"], item["layer"], item["neuron"]))
    write(out / "discovery.json", dict(all_first_order_scores=ranked, exact_shortlist=shortlist,
                                       baseline_margin=margin(baseline).tolist()))
    winner = shortlist[0]
    check(winner["exact_mean"] > 1e-4, "Ineligible discovery winner; stop")
    layer, neuron = winner["layer"], winner["neuron"]
    activations = baseline[f"L{layer}.activation"][:, -1, neuron]
    row = model.row_matrix(layer)[neuron]
    # torch.Tensor.median() uses the lower middle of an even count.
    lower_median = np.sort(np.abs(activations))[(len(activations)-1) // 2]
    sign = 1 if activations.mean() >= 0 else -1
    amp = float(lower_median * np.linalg.norm(row))
    check(amp > 1e-8 and np.isfinite(amp), "Degenerate contribution")
    controls, directions = generate_controls(64, neuron, amp)
    selected = dict(layer=layer, neuron=neuron, sign=sign, direction_norm=amp,
                    direction=(sign * row * lower_median).tolist(),
                    random_neurons_same_layer=controls, random_directions=directions.tolist(),
                    discovery_exact_mean=winner["exact_mean"], discovery_predicted_mean=winner["predicted_mean"],
                    discovery_sha256=sha(out / "discovery.json"), pilot_protocol_sha256=PIN_PROTOCOL)
    write(out / "selection.json", selected)


def compare_singletons(model, rows, batch, **edit):
    individual = [model.forward(row[None, :], trace=True, **edit) for row in rows]
    return {name: float(np.max(np.abs(batch[name] - np.concatenate([s[name] for s in individual]))))
            for name in batch}


def validate(model, rows, selected, arrays, batch_key):
    layer, neuron = selected["layer"], selected["neuron"]
    axis = model.row_matrix(layer)[neuron]
    unit = axis / np.linalg.norm(axis)
    base = model.forward(rows, trace=True)
    edited = model.forward(rows, layer=layer, zero=neuron, trace=True)
    activations = base[f"L{layer}.activation"]
    contribution = activations[:, -1, neuron, None] * axis
    subtracted = model.forward(rows, layer=layer, inject=-contribution, trace=True)
    control = model.forward(rows, layer=layer, inject=np.zeros(32), trace=True)
    restored = model.forward(rows, trace=True)
    for field, trace in (("baseline", base), ("ablate", edited), ("subtract", subtracted)):
        for key, value in trace.items():
            arrays[f"{batch_key}.{field}.{key}"] = value
    arrays[f"{batch_key}.contribution"] = contribution
    independent_projection = np.einsum("bti,ij->btj", activations, model.row_matrix(layer),
                                       optimize=False) + model.weights[f"transformer.h.{layer}.mlp.c_proj.bias"]
    delta = effect(base, edited)
    checks = {
        "baseline_singleton_batch": compare_singletons(model, rows, base),
        "ablation_singleton_batch": compare_singletons(model, rows, edited, layer=layer, zero=neuron),
        "zero_vector_change": {key: float(abs(value - control[key]).max()) for key, value in base.items()},
        "restored_baseline": {key: float(abs(value - restored[key]).max()) for key, value in base.items()},
        "subtraction_vs_zeroing_projected_max_abs": float(abs(edited[f"L{layer}.projected"] - subtracted[f"L{layer}.projected"]).max()),
        "subtraction_vs_zeroing_logits_max_abs": float(abs(edited["logits"] - subtracted["logits"]).max()),
        "projection_reconstruction_max_abs": float(abs(independent_projection - base[f"L{layer}.projected"]).max()),
        "prior_position_logit_change": float(abs(edited["logits"][:, :-1] - base["logits"][:, :-1]).max()),
        "trace_vs_uninstrumented_max_abs": float(abs(base["logits"] - model.forward(rows)["logits"]).max())}
    gradient = projection_gradient(model, rows, layer)
    arrays[f"{batch_key}.gradient"] = gradient
    first_order = (gradient @ axis) * activations[:, -1, neuron]
    plus = model.forward(rows, layer=layer, inject=.002 * unit)
    minus = model.forward(rows, layer=layer, inject=-.002 * unit)
    projected_gradient = gradient @ unit
    central = (margin(plus) - margin(minus)) / .004
    checks["gradient_vs_central_difference_max_abs"] = float(abs(central - projected_gradient).max())
    noise = []
    bm = margin(base)
    for control_index in selected["random_neurons_same_layer"]:
        rerun = model.forward(rows, layer=layer, zero=control_index)
        noise.append(effect(base, rerun))
        arrays[f"{batch_key}.random_neuron.N{control_index}.logits"] = rerun["logits"]
    cross = []
    for site in (0, 1):
        changes = []
        for i, direction in enumerate([selected["direction"]] + selected["random_directions"]):
            rerun = model.forward(rows, layer=site, inject=np.array(direction))
            changes.append(margin(rerun) - bm)
            arrays[f"{batch_key}.inject.L{site}.direction{i}.logits"] = rerun["logits"]
        chosen = changes[0]
        noise_effects = np.array(changes[1:])
        random_mean = noise_effects.mean(axis=0)
        cross.append(dict(layer=site, chosen_delta=chosen.tolist(), random_delta=noise_effects.tolist(),
                          random_mean_delta=random_mean.tolist(),
                          chosen_minus_random_mean=(chosen-random_mean).tolist()))
    expected = 25 if batch_key == "validation_positive" else 26
    return dict(baseline_margin=bm.tolist(), first_order_prediction=first_order.tolist(),
                exact_ablation_margin_decrease=delta.tolist(), random_neuron_margin_decrease=np.array(noise).tolist(),
                random_neuron_mean=float(np.mean(noise)), mean_exact_ablation=float(delta.mean()),
                all_exact_positive=bool(np.all(delta > 0)),
                baseline_expected_token_top1_count=int(np.count_nonzero(base["logits"][:, -1].argmax(axis=1) == expected)),
                gradient=projected_gradient.tolist(), central_difference=central.tolist(),
                cross_layer=cross, mechanism=checks)


def make_contexts(pairs):
    return {group: np.array([[index % 4 + offset, a, b, 24] for index, (a, b) in enumerate(pairs)])
            for group, offset in (("positive", 0), ("control", 4))}


def run(out):
    out.mkdir(parents=True, exist_ok=False)
    weights = HIST / "fixture.safetensors"
    files = {PILOT / "neuron_probe.py": PIN_SOURCE, weights: PIN_WEIGHTS, HIST / "protocol.json": PIN_PROTOCOL}
    for filename, expected in files.items():
        check(sha(filename) == expected, f"Identity check failed: {filename}")
    model = ReferenceFixture(weights)
    pairs = [(i, j) for i in range(8, 24) for j in range(8, 24)]
    random.Random(SEED).shuffle(pairs)
    training, discovery, validation = pairs[:232], pairs[232:244], pairs[244:]
    check(len(set(training) | set(discovery) | set(validation)) == 256, "Overlapping partitions")
    arrays = {}
    write(out / "environment.json", dict(python=platform.python_version(), numpy=np.__version__,
          scipy=scipy.__version__, platform=platform.platform(), weights_sha256=PIN_WEIGHTS,
          pilot_sha256=PIN_SOURCE, run_source_sha256={name:sha(HERE/name) for name in
             ("measure_fixture.py", "fixture_reference.py", "control_draws.py")}))
    discovery_rows = make_contexts(discovery)
    discover(model, discovery_rows["positive"], arrays, out)
    selection_path = out / "selection.json"
    frozen = sha(selection_path)
    held = make_contexts(validation)
    selected = json.loads(selection_path.read_text())
    fields = {}
    for name, rows in held.items():
        key = f"validation_{name}"
        fields[key] = validate(model, rows, selected, arrays, key)
    check(frozen == sha(selection_path), "Selection changed across validation")
    for filename, expected in files.items():
        check(sha(filename) == expected, f"Input changed: {filename}")
    write(out / "partitions.json", dict(training=training, **{
        f"{split}_{group}": values.tolist() for split, contexts in (("discovery", discovery_rows), ("validation", held))
        for group, values in contexts.items()}))
    write(out / "results.json", dict(selection_sha256=frozen, validation=fields))
    np.savez_compressed(out / "arrays.npz", **arrays)
    print(f"Saved {len(arrays)} named tensors. Frozen fixture selection L{selected['layer']} N{selected['neuron']}.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out", type=Path)
    run(parser.parse_args().out)

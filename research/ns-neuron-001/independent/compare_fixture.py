"""Compare complete fresh process artifacts and historical per-prompt measurements."""
import argparse
import json
from pathlib import Path

import numpy as np

from measure_fixture import HIST, PILOT, check, sha, write


# Fixed before running the independent measurement.
HISTORICAL_ATOL = 2e-5
HISTORICAL_FD_ATOL = 1e-3  # FP32 subtraction of nearby margins, divided by 0.004
FLOAT64_MECHANISM_ATOL = 1e-10
GRADIENT_ATOL = 1e-6


def read(path):
    return json.loads(path.read_text())


def compare(a, b, out):
    report = dict(scope="independent float64 fixture and separate-process replay",
                  history={}, functional_mechanism={}, process_replay={}, summaries={})
    failures = []
    def equal(key, value, category="history"):
        report[category][key] = bool(value)
        if not value:
            failures.append(key)
    def near(key, mine, other, tolerance=HISTORICAL_ATOL):
        x, y = np.asarray(mine), np.asarray(other)
        if x.shape != y.shape:
            raise ValueError(f"Shape mismatch for {key}: {x.shape} vs {y.shape}")
        delta = np.abs(x-y)
        report["history"][key] = dict(shape=list(x.shape), max_abs=float(delta.max()),
                                       mean_abs=float(delta.mean()), limit=tolerance)
        if not np.isfinite(delta).all() or delta.max() > tolerance:
            failures.append(key)
    for n in ("discovery.json","selection.json","results.json","partitions.json","environment.json"):
        equal(n, (a/n).read_bytes() == (b/n).read_bytes(), "process_replay")
    array_diffs = {}
    with np.load(a/"arrays.npz", allow_pickle=False) as first, np.load(b/"arrays.npz", allow_pickle=False) as second:
        equal("array_inventory", set(first.files) == set(second.files), "process_replay")
        for name in first.files:
            x,y = first[name],second[name]
            err = float(np.abs(x-y).max())
            exact = x.dtype == y.dtype and x.tobytes() == y.tobytes()
            if not np.isfinite(x).all() or not exact:
                failures.append(f"process_replay/{name}")
            array_diffs[name] = dict(shape=list(x.shape), max_abs=err, bitwise_equal=exact)
    report["process_replay"]["arrays"] = array_diffs
    manifest = [(line.split()[0], line.split()[1]) for line in (PILOT/"SHA256SUMS").read_text().splitlines()]
    equal("supplied_manifest_bindings", all(sha(PILOT/name) == digest for digest, name in manifest))
    partition = read(a/"partitions.json")
    protocol = read(HIST/"protocol.json")
    equal("training_pairs", partition["training"] == read(HIST/"training.json")["train_context_pairs"])
    for key, batch in protocol["batches"].items():
        equal(key+".token_ids", partition[key] == batch["input_ids"])
    mine, hist = read(a/"discovery.json"), read(HIST/"discovery.json")
    ranking = mine["all_first_order_scores"]
    original = hist["all_first_order_scores"]
    equal("entire_ranking_order", [x[1:] for x in ranking] == [x[1:] for x in original])
    near("all_128_first_order_scores", [x[0] for x in ranking], [x[0] for x in original])
    near("discovery.baseline_margin", mine["baseline_margin"], hist["baseline_margin"])
    original_top = [(k["layer"],k["neuron"]) for k in hist["exact_shortlist"]]
    top = [(k["layer"],k["neuron"]) for k in mine["exact_shortlist"]]
    equal("exact_order", top == original_top)
    for left, right in zip(mine["exact_shortlist"], hist["exact_shortlist"]):
        for key in ("exact_mean","per_prompt","predicted_mean"):
            near(f"shortlist.L{left['layer']}N{left['neuron']}.{key}", left[key], right[key])
    selected, archived = read(a/"selection.json"), read(HIST/"selection.json")
    for key in ("layer","neuron","sign","random_neurons_same_layer"):
        equal("selection."+key, selected[key] == archived[key])
    for key in ("direction_norm","direction","random_directions","discovery_exact_mean","discovery_predicted_mean"):
        near("selection."+key, selected[key], archived[key])
    near("generated_control_norms", np.linalg.norm(selected["random_directions"],axis=1),
         np.full(6, selected["direction_norm"]), 1e-6)
    result = read(a/"results.json")
    equal("frozen_selection_binding", result["selection_sha256"] == sha(a/"selection.json"))
    equal("frozen_discovery_binding", selected["discovery_sha256"] == sha(a/"discovery.json"))
    for group, values in result["validation"].items():
        reference = read(HIST/"results.json")["validation"][group]
        for key in ("exact_ablation_margin_decrease","random_neuron_margin_decrease","baseline_margin",
                    "first_order_prediction","mean_exact_ablation","random_neuron_mean"):
            near(group+"."+key, values[key], reference[key])
        for key in ("baseline_expected_token_top1_count","all_exact_positive"):
            equal(group+"."+key,values[key] == reference[key])
        for key,tol in (("gradient",HISTORICAL_ATOL),("central_difference",HISTORICAL_FD_ATOL)):
            near(group+"."+key,values[key],reference["mechanism_checks"][key],tol)
        for measured, old in zip(values["cross_layer"], reference["cross_layer"]):
            layer = measured["layer"]
            equal(group+f".cross_layer.{layer}.layer", layer == old["layer"])
            for key in ("chosen_delta","random_delta","random_mean_delta","chosen_minus_random_mean"):
                near(group+f".cross_layer.{layer}."+key,measured[key],old[key])
        for key, evidence in values["mechanism"].items():
            limit = GRADIENT_ATOL if key == "gradient_vs_central_difference_max_abs" else FLOAT64_MECHANISM_ATOL
            errs = evidence.values() if isinstance(evidence, dict) else [evidence]
            report["functional_mechanism"][group+"."+key] = dict(max_abs=max(errs), limit=limit)
            if not np.isfinite(max(errs)) or max(errs)>limit:
                failures.append(group+"."+key)
        report["summaries"][group] = dict(mean_exact=values["mean_exact_ablation"],
            mean_random_neuron=values["random_neuron_mean"],
            count_positive=sum(v>0 for v in values["exact_ablation_margin_decrease"]),
            cross_layer_means=[float(np.mean(c["chosen_minus_random_mean"])) for c in values["cross_layer"]])
    report["failure_keys"] = failures
    report["status"] = "INDEPENDENT_FIXTURE_AGREEMENT" if not failures else "DISCREPANCIES"
    write(out, report)
    print(f"{report['status']} across {len(report['history'])} historical comparisons, "
          f"{len(array_diffs)} arrays, {len(report['functional_mechanism'])} functional checks. "
          f"Failures: {failures}")
    check(not failures, "Inspection required")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("first", type=Path)
    parser.add_argument("replay", type=Path)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()
    compare(args.first, args.replay, args.report)

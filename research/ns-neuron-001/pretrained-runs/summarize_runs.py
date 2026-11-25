"""Compare complete study and replay artifacts and summarize their finite contrast."""
import ast
import hashlib
import json
import statistics
import sys
from pathlib import Path


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def read(path):
    return json.loads(path.read_text())


def main(snapshot):
    root = Path(__file__).resolve().parent
    source = root.parent / "pilot" / "neuron_probe.py"
    pins = next(ast.literal_eval(node.value) for node in ast.parse(source.read_text()).body
                if isinstance(node, ast.Assign) and node.targets[0].id == "PINS")
    first, second = root / "study-001", root / "replay-001"
    names = sorted({f.name for f in first.iterdir()} | {f.name for f in second.iterdir()})
    artifacts = {}
    for name in names:
        f, s = first / name, second / name
        artifacts[name] = {"study": digest(f), "replay": digest(s),
                           "byte_identical": f.read_bytes() == s.read_bytes()}
    inputs = {name: {"expected": expected, "observed_after_replay": digest(snapshot / name)}
              for name, expected in pins.items()}
    results = read(first / "results.json")
    selection = read(first / "selection.json")
    discovery = read(first / "discovery.json")
    groups = {}
    for name, v in results["validation"].items():
        effects = v["exact_ablation_margin_decrease"]
        margins = v["baseline_margin"]
        groups[name] = {
            "exact_per_prompt": effects,
            "mean_exact": statistics.mean(effects),
            "mean_random_neuron": statistics.mean(d for row in v["random_neuron_margin_decrease"] for d in row),
            "positive_effect_count": sum(d > 0 for d in effects),
            "row_count": len(effects),
            "correct_pairwise_preference_count": sum(m > 0 if name.endswith("positive") else m < 0 for m in margins),
            "pairwise_preference_flips_after_ablation": sum((m > 0) != (m - d > 0) for m, d in zip(margins, effects)),
            "baseline_expected_token_top1_count": v["baseline_expected_token_top1_count"],
            "cross_layer": [
                {"layer": c["layer"], "chosen_mean": statistics.mean(c["chosen_delta"]),
                 "random_mean": statistics.mean(d for row in c["random_delta"] for d in row),
                 "mean_chosen_minus_random": statistics.mean(c["chosen_minus_random_mean"])}
                for c in v["cross_layer"]
            ],
        }
    report = {
        "scope": "Same-host separate-process empirical replay and descriptive arithmetic",
        "source_sha256": digest(source),
        "model_sha256": inputs,
        "model_readonly_modes_after_replay": {p.name: oct(p.stat().st_mode & 0o777) for p in snapshot.iterdir()},
        "artifacts": artifacts,
        "exit_codes": [read(root / (name + ".exit.json"))["exit_code"] for name in ["study-001", "replay-001"]],
        "study_status": results["status"],
        "mechanism_checks_passed": results["mechanism_checks_passed"],
        "selected_layer": selection["layer"], "selected_neuron": selection["neuron"],
        "score_inventory_size": len(discovery["all_first_order_scores"]),
        "shortlist_size": len(discovery["exact_shortlist"]),
        "groups": groups,
    }
    matched = all(v["expected"] == v["observed_after_replay"] for v in inputs.values())
    report["replay_and_pin_match"] = (
        set(names) == {"protocol.json", "discovery.json", "selection.json", "results.json"}
        and all(item["byte_identical"] for item in artifacts.values()) and report["exit_codes"] == [0, 0]
        and matched and set(pins) == {p.name for p in snapshot.iterdir()}
        and report["source_sha256"] == "6372d218768d98f487bf89e41230da111bcb16532a8d95818796043f962ef8ce"
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["replay_and_pin_match"] else 2


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1])))

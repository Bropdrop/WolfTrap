"""Regenerate the fixture's frozen CPU control draws before measuring held-out prompts."""
import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from control_draws import generate_controls


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pilot", type=Path, required=True)
    options = parser.parse_args()
    fixture = options.pilot / "evidence" / "fixture-run-001"
    inputs = {
        options.pilot / "neuron_probe.py": "6372d218768d98f487bf89e41230da111bcb16532a8d95818796043f962ef8ce",
        fixture / "protocol.json": "4cf16e607fd33278732e3a3e6323552d22323f8b91cdc225808f64da4184cbea",
        fixture / "selection.json": "b5d3eb176c7727baa559f2ff0bf3aabd628d92a133598c0ad65cd18e291549d2",
    }
    for path, expected in inputs.items():
        if sha(path) != expected:
            raise ValueError(f"Input SHA-256 mismatch for {path.name}")
    protocol = json.loads((fixture / "protocol.json").read_bytes())
    archived = json.loads((fixture / "selection.json").read_bytes())
    neuron_ids, directions = generate_controls(
        64, archived["neuron"], archived["direction_norm"], seed=protocol["seed"]
    )
    historical = np.asarray(archived["random_directions"], dtype=np.float32)
    if historical.shape != (6, 32):
        raise ValueError("Unexpected shape of the archived draws.")
    differences = abs(directions.astype(np.float64) - historical)
    error = float(np.max(differences))
    tolerance = float(np.finfo(np.float32).eps * archived["direction_norm"])
    ids_match = neuron_ids == archived["random_neurons_same_layer"]
    numerical_match = bool(np.isfinite(differences).all() and error <= tolerance)
    print(json.dumps({
        "command": "python verify_control_draws.py --pilot ../../pilot",
        "python": platform.python_version(),
        "numpy": np.__version__,
        "script_sha256": sha(Path(__file__)),
        "control_generator_sha256": sha(Path(__file__).resolve().parents[1] / "control_draws.py"),
        "input_sha256": {str(p.relative_to(options.pilot)): h for p, h in inputs.items()},
        "scope": "Regenerate the fixture's seeded same-layer neuron IDs and 192 direction components. The scale and excluded neuron are inputs from the frozen discovery selection. This check does not load validation inputs, models or Torch.",
        "selected_layer": archived["layer"],
        "excluded_neuron": archived["neuron"],
        "frozen_scale": archived["direction_norm"],
        "neuron_rng_seed": protocol["seed"] + 2,
        "direction_rng_seed": protocol["seed"] + 3,
        "same_layer_neuron_ids": neuron_ids,
        "neuron_ids_match": ids_match,
        "direction_components": directions.tolist(),
        "direction_norms_float64": np.linalg.norm(directions.astype(np.float64), axis=1).tolist(),
        "max_abs_error_by_direction": differences.max(axis=1).tolist(),
        "max_abs_error": error,
        "unequal_float32_components": int(np.count_nonzero(differences)),
        "abs_tolerance_float32_epsilon_times_scale": tolerance,
        "directions_agree_within_tolerance": numerical_match,
    }, indent=2, allow_nan=False))
    if not ids_match or not numerical_match:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

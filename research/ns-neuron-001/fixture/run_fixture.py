"""Run the unmodified pilot against the saved weights, preserving each attempt."""
import argparse
import ast
import datetime as dt
import hashlib
import importlib.metadata as metadata
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PILOT = HERE.parent / "pilot"
HIST = PILOT / "evidence" / "fixture-run-001"
FILES = [
    "fixture.safetensors", "protocol.json", "discovery.json", "selection.json", "results.json",
]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump(path, obj):
    path.write_text(json.dumps(obj, sort_keys=True, indent=2, allow_nan=False) + "\n")


def get_version(package):
    try:
        return metadata.version(package)
    except metadata.PackageNotFoundError:
        return None


def differences(before, after, path="$"):
    if type(before) is not type(after):
        yield {"path": path, "before": before, "after": after, "type_changed": True}
    elif isinstance(before, dict):
        for key in sorted(before.keys() | after.keys()):
            if key in before and key in after:
                yield from differences(before[key], after[key], f"{path}.{key}")
            else:
                yield {"path": f"{path}.{key}", "before": before.get(key), "after": after.get(key)}
    elif isinstance(before, list):
        if len(before) != len(after):
            yield {"path": path, "length_before": len(before), "length_after": len(after)}
        for i, (a, b) in enumerate(zip(before, after)):
            yield from differences(a, b, f"{path}[{i}]")
    elif before != after:
        item = {"path": path, "before": before, "after": after}
        if type(before) in (float, int):
            item["absolute_difference"] = abs(before - after)
        yield item


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="fresh directory, relative to invoking cwd")
    args = parser.parse_args()
    destination = args.destination.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    env = os.environ.copy()
    settings = {
        "PYTHONDONTWRITEBYTECODE": "1", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
        "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1", "CUDA_VISIBLE_DEVICES": "",
    }
    env.update(settings)
    dump(destination / "environment.json", {
        "utc_started": dt.datetime.now(dt.timezone.utc).isoformat(),
        "python": sys.version, "executable": sys.executable, "platform": platform.platform(),
        "distribution_versions": {p: get_version(p) for p in ["torch", "transformers", "safetensors", "numpy", "scipy"]},
        "execution_settings": settings, "historical_environment": json.loads((PILOT / "evidence/environment.json").read_text()),
        "source_sha256": {p.name: sha(p) for p in PILOT.iterdir() if p.is_file()},
    })
    records = []
    def run(name, cmd):
        with (destination / (name + ".stdout")).open("w") as out, (destination / (name + ".stderr")).open("w") as err:
            proc = subprocess.run(cmd, env=env, cwd=PILOT, stdout=out, stderr=err, check=False)
        records.append({"phase": name, "cwd": str(PILOT), "argv": cmd, "exit_code": proc.returncode})
        dump(destination / "commands.json", records)
        return proc.returncode

    manifest = (PILOT / "SHA256SUMS").read_text().splitlines()
    coverage = {str(Path(line.split(None, 1)[1])) for line in manifest}
    actual = {str(p.relative_to(PILOT)) for p in PILOT.rglob("*") if p.is_file()} - {"SHA256SUMS"}
    digest_ok = run("manifest-check", ["sha256sum", "-c", "SHA256SUMS"]) == 0
    if not digest_ok or coverage != actual:
        raise ValueError(f"Input validation failed: omitted or additional paths {coverage ^ actual}")
    tests = [f.name for cls in ast.parse((PILOT / "test_neuron_probe.py").read_text()).body if isinstance(cls, ast.ClassDef)
             for f in cls.body if isinstance(f, ast.FunctionDef) and f.name.startswith("test_")]
    test_rc = run("focused-tests", [sys.executable, "-m", "unittest", "-v", "test_neuron_probe"])
    review_rc = run("stored-arithmetic", [sys.executable, "review_evidence.py"])
    historical_review = (PILOT / "evidence" / "artifact-review.json").read_bytes()
    fresh_review = (destination / "stored-arithmetic.stdout").read_bytes()
    replay = destination / "saved-weights-replay"
    replay_rc = run("saved-weights", [sys.executable, "neuron_probe.py", "--mode", "fixture", "--replay-weights",
        "evidence/fixture-run-001/fixture.safetensors", "--out", str(replay)])
    comparison = {}
    for name in FILES:
        previous, current = HIST / name, replay / name
        row = {"historical_sha256": sha(previous), "current_sha256": sha(current) if current.is_file() else None}
        if current.is_file():
            row["byte_identical"] = previous.read_bytes() == current.read_bytes()
            if not row["byte_identical"] and previous.suffix == ".json":
                diffs = list(differences(json.loads(previous.read_text()), json.loads(current.read_text())))
                dump(destination / ("diff-" + name), diffs)
                row["changed_leaves"] = len(diffs)
                row["max_numeric_difference_including_changed_ids"] = max((d.get("absolute_difference", 0) for d in diffs), default=0)
        comparison[name] = row
    dump(destination / "summary.json", {
        "manifest_passed": digest_ok, "manifest_entry_count": len(manifest), "closed_manifest_inventory_excluding_manifest": actual == coverage,
        "focused_suite_exit": test_rc, "test_names_in_source": tests, "stored_arithmetic_exit": review_rc,
        "stored_arithmetic_stdout_byte_matches_historical": fresh_review == historical_review,
        "stored_arithmetic_json_matches_historical": review_rc == 0 and json.loads(fresh_review) == json.loads(historical_review),
        "saved_weights_replay_exit": replay_rc, "replay_comparison": comparison,
    })
    return int(any([test_rc, review_rc, replay_rc]))


if __name__ == "__main__":
    sys.exit(main())

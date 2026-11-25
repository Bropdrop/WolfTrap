"""Report local prerequisites for the historical adapter without importing it."""

import argparse
import ast
import hashlib
import importlib.metadata
import importlib.util
import json
import platform
import sys
from pathlib import Path


EXPECTED_ADAPTER = "6372d218768d98f487bf89e41230da111bcb16532a8d95818796043f962ef8ce"


def file_hash(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def audit_model(model_dir, pins):
    actual_names = set()
    if model_dir is not None and model_dir.is_dir():
        actual_names = {entry.name for entry in model_dir.iterdir()}
    files = {}
    for name, expected in pins.items():
        path = model_dir / name if model_dir is not None else None
        observed = file_hash(path) if path and path.is_file() else None
        files[name] = {"expected_sha256": expected, "observed_sha256": observed}
    matched = sum(row["expected_sha256"] == row["observed_sha256"] for row in files.values())
    return {
        "directory_supplied": model_dir is not None,
        "extra_names": sorted(actual_names - set(pins)),
        "missing_names": sorted(set(pins) - actual_names),
        "files": files,
        "matched_files": matched,
        "inventory_verified": actual_names == set(pins) and matched == len(pins),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-dir", type=Path, help="A recovered local seven-file snapshot")
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[1] / "pilot" / "neuron_probe.py"
    observed_source = file_hash(source)
    if observed_source != EXPECTED_ADAPTER:
        sys.exit(f"Adapter hash mismatch: {observed_source}")
    values = {
        statement.targets[0].id: ast.literal_eval(statement.value)
        for statement in ast.parse(source.read_text()).body
        if isinstance(statement, ast.Assign)
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id in {"PINS", "PIN_REV"}
    }
    model = audit_model(args.model_dir, values["PINS"])
    dependencies = {}
    for name in ("torch", "transformers", "safetensors", "tokenizers"):
        spec = importlib.util.find_spec(name)
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            version = None
        dependencies[name] = {
            "version": version,
            "module_origin": str(spec.origin).split("/site-packages/")[-1] if spec else None,
            "module_located": spec is not None,
        }
    ready = model["inventory_verified"] and all(
        item["module_located"] and item["version"] for item in dependencies.values()
    )
    print(json.dumps({
        "status": "LOCAL_INPUTS_LOCATED" if ready else "BLOCKED_MISSING_LOCAL_INPUTS",
        "scope": "Local package discovery and pinned file inventory; no model load or forwards",
        "python_version": sys.version,
        "platform": platform.platform(),
        "source_sha256": observed_source,
        "expected_revision": values["PIN_REV"],
        "dependencies": dependencies,
        "model": model,
    }, indent=2, sort_keys=True))
    return 0 if ready else 2


if __name__ == "__main__":
    sys.exit(main())

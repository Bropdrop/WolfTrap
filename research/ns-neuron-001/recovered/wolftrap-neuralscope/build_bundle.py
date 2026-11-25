#!/usr/bin/env python3
"""Create the reproducible source-and-example ZIP without running models."""
import argparse
import hashlib
import json
from pathlib import Path
import stat
import zipfile
import zlib

from neuralscope import __version__

ROOT_FILES = ("README.md", "DESIGN.md", "PRETRAINED.md", "ATTENTION.md", "LICENSE", "pyproject.toml", "requirements.txt",
              "requirements-reference.txt", "requirements-reference-lock.txt", "build_bundle.py", "validation.json")
ROOT_DIRS = ("neuralscope", "tests", "examples", "example-run", "example-api-dry-run", "pretrained-summary", "attention-summary")


def build(output):
    root = Path(__file__).resolve().parent
    files = {}
    for name in ROOT_FILES:
        path = root / name
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError("package root member is not a regular file")
        files[name] = path.read_bytes()
    for directory in ROOT_DIRS:
        for path in sorted((root / directory).rglob("*")):
            if "__pycache__" in path.parts or path.suffix in (".pyc", ".pyo"):
                continue
            if path.is_symlink():
                raise ValueError("symlink in source inventory")
            if path.is_file():
                files[path.relative_to(root).as_posix()] = path.read_bytes()
    receipt = {"schema": "wolftrap.neuralscope.source-bundle/v1", "version": __version__,
               "members": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                           for name, data in sorted(files.items())},
               "signature": None}
    files["bundle-inventory.json"] = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
    output = Path(output)
    if output.exists():
        raise ValueError("choose a fresh output ZIP path")
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo("wolftrap-neuralscope/" + name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    data = output.read_bytes()
    return {"file": str(output), "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "members": len(files)}


def build_evidence(directory, output):
    """Archive complete verified numeric evidence; keep large weights external.

    Deflate reduces the duplicate/correlated numeric traces. Reproducibility is
    checked within the recorded Python/zlib environment; unlike the stored source
    ZIP, compressed bytes are not promised identical across zlib versions.
    """
    from neuralscope.evidence import digest, verify
    root = Path(directory)
    integrity = verify(root)
    context = json.loads((root / "manifest.json").read_text())["context"]
    archive_root = ("wolftrap-neuralscope-attention-evidence/" if
                    context.get("kind") == "counterbalanced-attention-head-study" else
                    "wolftrap-neuralscope-pretrained-evidence/")
    output = Path(output)
    if output.exists():
        raise ValueError("choose a fresh evidence ZIP path")
    files = sorted(path for path in root.rglob("*") if path.is_file())
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in files:
            if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("nonregular evidence archive member")
            name = archive_root + path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            info._compresslevel = 6
            with path.open("rb") as source, archive.open(info, "w") as target:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    target.write(block)
    verify(root, integrity["manifest_sha256"])
    return {"file": str(output), **digest(output), "members": len(files),
            "evidence_manifest_sha256": integrity["manifest_sha256"],
            "compression": "DEFLATE level6", "zlib": zlib.ZLIB_RUNTIME_VERSION,
            "external_model_required_for_replay": True}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--evidence", type=Path, help="archive this complete sealed pretrained or attention evidence instead of source")
    args = parser.parse_args()
    result = build_evidence(args.evidence, args.output) if args.evidence else build(args.output)
    print(json.dumps(result, sort_keys=True))

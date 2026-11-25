"""Verify an independently supplied historical ZIP without extracting it."""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREFIX = "wolftrap-neuralscope/"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("zip", type=Path)
    args = parser.parse_args()
    receipt = json.loads((HERE / "release-recovery.json").read_text())
    with args.zip.open("rb") as f:
        digest = hashlib.file_digest(f, "sha256").hexdigest()
    if digest != receipt["sha256"] or args.zip.stat().st_size != receipt["bytes"]:
        raise ValueError("release archive size or SHA-256 mismatch")
    with zipfile.ZipFile(args.zip) as z:
        members = z.namelist()
        expected = receipt["extraction"]
        if set(members) != expected.keys() or len(members) != len(expected) or z.testzip():
            raise ValueError("archive inventory or CRC mismatch")
        for name in members:
            with z.open(name) as f:
                observed = hashlib.file_digest(f, "sha256").hexdigest()
            if observed != expected[name]["sha256"] or z.getinfo(name).file_size != expected[name]["bytes"]:
                raise ValueError(f"archive member mismatch: {name}")
        manifest = json.loads(z.read(PREFIX + "bundle-inventory.json"))
        delivered = {name.removeprefix(PREFIX): record for name, record in expected.items()
                     if name != PREFIX + "bundle-inventory.json"}
        if delivered != manifest["members"]:
            raise ValueError("bundle inventory mismatch")
        if z.read(PREFIX + "examples/distilgpt2-pin.json") != (HERE / "distilgpt2-pin.json").read_bytes():
            raise ValueError("published model pin differs from historical release")
    print(f"Verified NeuralScope {manifest['version']} ZIP and {len(delivered)} bundle-inventory entries.")


if __name__ == "__main__":
    main()

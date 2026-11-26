"""Check the complete recovered file set against the separately recorded handoff inventory."""
import hashlib
import json
from pathlib import Path
import stat

HERE = Path(__file__).resolve().parent


def verify():
    receipt = json.loads((HERE / "source-receipt.json").read_bytes())
    root = HERE / "wolftrap-api-geotrace-v1"
    if root.is_symlink():
        raise ValueError("unexpected recovery root")
    inventory = {}
    for path in root.rglob("*"):
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError("unexpected member type")
        raw = path.read_bytes()
        inventory[path.relative_to(HERE).as_posix()] = (len(raw), hashlib.sha256(raw).hexdigest())
    expected = {row["path"]:(row["bytes"], row["sha256"]) for row in receipt["members"]}
    if len(expected) != 6 or inventory != expected:
        raise ValueError("recovered inventory mismatch")
    probe = (HERE / "independent_tests/test_hostile_geotrace.py").read_bytes()
    if {"bytes":len(probe),"sha256":hashlib.sha256(probe).hexdigest()} != receipt["independent_probe"]:
        raise ValueError("independent suite mismatch")
    print("Six original files and independent probe suite match the recorded handoff hashes.")


if __name__ == "__main__":
    verify()

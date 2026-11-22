"""Inventory the effective security-relevant files of the selected installation."""
import hashlib
import json
from pathlib import Path
import platform

from isolation import BWRAP, FILTER, HERE, HOST_LIBS, LIBDIR, LIBS, LOADER, PYTHON, ROOT


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def fingerprint(paths, root):
    return sha(encoded({str(p.relative_to(root)): sha(p.read_bytes()) for p in sorted(paths)}))


def members(root):
    return [p for p in root.rglob("*") if p.is_file() and "__pycache__" not in p.parts
            and p.suffix != ".pyc"]


def configuration(policy_digest, model, harness):
    plugin = ROOT / "plugins/wolftrap-security"
    runtime = [Path(p) for p in (PYTHON, BWRAP, LOADER)]
    runtime.extend(Path(LIBDIR) / lib for lib in LIBS + HOST_LIBS)
    runtime.extend(members(Path("/usr/lib/python3.13")))
    # CPython can load distribution bytecode even with -B. Bind that identity too.
    runtime.extend(Path("/usr/lib/python3.13").rglob("*.pyc"))
    return {"engine": fingerprint(members(ROOT / "src/wolftrap"), ROOT),
            "plugin": fingerprint(members(plugin), ROOT), "schema": sha((HERE/"catalog.json").read_bytes()),
            "host": fingerprint([HERE/"host.py", HERE/"configuration.py", HERE/"frontend.py",
                                 HERE/"engine_entry.py"], ROOT),
            "policy": policy_digest, "sandbox": fingerprint([HERE/"isolation.py", HERE/"launch.py", HERE/"install-files.json", FILTER], ROOT),
            "runtime": fingerprint(runtime, Path("/")), "kernel": platform.release(),
            "platform": platform.machine(), "model": model, "harness": harness,
            "qualification": fingerprint([p for p in HERE.iterdir() if p.suffix == ".py"
                                          and (p.name == "packet.py" or p.name.startswith(("test_", "qualify", "codex_")))], ROOT)}

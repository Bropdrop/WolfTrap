"""Measured Linux profile for the operator launcher and nested workers."""
import hashlib
import json
import os
from pathlib import Path
import platform
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OLD = HERE.parent / "wt_mcp_001"
sys.path.insert(0, str(OLD))
import isolation

CAP = "wolftrap_capabilities"
SCAN = "wolftrap_scan_authorized_local"
VERIFY = "wolftrap_verify_evidence"
OPS = {CAP: "list", SCAN: "scan-geotrace", VERIFY: "verify-geotrace"}
INPUT_KEYS = ("approval", "principal", "tenant", "task", "session", "source", "resource",
              "operation", "destination", "policy_version", "policy_digest", "generation")
FIELDS = {k: {"type": "integer" if k == "generation" else "string"} for k in INPUT_KEYS}
CATALOG = {"tools": [{"name": name, "description": description,
             "inputSchema": {"type":"object","properties":FIELDS,"required":list(INPUT_KEYS),
                             "additionalProperties":False}}
            for name,description in zip(OPS, ("List approved GeoTrace operations.",
                 "Scan an approved capture into its designated evidence slot.",
                 "Replay an approved evidence slot."))]}
FILES = {"geotrace.json", "geotrace.sarif", "geotrace.md", "manifest.json"}
NEW = ("profile.py","launch.py","broker.py","store.py","locked_worker.py","front.py","owner.py","reference_pin.py")
MEMBERS = ([HERE / name for name in NEW] + [OLD / name for name in ("engine_entry.py","isolation.py")] +
           [ROOT / "src/wolftrap" / f for f in isolation.ENGINE] + [isolation.FILTER,
           ROOT / "plugins/wolftrap-security/plugin.json", ROOT / "pyproject.toml", ROOT / "LICENSE"])
HOST_LIBS = isolation.HOST_LIBS + ("libsqlite3.so.0",)


def require(condition):
    if not condition:
        raise ValueError("boundary check failed")


def encode(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inventory():
    return {str(p.relative_to(ROOT)):sha(p.read_bytes()) for p in MEMBERS}


def measurement(client):
    paths = [Path(p) for p in (isolation.BWRAP,isolation.PYTHON,isolation.LOADER)]
    paths += [Path(isolation.LIBDIR)/lib for lib in isolation.LIBS + HOST_LIBS]
    stdlib = Path("/usr/lib/python3.13")
    paths += [p for p in stdlib.rglob("*") if p.is_file() and p.resolve().is_relative_to(stdlib)]
    return sha(encode({"files":inventory(),"client":client,"kernel":platform.release(),
                       "machine":platform.machine(),"runtime":{str(p):sha(p.read_bytes()) for p in paths}}))


def directory(path):
    require(path.is_absolute() and path == path.resolve(strict=True) and path.is_dir()
            and path.stat().st_uid == os.getuid() and path.stat().st_mode & 0o077 == 0)


def worker(role, mounts=(), args=(), payload=b""):
    return isolation.run(HERE/"locked_worker.py", [("--ro-bind",role,"/role.py"),*mounts], args, payload)


def engine(scan, inputs, output, policy):
    return worker(OLD/"engine_entry.py", isolation.engine_mounts(scan,inputs,output),
                  [OPS[SCAN if scan else VERIFY],"--root","/capture","--file","sample.json",
                   "--policy","/geo.json","--policy-sha256",policy["geo_digest"],
                   "--as-of",policy["as_of"],"--output-dir" if scan else "--evidence-dir","/output/bundle"])

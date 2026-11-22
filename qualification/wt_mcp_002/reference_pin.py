"""Independent supervisor measurement. Does not import the broker or its inventory."""
import hashlib
import json
from pathlib import Path
import platform

ENGINE=("__init__.py","agent_scan.py","agent_rules.py","geotrace.py","geotrace_cli.py","_geotrace_v1.py")
ADAPTER=("profile.py","launch.py","broker.py","store.py","locked_worker.py","front.py","owner.py")
LIBS=("libc.so.6","libm.so.6","libexpat.so.1","libz.so.1","libffi.so.8","libseccomp.so.2",
      "libcrypto.so.3","liblzma.so.5","libbz2.so.1.0","libselinux.so.1","libcap.so.2",
      "libpcre2-8.so.0","libsqlite3.so.0")


def digest(path):
    with path.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def expected_configuration(install,client):
    root=install.parents[1]
    members=[*(Path("qualification/wt_mcp_002")/p for p in ADAPTER),
             *(Path("src/wolftrap")/p for p in ENGINE),
             *(Path("qualification/wt_mcp_001")/p for p in ("engine_entry.py","isolation.py")),
             Path("qualification/wt_zt_001/offline.py"),Path("plugins/wolftrap-security/plugin.json"),
             Path("pyproject.toml"),Path("LICENSE")]
    runtime=[Path("/usr/bin/bwrap"),Path("/usr/bin/python3.13"),Path("/lib64/ld-linux-x86-64.so.2")]
    runtime.extend(Path("/usr/lib/x86_64-linux-gnu")/lib for lib in LIBS)
    stdlib=Path("/usr/lib/python3.13")
    runtime.extend(p for p in stdlib.rglob("*") if p.is_file() and p.resolve().is_relative_to(stdlib))
    components={"files":{str(p):digest(root/p) for p in members},"client":client,
                "runtime":{str(p):digest(p) for p in runtime},"kernel":platform.release(),
                "machine":platform.machine()}
    return hashlib.sha256(json.dumps(components,sort_keys=True,separators=(",",":")).encode()).hexdigest()

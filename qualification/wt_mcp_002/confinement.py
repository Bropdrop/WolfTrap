"""OS probes over the same locked worker and mount constructors used by both clients."""
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from profile import HERE, ROOT
from launch import add_file
from reference_pin import application_bytes
from sibling import Q, run_job
from job_wire import NAMES
from trials import check


def run():
    if sys.executable != "/usr/bin/python3.13":
        return json.loads(subprocess.check_output(["/usr/bin/python3.13","-IBS",__file__]))
    records={}
    with tempfile.TemporaryDirectory() as tmp:
        p=Path(tmp)
        (p/"sample.json").write_bytes(b"{}")
        (p/"geo.json").write_bytes(b"{}")
        (p/"private-canary").write_bytes(b"fictional")
        output=p/"output"
        output.mkdir()
        with (p/"private-canary").open("rb") as sentinel:
            os.dup2(sentinel.fileno(),87,inheritable=True)
            os.environ["WT_PRIVATE_CANARY"]="fictional"
            try:
                for mode in ("front","scan","verify"):
                    contents = application_bytes(ROOT)
                    role = {"front": b"F", "scan": b"S", "verify": b"V"}[mode]
                    member = "front.py" if mode == "front" else "engine_role.py"
                    # Only this test driver substitutes measured role bytes; clients cannot select them.
                    diagnostic = (HERE/"os_probe.py").read_text()
                    contents[Q + member] = diagnostic.replace("CANARY_PATH", repr(str(p/"private-canary"))).encode()
                    parts = [b"{}"] if mode == "front" else [b"{}", b"{}", b"2026-01-01", b"0"*64]
                    if mode == "verify":
                        parts.extend([b"{}"] * len(NAMES))
                    fds = []
                    try:
                        rc, raw = run_job(role, parts, contents, add_file, fds)
                    finally:
                        for fd in fds:
                            os.close(fd)
                    actual=json.loads(raw)
                    expected={"host_mounts":[], "socket":"EPERM","fork":"EPERM","exec_nonexistent":"EPERM","shell":False,"inherited":"EBADF","secret":"ENOENT",
                              "environment":False,"source_write":"ENOENT" if mode=="front" else "EROFS",
                              "source_read":"ENOENT" if mode=="front" else "ALLOWED","install_write":"EROFS",
                              "unapproved_write":"EROFS","slot_write":{"front":"ENOENT","scan":"ALLOWED",
                                                                      "verify":"EROFS"}[mode]}
                    check(rc==0 and expected==actual,mode+str(actual))
                    records[mode]={"expected":expected,"observed":actual}
            finally:
                os.close(87)
                del os.environ["WT_PRIVATE_CANARY"]
        check((p/"sample.json").read_bytes()==b"{}","source changed")
    return records


if __name__ == "__main__":
    print(json.dumps(run()))

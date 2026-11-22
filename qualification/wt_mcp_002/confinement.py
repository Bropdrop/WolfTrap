"""OS probes over the same locked worker and mount constructors used by both clients."""
import json
import os
from pathlib import Path
import tempfile

from profile import HERE,isolation,worker
from trials import check


def run():
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
                    mounts=[] if mode=="front" else isolation.engine_mounts(mode=="scan",p,output)
                    rc,raw=worker(HERE/"os_probe.py",mounts,[str(p/"private-canary")])
                    actual=json.loads(raw)
                    expected={"socket":"EPERM","fork":"EPERM","shell":False,"inherited":"EBADF","secret":"ENOENT",
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

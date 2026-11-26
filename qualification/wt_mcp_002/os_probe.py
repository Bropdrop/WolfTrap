"""Inert worker-side canary diagnostics. This file is excluded from the adapter package."""
import json
import os
from pathlib import Path
import socket
import sys


def test(action):
    try:
        action()
        return "ALLOWED"
    except OSError as exc:
        import errno
        return errno.errorcode[exc.errno]


def child():
    pid=os.fork()
    if pid==0:
        os._exit(0)
    os.waitpid(pid,0)


path=Path("/capture/sample.json")
print(json.dumps({"socket":test(lambda:socket.socket().close()),"fork":test(child),
                  "exec_nonexistent":test(lambda:os.execve("/absent-fixture",["fixture"],{})),
                  "shell":Path("/bin/sh").exists(),"inherited":test(lambda:os.fstat(87)),
                  "secret":test(lambda:Path(sys.argv[1]).read_bytes()),"environment":"WT_PRIVATE_CANARY" in os.environ,
                  "source_write":test(lambda:path.open("ab").close()),"source_read":test(path.read_bytes),
                  "install_write":test(lambda:Path("/role.py").open("ab").close()),
                  "unapproved_write":test(lambda:Path("/unapproved").touch()),
                  "slot_write":test(lambda:Path("/output/probe").touch())}))

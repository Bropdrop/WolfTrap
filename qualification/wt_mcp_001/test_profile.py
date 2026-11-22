"""Inert OS conformance probe. Receives only fictional canary paths from the oracle."""
import errno
import json
import os
from pathlib import Path
import socket
import sys


def attempt(operation):
    try:
        operation()
    except OSError as exc:
        return errno.errorcode[exc.errno]
    return "ALLOWED"


if __name__ == "__main__":
    mode, canary = sys.argv[1:]
    source = Path("/capture/sample.json")
    stage = Path("/output/canary")
    checks = {"socket": attempt(lambda: socket.socket().close()),
              "secret": attempt(lambda: Path(canary).read_bytes()),
              "traversal": attempt(lambda: Path("/capture/.." + canary).read_bytes()),
              "outside": attempt(lambda: Path("/unapproved").write_bytes(b"fixture")),
              "source_write": attempt(lambda: source.open("ab").close()),
              "selected_write": attempt(lambda: stage.write_bytes(b"fixture")),
              "selected_read": attempt(lambda: source.read_bytes()),
              "host_environment": "WT_FICTIONAL_CANARY" in os.environ}
    print(json.dumps(checks))

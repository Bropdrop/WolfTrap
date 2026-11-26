"""Fixed sibling scanner entry. Export bounded provisional bytes only after the scanner finishes."""
import contextlib
import io
import os
from pathlib import Path
import runpy
import stat
import sys

sys.path.insert(0, "/")
from job_wire import ARTIFACT, NAMES, put

scan = sys.argv[1] == "scan"
sys.argv = ["/scanner.py", "scan-geotrace" if scan else "verify-geotrace", "--root", "/capture",
            "--file", "sample.json", "--policy", "/geo.json", "--policy-sha256", Path("/digest").read_text(),
            "--as-of", Path("/date").read_text(), "--output-dir" if scan else "--evidence-dir", "/output/bundle"]
message = io.StringIO()
try:
    with contextlib.redirect_stdout(message):
        runpy.run_path("/scanner.py", run_name="__main__")
except SystemExit as exc:
    code = exc.code
else:
    code = 0
if scan and code in (0, 1):
    directory = os.open("/output/bundle", os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if set(os.listdir(directory)) != set(NAMES):
            raise ValueError("incomplete scanner output")
        for name in NAMES:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= ARTIFACT:
                    raise ValueError("invalid scanner output")
                put(sys.stdout.buffer, stream.read(ARTIFACT + 1), ARTIFACT)
    finally:
        os.close(directory)
elif not scan:
    sys.stdout.write(message.getvalue())
sys.exit(code)

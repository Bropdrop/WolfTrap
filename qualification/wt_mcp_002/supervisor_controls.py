"""External controls for the fixed worker channel and the broker's process boundary."""
import io
import json
from pathlib import Path
import struct
import subprocess
import tempfile

from fixtures import provision
from job_wire import INPUTS
from recovery import change, copy_install, pin_for
from sibling import serve
from trials import check, command, observe

# Runs inside the broker after descriptor cleanup and installation of its irreversible filter.
DIAGNOSTIC = '''
    import errno, socket
    def outcome(action):
        try:
            action()
            return "ALLOWED"
        except OSError as exc:
            return errno.errorcode[exc.errno]
    def fork_probe():
        child = os.fork()
        if not child:
            os._exit(0)
        os.waitpid(child, 0)
    endpoints = list(map(int, sys.argv[5:]))
    fds = [fd for fd in range(3, 256) if outcome(lambda: os.fstat(fd)) == "ALLOWED"]
    result = {"channel_only": sorted(endpoints) == fds,
              "fork": outcome(fork_probe),
              "exec": outcome(lambda: os.execve("/absent-synthetic", ["probe"], {})),
              "socket": outcome(lambda: socket.socket().close())}
    print(json.dumps(result))
    return 0
'''


def run():
    boundaries = {}
    invalid = {"unknown-role":b"/", "truncated-header":b"F\0", "truncated-body":b"F\0\0\0\x03x",
               "oversize":b"F"+struct.pack("!I",INPUTS[b"F"][0]+1)}
    for label, data in invalid.items():
        out = io.BytesIO()
        try:
            # No package or runner is supplied. Any attempt at a mount or dispatch fails this test.
            serve(io.BytesIO(data), out, {}, None)
        except (ValueError, EOFError) as exc:
            boundaries[label] = type(exc).__name__
        else:
            raise AssertionError(label+" accepted")
        check(out.getvalue() == b"", label+" generated a reply")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        state = root/"state"
        policy = provision(state)
        install = copy_install(root/"installed")
        change(install/"broker.py", "    broker=Broker(*sys.argv[1:5])", DIAGNOSTIC)
        client = "broker-confinement-canary"
        cmd = command(state, policy, pin_for(install,client), client, install)
        observed = json.loads(subprocess.check_output(cmd,input=b"",timeout=15))
        expected = {"channel_only":True, "fork":"EPERM", "exec":"EPERM", "socket":"EPERM"}
        check(observed == expected and observe(state,"alpha")=={"journal":[],"files":{}}, "broker boundary")
    return {"private_frames_rejected":boundaries, "broker":{"expected":expected,"observed":observed}}

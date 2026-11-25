"""Check the offline launcher's syscall policy in parent and exec'd child."""

import ctypes
import errno
import json
import os
import socket
import subprocess
import sys
from pathlib import Path


def check_process():
    observations = {}
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX, socket.AF_NETLINK):
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            label = f"{family.name}/{kind.name}"
            try:
                test = socket.socket(family, kind)
            except OSError as exc:
                observations[label] = exc.errno
            else:
                test.close()
                observations[label] = 0
    sec = ctypes.CDLL("libseccomp.so.2")
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    libc = ctypes.CDLL(None, use_errno=True)
    for name in ("connect", "socketpair", "io_uring_setup", "io_uring_enter", "io_uring_register"):
        nr = sec.seccomp_syscall_resolve_name(name.encode())
        ctypes.set_errno(0)
        result = libc.syscall(nr, -1, 0, 0, 0, 0, 0)
        observations[name] = ctypes.get_errno() if result == -1 else 0
    observed_status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in {"NoNewPrivs", "Seccomp", "Seccomp_filters"}:
            observed_status[key] = int(value)
    return {
        "pid": os.getpid(),
        "errno_by_operation": observations,
        "proc_status": observed_status,
        "all_denied_with_eperm": all(v == errno.EPERM for v in observations.values()),
    }


if __name__ == "__main__":
    current = check_process()
    if "--child" in sys.argv:
        print(json.dumps(current))
        sys.exit(0 if current["all_denied_with_eperm"] else 1)
    child = subprocess.run(
        [sys.executable, "-B", __file__, "--child"], text=True, capture_output=True, check=True
    )
    report = {"parent": current, "child": json.loads(child.stdout)}
    print(json.dumps(report, indent=2, sort_keys=True))
    sys.exit(0 if current["all_denied_with_eperm"] else 1)

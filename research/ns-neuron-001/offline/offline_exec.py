"""Run a local process tree with networking disabled on this Linux host."""

import ctypes
import errno
import os
import stat
import sys


# Dropping io_uring prevents asynchronous socket operations outside this filter.
# The native architecture is the sole supported ABI in libseccomp's new context.
BLOCKED_CALLS = (
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
    "shutdown", "setsockopt", "getsockopt", "getsockname", "getpeername",
    "io_uring_setup", "io_uring_register", "io_uring_enter",
)


def install_filter():
    sec = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    sec.seccomp_init.argtypes = [ctypes.c_uint32]
    sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    sec.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    sec.seccomp_load.argtypes = [ctypes.c_void_p]
    sec.seccomp_release.argtypes = [ctypes.c_void_p]
    sec.seccomp_release.restype = None
    ctx = sec.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not ctx:
        raise RuntimeError("Could not initialize seccomp")
    try:
        for name in BLOCKED_CALLS:
            number = sec.seccomp_syscall_resolve_name(name.encode())
            if number < 0:
                raise RuntimeError(f"Unknown syscall {name}")
            result = sec.seccomp_rule_add(ctx, 0x00050000 | errno.EPERM, number, 0)
            if result != 0:
                raise OSError(-result, f"Could not deny {name}")
        result = sec.seccomp_load(ctx)
        if result != 0:
            raise OSError(-result, "Could not install seccomp filter")
    finally:
        sec.seccomp_release(ctx)


def main():
    command = sys.argv[1:]
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        sys.exit("Usage: python3 offline_exec.py -- executable [arguments ...]")
    for name in os.listdir("/proc/self/fd"):
        fd = int(name)
        try:
            mode = os.fstat(fd).st_mode
        except OSError:
            continue
        if fd > 2:
            os.close(fd)
        elif stat.S_ISSOCK(mode):
            raise RuntimeError("Use a file, pipe or terminal for standard I/O")
    os.environ.update({
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "HF_HUB_DISABLE_TELEMETRY": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PIP_NO_INDEX": "1",
    })
    install_filter()
    os.execvp(command[0], command)


if __name__ == "__main__":
    main()

"""Linux libseccomp launcher for trusted offline qualification processes and children."""
import ctypes
import errno
import os
import sys

lib = ctypes.CDLL("libseccomp.so.2")
lib.seccomp_init.argtypes = [ctypes.c_uint32]
lib.seccomp_init.restype = ctypes.c_void_p
lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
lib.seccomp_load.argtypes = [ctypes.c_void_p]
lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
ctx = lib.seccomp_init(0x7fff0000)
if not ctx:
    raise RuntimeError("seccomp initialization failed")
for name in ("socket", "socketpair", "connect", "io_uring_setup"):
    nr = lib.seccomp_syscall_resolve_name(name.encode())
    if nr < 0 or lib.seccomp_rule_add(ctx, 0x50000 | errno.EPERM, nr, 0):
        raise RuntimeError(f"could not restrict {name}")
if lib.seccomp_load(ctx):
    raise RuntimeError("could not load filter")
os.closerange(3, os.sysconf("SC_OPEN_MAX"))
os.execvp(sys.argv[1], sys.argv[1:])

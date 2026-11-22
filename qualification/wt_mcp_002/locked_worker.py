"""Install the second, irreversible process filter before loading the selected role."""
import ctypes
import errno
import runpy
import sys

lib = ctypes.CDLL("libseccomp.so.2")
lib.seccomp_init.argtypes = [ctypes.c_uint32]
lib.seccomp_init.restype = ctypes.c_void_p
lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
lib.seccomp_load.argtypes = [ctypes.c_void_p]
lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
ctx = lib.seccomp_init(0x7fff0000)
if not ctx:
    raise SystemExit(2)
for name in ("execve","execveat","fork","vfork","clone","clone3","unshare","setns","mount","ptrace"):
    nr = lib.seccomp_syscall_resolve_name(name.encode())
    if nr < 0 or lib.seccomp_rule_add(ctx,0x50000 | errno.EPERM,nr,0):
        raise SystemExit(2)
if lib.seccomp_load(ctx):
    raise SystemExit(2)
sys.argv[0] = "/role.py"
runpy.run_path("/role.py",run_name="__main__")

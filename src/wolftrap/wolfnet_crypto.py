"""Ed25519 verification through the system libsodium ABI. No network key discovery."""

from __future__ import annotations

import ctypes
import platform
import stat
from functools import lru_cache
from pathlib import Path

from .cursorial_trace import Gap, need

PTR = ctypes.c_void_p
SIZE = ctypes.c_ulonglong


@lru_cache(maxsize=1)
def sodium():
    """Only distributor-owned Linux libraries at known ABI locations are supported."""
    multiarch = {"x86_64": "x86_64-linux-gnu", "aarch64": "aarch64-linux-gnu"}.get(platform.machine())
    need(platform.system() == "Linux" and multiarch is not None, "BLOCKED-ed25519-backend")
    try:
        base = Path("/usr/lib") / multiarch
        path = (base / "libsodium.so.23").resolve(strict=True)
        owner = Path("/usr").stat().st_uid
        need(path.parent == base and stat.S_ISREG(path.stat().st_mode), "BLOCKED-ed25519-backend")
        for part in (path, *path.parents):
            info = part.stat()
            need(info.st_uid == owner and not info.st_mode & 0o022, "BLOCKED-untrusted-crypto-installation")
        lib = ctypes.CDLL(str(path))
        signatures = {"sodium_init": ([], ctypes.c_int), "sodium_version_string": ([], ctypes.c_char_p),
                      "crypto_core_ed25519_is_valid_point": ([PTR], ctypes.c_int),
                      "crypto_sign_ed25519_verify_detached": ([PTR, PTR, SIZE, PTR], ctypes.c_int),
                      "crypto_sign_ed25519_seed_keypair": ([PTR, PTR, PTR], ctypes.c_int),
                      "crypto_sign_ed25519_detached": ([PTR, PTR, PTR, SIZE, PTR], ctypes.c_int)}
        for name, (args, result) in signatures.items():
            fn = getattr(lib, name)
            fn.argtypes, fn.restype = args, result
        version = tuple(int(v) for v in lib.sodium_version_string().decode("ascii").split("."))
        need(lib.sodium_init() >= 0 and version >= (1, 0, 18), "BLOCKED-ed25519-backend")
        return lib
    except (OSError, AttributeError, UnicodeError, TypeError, ValueError) as exc:
        if isinstance(exc, Gap):
            raise
        raise Gap("BLOCKED-ed25519-backend") from None


def valid_key(public: bytes) -> bool:
    return len(public) == 32 and sodium().crypto_core_ed25519_is_valid_point(public) == 1


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    return (len(signature) == 64 and valid_key(public)
            and sodium().crypto_sign_ed25519_verify_detached(signature, message, len(message), public) == 0)

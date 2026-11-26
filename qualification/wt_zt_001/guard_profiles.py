"""Bounded fixture controls for GR-01, GR-03, GR-04 and GR-07."""
import os
from pathlib import PurePosixPath
import stat


def reset_fixture(selector, databases):
    """The resource map is host-owned and contains only two in-memory databases."""
    if selector != "fixture-test":
        return "DENY"
    with databases["fixture-test"] as db:
        db.execute("DELETE FROM sample")
    return "APPLIED"


def capture_candidate(root_fd, relative):
    """Descriptor-relative selection, read only. Return a bounded complete regular file."""
    parts = relative.split("/")
    if (PurePosixPath(relative).is_absolute() or any(p in {"", ".", ".."} for p in parts)
            or any(c in relative for c in "*?[]\\:")):
        return "HOLD"
    fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(parts[-1], os.O_NOFOLLOW | os.O_NONBLOCK | os.O_RDONLY, dir_fd=fd)
        with os.fdopen(leaf, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 4096:
                return "HOLD"
            data = stream.read(4097)
            if len(data) != info.st_size:
                return "HOLD"
            return data
    except OSError:
        return "HOLD"
    finally:
        os.close(fd)


def retire_fixture(active, resource):
    """Only the volatile fictional resource map is in this authority's interface."""
    return active.pop(resource, None) is not None

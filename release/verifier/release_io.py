"""Bounded subscriber-side file and ZIP handling. The verifier never imports the wheel."""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import zipfile

BUNDLE_LIMIT = 6 * 1024 * 1024
WHEEL_LIMIT = 4 * 1024 * 1024
DOC_LIMIT = 128 * 1024
OPEN_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


class Verdict(Exception):
    def __init__(self, status, reason):
        self.status = status
        self.reason = reason
        super().__init__(reason)


def require(condition, reason, status="REJECTED"):
    if not condition:
        raise Verdict(status, reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(obj):
    return (json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False) + "\n").encode(
        "ascii"
    )


def parse(data, limit=DOC_LIMIT):
    require(0 < len(data) <= limit, "document-size")

    def unique(pairs):
        obj = dict(pairs)
        require(len(obj) == len(pairs), "duplicate-json-key")
        return obj

    try:
        obj = json.loads(data.decode("ascii"), object_pairs_hook=unique)
        pending = [(obj, 0)]
        nodes = 0
        while pending:
            item, depth = pending.pop()
            nodes += 1
            require(nodes <= 6000 and depth <= 16, "json-complexity")
            if type(item) is dict:
                pending.extend((v, depth + 1) for v in item.values())
            elif type(item) is list:
                pending.extend((v, depth + 1) for v in item)
            else:
                require(type(item) in (str, int, bool, type(None)), "json-value")
        require(data == encode(obj), "noncanonical-json")
        return obj
    except (ValueError, UnicodeError, RecursionError):
        raise Verdict("REJECTED", "malformed-json") from None


def path(value):
    raw = os.fspath(value)
    p = Path(raw)
    require(
        raw
        and len(os.fsencode(raw)) <= 4096
        and len(p.parts) <= 64
        and ".." not in p.parts
        and not raw.startswith("//")
        and "\\" not in raw
        and "\0" not in raw,
        "unsafe-path",
    )
    return p.absolute()


def directory(p):
    p = path(p)
    fd = os.open("/", OPEN_DIR)
    try:
        for component in p.parts[1:]:
            nxt = os.open(component, OPEN_DIR, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def stamp(s):
    return s.st_dev, s.st_ino, s.st_mode, s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns


def file_bytes(p, limit):
    p = path(p)
    parent = directory(p.parent)
    try:
        fd = os.open(p.name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "unsafe-input-file")
            require(0 < info.st_size <= limit, "input-size")
            with open(f"/proc/self/fd/{fd}", "rb") as stream:
                data = stream.read(limit + 1)
            require(
                len(data) == info.st_size
                and stamp(info) == stamp(os.fstat(fd))
                and stamp(info) == stamp(os.stat(p.name, dir_fd=parent, follow_symlinks=False)),
                "input-changed",
            )
            return data
        finally:
            os.close(fd)
    finally:
        os.close(parent)


def unzip(raw, *, wheel=False):
    limit = WHEEL_LIMIT if wheel else BUNDLE_LIMIT
    require(0 < len(raw) <= limit, "archive-size")
    result = {}
    cap_count = 256 if wheel else 12
    require(len(raw) >= 22, "malformed-archive")
    magic, disk, central_disk, count, total_count, size, offset, comment = struct.unpack(
        "<4s4H2IH", raw[-22:]
    )
    require(
        magic == b"PK\x05\x06"
        and disk == central_disk == comment == 0
        and count == total_count
        and 1 <= count <= cap_count
        and size <= count * 246
        and offset + size == len(raw) - 22,
        "archive-directory-bounds",
    )
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            entries = z.infolist()
            require(len(entries) == count and not z.comment, "archive-inventory")
            total = 0
            for i in entries:
                n = i.filename
                require(
                    n == i.orig_filename
                    and len(n) <= 200
                    and n not in result
                    and not i.is_dir()
                    and all(re.fullmatch(r"[a-zA-Z0-9_][a-zA-Z0-9._-]*", piece) for piece in n.split("/"))
                    and (wheel or "/" not in n),
                    "unsafe-archive-member",
                )
                require(
                    stat.S_IFMT(i.external_attr >> 16) in (0, stat.S_IFREG)
                    and i.compress_type == zipfile.ZIP_STORED
                    and not i.flag_bits
                    and not i.extra
                    and not i.comment
                    and i.file_size == i.compress_size,
                    "unsupported-archive-member",
                )
                total += i.file_size
                cap = 1024 * 1024 if wheel else WHEEL_LIMIT if n.endswith(".whl") else DOC_LIMIT
                require(0 <= i.file_size <= cap and total <= limit, "archive-work-limit")
                result[n] = z.read(i)
            # The transport has one deterministic representation. Reject prefixes,
            # hidden local entries, trailing bytes, gaps and parser differentials.
            require(raw == pack(result), "noncanonical-archive")
            return result
    except (zipfile.BadZipFile, RuntimeError, UnicodeError, ValueError, OverflowError, OSError):
        raise Verdict("REJECTED", "malformed-archive") from None


def pack(files):
    dest = io.BytesIO()
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return dest.getvalue()

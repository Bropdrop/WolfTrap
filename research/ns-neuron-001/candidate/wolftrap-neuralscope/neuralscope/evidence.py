"""Closed-inventory evidence receipts; no signatures or authenticity assertions.

Verification assumes a quiescent local evidence directory. Individual regular
files are checked for modification while read, and the receipt's hash and parsed
inventory use the same bytes. Directory traversal does not defend against an
attacker concurrently replacing parent directories; this is not an OS sandbox.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat

MAX_FILES = 10000
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_PAYLOAD_BYTES = 2 * 1024 * 1024 * 1024
SCHEMA = "wolftrap.neuralscope.evidence/v1"


def canonical(value):
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with path.open("xb") as handle:
        handle.write(canonical(value))


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_bounded(path, limit):
    if type(limit) is not int or limit < 1:
        raise ValueError("read limit must be a positive integer")
    with _open_regular(path) as handle:
        original = os.fstat(handle.fileno())
        if original.st_size > limit:
            raise ValueError("JSON input exceeds size bound")
        data = handle.read(limit + 1)
        final = os.fstat(handle.fileno())
        before = (original.st_dev, original.st_ino, original.st_size,
                  original.st_mtime_ns, original.st_ctime_ns)
        after = (final.st_dev, final.st_ino, final.st_size,
                 final.st_mtime_ns, final.st_ctime_ns)
        if len(data) > limit:
            raise ValueError("JSON input exceeds size bound")
        if len(data) != original.st_size or before != after:
            raise ValueError("JSON input changed while reading")
    return data


def _parse_json(data):
    return json.loads(data, object_pairs_hook=_unique_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(
                          ValueError("non-finite JSON value")))


def read_json(path, limit=MAX_MANIFEST_BYTES):
    return _parse_json(_read_bounded(path, limit))


def _open_regular(path):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("evidence must be a regular file with one link")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def digest(path):
    sha = hashlib.sha256()
    with _open_regular(path) as handle:
        original = os.fstat(handle.fileno())
        if original.st_size > MAX_PAYLOAD_BYTES:
            raise ValueError("payload exceeds size bound")
        total = 0
        for data in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(data)
            if total > MAX_PAYLOAD_BYTES:
                raise ValueError("payload grew beyond size bound")
            sha.update(data)
        final = os.fstat(handle.fileno())
        if total != original.st_size or (original.st_mtime_ns, original.st_ctime_ns) != (
                final.st_mtime_ns, final.st_ctime_ns):
            raise ValueError("payload changed while reading")
    return {"bytes": total, "sha256": sha.hexdigest()}


def _inventory(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("evidence root must be a real directory")
    found, directories = {}, set()
    for parent, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames:
            directory = Path(parent) / name
            if not stat.S_ISDIR(directory.lstat().st_mode):
                raise ValueError("symlink or special directory in evidence")
            directories.add(directory.relative_to(root).as_posix())
        for name in filenames:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            if relative != "manifest.json":
                found[relative] = digest(path)
            if len(found) + len(directories) > MAX_FILES:
                raise ValueError("evidence inventory exceeds bound")
    return found, directories


def seal(root, context):
    root = Path(root)
    if (root / "manifest.json").exists():
        raise ValueError("refusing to replace an evidence receipt")
    files, directories = _inventory(root)
    manifest = {"schema": SCHEMA, "context": context, "files": files,
                "directories": sorted(directories),
                "claim": "byte integrity relative to this unsigned receipt only"}
    write_json(root / "manifest.json", manifest)
    return digest(root / "manifest.json")["sha256"]


def verify(root, expected_manifest_sha256=None):
    """Check a quiescent local inventory against one captured receipt.

    A supplied receipt digest pins the exact bytes parsed here. It does not
    authenticate their author or protect concurrent directory substitutions.
    """
    root = Path(root)
    manifest_bytes = _read_bounded(root / "manifest.json", MAX_MANIFEST_BYTES)
    manifest_identity = {"bytes": len(manifest_bytes),
                         "sha256": hashlib.sha256(manifest_bytes).hexdigest()}
    if expected_manifest_sha256 is not None and manifest_identity["sha256"] != expected_manifest_sha256:
        raise ValueError("receipt does not match independently retained digest")
    manifest = _parse_json(manifest_bytes)
    if (not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA
            or not isinstance(manifest.get("files"), dict)):
        raise ValueError("unsupported evidence receipt")
    for name, record in manifest["files"].items():
        parts = PurePosixPath(name)
        if (not name or name == "manifest.json" or "\\" in name or parts.is_absolute()
                or ".." in parts.parts or parts.as_posix() != name):
            raise ValueError("unsafe inventory member")
        if (not isinstance(record, dict) or set(record) != {"bytes", "sha256"}
                or type(record["bytes"]) is not int or record["bytes"] < 0
                or not isinstance(record["sha256"], str) or len(record["sha256"]) != 64):
            raise ValueError("invalid inventory record")
    files, directories = _inventory(root)
    if files != manifest["files"] or sorted(directories) != manifest.get("directories"):
        raise ValueError("closed inventory or file digest mismatch")
    return {"status": "INTEGRITY_MATCH", "manifest_sha256": manifest_identity["sha256"],
            "files": len(files), "publisher_authenticated": False,
            "externally_pinned_receipt": expected_manifest_sha256 is not None,
            "scientific_claims_verified": False,
            "concurrency_scope": "quiescent local evidence directory"}

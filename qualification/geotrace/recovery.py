"""WT-GEO-R00: inert GeoTrace v1 ZIP custody and inventory gate.

This is NOT GeoTrace v1 or v2. It never extracts or runs archive members.
It does not establish provenance, compatibility, test success, or authority.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import unicodedata
import zipfile

SCHEMA = "wolftrap.geotrace-recovery/v1"
MANIFEST_SCHEMA = "wolftrap.geotrace-recovery-manifest/v1"
REPORT = "geotrace-recovery.json"
MARKDOWN = "geotrace-recovery.md"
MANIFEST = "geotrace-recovery.manifest.json"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_FILES = 512
MAX_MEMBER = 8 * 1024 * 1024
MAX_UNCOMPRESSED = 64 * 1024 * 1024
MAX_COMPONENT_DEPTH = 16
MAX_RATIO = 250
REPO_ROOT = Path(__file__).resolve().parents[2]


class UnsafeArtifact(ValueError):
    pass


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def strict_json(data: bytes) -> object:
    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise UnsafeArtifact("duplicate JSON key")
            result[key] = value
        return result

    def bad_constant(_: str) -> None:
        raise UnsafeArtifact("nonfinite JSON number")

    return json.loads(data, object_pairs_hook=pairs, parse_constant=bad_constant)


def read_regular(path: Path, bound: int) -> bytes:
    if not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink():
        raise UnsafeArtifact("input is not a plain regular file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > bound:
            raise UnsafeArtifact("input is not a bounded regular file")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(bound + 1)
        if len(raw) > bound or len(raw) != metadata.st_size:
            raise UnsafeArtifact("input size changed or exceeded bound")
        return raw
    finally:
        os.close(fd)


def safe_archive_name(name: str, directory: bool) -> str:
    if (not name or len(name) > 240 or "\\" in name or "\x00" in name
            or name.startswith("/") or name.startswith("~")
            or unicodedata.normalize("NFC", name) != name
            or any(ord(c) < 32 or ord(c) == 127 for c in name)):
        raise UnsafeArtifact("unsafe ZIP member name")
    clean = name[:-1] if directory and name.endswith("/") else name
    segments = clean.split("/")
    if (not clean or len(segments) > MAX_COMPONENT_DEPTH
            or any(seg in ("", ".", "..") or ":" in seg for seg in segments)):
        raise UnsafeArtifact("noncanonical ZIP path")
    if directory and not name.endswith("/"):
        raise UnsafeArtifact("directory missing canonical slash")
    if not directory and name.endswith("/"):
        raise UnsafeArtifact("file has trailing slash")
    return clean


def inventory_zip(archive: bytes) -> list[dict[str, object]]:
    try:
        z = zipfile.ZipFile(io.BytesIO(archive), mode="r", allowZip64=True)
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise UnsafeArtifact("not a readable ZIP archive") from exc
    try:
        infos = z.infolist()
        if not infos or len(infos) > MAX_FILES:
            raise UnsafeArtifact("ZIP file count outside allowed bounds")
        paths: dict[str, str] = {}
        entries: list[dict[str, object]] = []
        total = 0
        for info in infos:
            kind = stat.S_IFMT(info.external_attr >> 16)
            is_dir = info.is_dir()
            if kind not in (0, stat.S_IFDIR if is_dir else stat.S_IFREG):
                raise UnsafeArtifact("ZIP contains a link or special file")
            if info.flag_bits & 1:
                raise UnsafeArtifact("encrypted ZIP members not supported")
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise UnsafeArtifact("unsupported ZIP compression")
            name = safe_archive_name(info.filename, is_dir)
            alias = name.casefold()
            if alias in paths:
                raise UnsafeArtifact("duplicate or case-ambiguous ZIP path")
            paths[alias] = "dir" if is_dir else "file"
            if is_dir:
                if info.file_size != 0:
                    raise UnsafeArtifact("nonempty directory member")
                continue
            if info.file_size > MAX_MEMBER:
                raise UnsafeArtifact("ZIP member uncompressed size exceeds bound")
            if info.file_size > 4096 and info.file_size / max(info.compress_size, 1) > MAX_RATIO:
                raise UnsafeArtifact("ZIP compression ratio exceeds bound")
            total += info.file_size
            if total > MAX_UNCOMPRESSED:
                raise UnsafeArtifact("ZIP expanded size exceeds bound")
            digest = hashlib.sha256()
            actual = 0
            try:
                with z.open(info, "r") as member:
                    while True:
                        chunk = member.read(min(128 * 1024, MAX_MEMBER + 1 - actual))
                        if not chunk:
                            break
                        actual += len(chunk)
                        if actual > MAX_MEMBER or actual > info.file_size:
                            raise UnsafeArtifact("ZIP member changed or exceeded bound")
                        digest.update(chunk)
            except (OSError, ValueError, RuntimeError, EOFError, zipfile.BadZipFile) as exc:
                raise UnsafeArtifact("ZIP payload invalid or inconsistent") from exc
            if actual != info.file_size:
                raise UnsafeArtifact("ZIP payload size mismatch")
            entries.append({"path": name, "bytes": actual, "compressed_bytes": info.compress_size, "sha256": digest.hexdigest()})
        for alias, kind in paths.items():
            components = alias.split("/")
            for pos in range(1, len(components)):
                ancestor = "/".join(components[:pos])
                if paths.get(ancestor) == "file":
                    raise UnsafeArtifact("ZIP path has file-as-directory collision")
        if not entries:
            raise UnsafeArtifact("ZIP contains no regular files")
        return sorted(entries, key=lambda item: str(item["path"]))
    finally:
        z.close()


def build_report(raw: bytes, anchored_sha256: str | None) -> dict[str, object]:
    identity = sha(raw)
    if anchored_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", anchored_sha256):
            raise UnsafeArtifact("expected SHA-256 must be 64 lowercase hex characters")
        if not hmac.compare_digest(identity, anchored_sha256):
            raise UnsafeArtifact("archive does not match independently selected digest")
    return {
        "schema": SCHEMA,
        "mission": "WT-ZT-001/GEOTRACE-RECOVERY",
        "qualification": "BLOCKED_ORIGINAL_BASELINE_NOT_EXECUTED",
        "inventory": inventory_zip(raw),
        "archive": {"bytes": len(raw), "sha256": identity},
        "expected_digest_supplied": anchored_sha256 is not None,
        "digest_match_only": anchored_sha256 is not None,
        "original_custody_verified": False,
        "original_21_tests_executed": 0,
        "geotrace_v1_compatibility": "NOT_TESTED",
        "geotrace_v2_integration": "BLOCKED",
        "archive_members_extracted": False,
        "archive_code_executed": False,
        "network_access_requested": False,
        "limitation": (
            "Inert ZIP inspection proves only bounded readability and bytes relative to an expected "
            "digest if independently selected. It cannot prove origin, author, baseline compatibility, "
            "test results, or release readiness."
        ),
    }


def render(report: dict[str, object]) -> bytes:
    lines = [
        "# GeoTrace original-archive custody gate", "",
        "Status: BLOCKED_ORIGINAL_BASELINE_NOT_EXECUTED", "",
        "Only inert ZIP structure and archive member bytes were inspected.",
        "No archive code was executed or extracted; no geolocation service was contacted.", "",
        "Original v1 tests executed in this run: 0", "",
        "Original custody verified: NO", "",
        "Full ZIP SHA-256: " + str(report["archive"]["sha256"]),
        "Archive size (bytes): " + str(report["archive"]["bytes"]),
        "Member count: " + str(len(report["inventory"])), "",
        "An independently obtained expected hash is not by itself proof of publisher identity.",
        "Original 21-case test suite must be inspected and independently executed after source recovery.", "",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def open_evidence(output: Path) -> None:
    if output.is_symlink() or output.exists():
        raise UnsafeArtifact("evidence directory must be new and not a symlink")
    absolute = output.resolve(strict=False)
    if absolute.is_relative_to(REPO_ROOT.resolve()):
        raise UnsafeArtifact("evidence must remain outside the source checkout")
    if not output.parent.is_dir():
        raise UnsafeArtifact("evidence parent must already exist")
    output.mkdir(mode=0o700, parents=False, exist_ok=False)


def publish(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, mode=0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)


def create(archive: Path, output: Path, expected: str | None) -> dict[str, object]:
    raw = read_regular(archive, MAX_ARCHIVE)
    report = build_report(raw, expected)
    body = encode(report)
    markdown = render(report)
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "state": "COMPLETE_INVENTORY_ONLY",
        "qualification": report["qualification"],
        "archive_sha256": report["archive"]["sha256"],
        "files": {
            REPORT: {"bytes": len(body), "sha256": sha(body)},
            MARKDOWN: {"bytes": len(markdown), "sha256": sha(markdown)},
        },
    }
    open_evidence(output)
    publish(output / REPORT, body)
    publish(output / MARKDOWN, markdown)
    publish(output / MANIFEST, encode(manifest))
    return report


def validate(archive: Path, directory: Path, expected: str | None) -> dict[str, object]:
    if not directory.is_dir() or directory.is_symlink():
        raise UnsafeArtifact("evidence directory unavailable")
    if {x.name for x in directory.iterdir()} != {REPORT, MARKDOWN, MANIFEST}:
        raise UnsafeArtifact("evidence contains missing or unexpected members")
    manifest = strict_json(read_regular(directory / MANIFEST, 128 * 1024))
    if not isinstance(manifest, dict) or (
        manifest.get("schema") != MANIFEST_SCHEMA
        or manifest.get("state") != "COMPLETE_INVENTORY_ONLY"
        or set(manifest.get("files", {})) != {REPORT, MARKDOWN}
    ):
        raise UnsafeArtifact("invalid recovery manifest")
    payload = {}
    for name in (REPORT, MARKDOWN):
        raw = read_regular(directory / name, 2 * 1024 * 1024)
        if manifest["files"][name] != {"bytes": len(raw), "sha256": sha(raw)}:
            raise UnsafeArtifact("recovery file bytes do not match manifest")
        payload[name] = raw
    saved = strict_json(payload[REPORT])
    fresh = build_report(read_regular(archive, MAX_ARCHIVE), expected)
    if saved != fresh or payload[REPORT] != encode(fresh) or payload[MARKDOWN] != render(fresh):
        raise UnsafeArtifact("recovery report differs from an independent archive reread")
    if manifest["archive_sha256"] != fresh["archive"]["sha256"] or manifest["qualification"] != fresh["qualification"]:
        raise UnsafeArtifact("manifest conflicts with archive")
    return fresh


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("inspect", "verify"):
        p = sub.add_parser(command)
        p.add_argument("--archive", type=Path, required=True)
        p.add_argument("--evidence-dir", type=Path, required=True)
        p.add_argument("--expected-sha256", default=None)
    args = parser.parse_args(argv)
    try:
        if args.command == "inspect":
            report = create(args.archive, args.evidence_dir, args.expected_sha256)
        else:
            report = validate(args.archive, args.evidence_dir, args.expected_sha256)
    except (UnsafeArtifact, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"BLOCKED: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    print(f"{report['qualification']}: {len(report['inventory'])} inert ZIP members; 0 GeoTrace tests")
    return 0  # inventory tool success only; release qualification explicitly BLOCKED


if __name__ == "__main__":
    raise SystemExit(main())

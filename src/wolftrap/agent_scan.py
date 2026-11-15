"""Bounded offline agent-boundary inspection; no target code is executed.

Source names and source text are never copied into evidence. Locations use a
SHA-256 of the root-relative path, plus line number. Directory-descriptor walks
reject symlink components and bound discovery before source reads.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .agent_rules import inspect_text

MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
MAX_FILES = 64
MAX_ENTRIES = 1024
MAX_DEPTH = 12
MAX_FINDINGS = 256
SUFFIXES = (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")
EXCLUDED_DIRECTORIES = (".git", "node_modules")
REPORT_NAME = "agent-scan.json"
MARKDOWN_NAME = "agent-scan.md"
SARIF_NAME = "agent-scan.sarif"
MANIFEST_NAME = "agent-scan.manifest.json"
RULES = {
    "WT-AGENT-001": "Guardrail error path has an allow-like outcome",
    "WT-AGENT-002": "Authentication or approval callback has unconditional success",
    "WT-AGENT-003": "Session credential reaches an explicit browser-visible sink",
}


@dataclass(frozen=True)
class AgentScanOutcome:
    report: dict[str, Any]
    exit_code: int


class AgentInputError(ValueError):
    """Sanitized incomplete inspection; never carries source content."""


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                       indent=2) + "\n").encode("utf-8")


def _open_directory(path: Path, *, create: bool = False) -> int:
    """Walk from / with O_NOFOLLOW on every component; hold final directory."""
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise AgentInputError("safe descriptor-relative file access is unavailable")
    absolute = Path(os.path.abspath(path))
    if ".." in path.parts:
        raise AgentInputError("parent traversal is unsupported")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(absolute.anchor, flags)
    try:
        for component in absolute.parts[1:]:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_file(directory: int, name: str, limit: int = MAX_FILE_BYTES) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(name, flags, dir_fd=directory)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise AgentInputError("input is nonregular or exceeds its byte bound")
        chunks: list[bytes] = []
        remaining = limit + 1
        while remaining:
            raw = os.read(fd, min(65536, remaining))
            if not raw:
                break
            chunks.append(raw)
            remaining -= len(raw)
        raw = b"".join(chunks)
        after = os.fstat(fd)
        if (len(raw) > limit or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            raise AgentInputError("input changed or exceeded its byte bound")
        return raw
    finally:
        os.close(fd)


def _selected_file(root: int, relative: str) -> bytes:
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise AgentInputError("invalid input selection")
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or len(path.parts) > MAX_DEPTH:
        raise AgentInputError("input selection escapes root or exceeds depth bound")
    if path.suffix.lower() not in SUFFIXES:
        raise AgentInputError("selected file extension is unsupported")
    descriptor = os.dup(root)
    try:
        for component in path.parts[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return _read_file(descriptor, path.name)
    finally:
        os.close(descriptor)


def _discover(root: int) -> tuple[list[str], int, int]:
    paths: list[str] = []
    entries_seen = 0
    ignored = 0

    def walk(directory: int, prefix: str, depth: int) -> None:
        nonlocal entries_seen, ignored
        if depth > MAX_DEPTH:
            raise AgentInputError("source directory depth exceeds inspection bound")
        before = os.fstat(directory)
        names: list[str] = []
        with os.scandir(directory) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > MAX_ENTRIES:
                    raise AgentInputError("source discovery exceeds entry bound")
                names.append(entry.name)
        for name in sorted(names):
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if name in EXCLUDED_DIRECTORIES:
                ignored += 1
                continue
            if stat.S_ISLNK(metadata.st_mode):
                raise AgentInputError("source discovery encountered a symlink")
            relative = prefix + name
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
                try:
                    walk(child, relative + "/", depth + 1)
                finally:
                    os.close(child)
            elif Path(name).suffix.lower() in SUFFIXES:
                if not stat.S_ISREG(metadata.st_mode):
                    raise AgentInputError("supported source is not a regular file")
                paths.append(relative)
                if len(paths) > MAX_FILES:
                    raise AgentInputError("source exceeds file-count bound")
            else:
                ignored += 1
        after = os.fstat(directory)
        if before.st_mtime_ns != after.st_mtime_ns or before.st_ctime_ns != after.st_ctime_ns:
            raise AgentInputError("source directory changed during discovery")

    walk(root, "", 0)
    return paths, entries_seen, ignored


def _publish(directory: int, name: str, raw: bytes) -> None:
    """Atomic fixed-name publication relative to an already opened directory."""
    temporary = "." + name + ".pending"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    except BaseException:
        try:
            os.unlink(temporary, dir_fd=directory)
        except OSError:
            pass
        raise


def _output_directory(source: Path, output: Path) -> int:
    try:
        src = source.resolve(strict=False)
        out = output.resolve(strict=False)
        if out == src or out.is_relative_to(src) or src.is_relative_to(out):
            raise ValueError("agent evidence must be outside inspected source")
        fd = _open_directory(output, create=True)
        if os.listdir(fd):
            os.close(fd)
            raise ValueError("agent evidence directory must be fresh or empty")
        return fd
    except (OSError, AgentInputError, RuntimeError) as exc:
        raise ValueError("agent evidence directory cannot be safely opened") from None


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    lines = ["# WolfTrap Stage 5.1 agent trust-boundary inspection", "",
             "Conditional static review only. No confirmed vulnerability or security certification.",
             "", "Status: " + report["qualification"]["status"], "",
             "Locations are SHA-256 path aliases; source text and credential values are omitted.",
             "Output moderation is distinct from tool authorization.", ""]
    for finding in report["findings"]:
        lines.append(f"- {finding['rule_id']} at {finding['path']}:{finding['line']} — {finding['title']}")
    for issue in report["errors"]:
        lines.append("- Incomplete inspection: " + issue)
    sarif = {
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "WolfTrap scan-agent", "rules": [
                {"id": key, "shortDescription": {"text": value}}
                for key, value in RULES.items()
            ]}},
            "invocations": [{"executionSuccessful": not report["errors"]}],
            "results": [{"ruleId": item["rule_id"], "level": "warning",
                "message": {"text": item["title"] + ". Conditional review required."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": item["path"]},
                    "region": {"startLine": item["line"]}}}],
                "partialFingerprints": {"wolftrap/v1": item["id"]},
                "properties": {"classification": "REVIEW_REQUIRED",
                               "confidence": "CONDITIONAL_STATIC",
                               "boundary": item["boundary"], "context": item["context"]}}
                for item in report["findings"]]
        }]
    }
    return {REPORT_NAME: _json(report), MARKDOWN_NAME: ("\n".join(lines) + "\n").encode(),
            SARIF_NAME: _json(sarif)}


def scan_agent(root: str | Path, output_dir: str | Path, *,
               files: Sequence[str] | None = None) -> AgentScanOutcome:
    """Inspect selected local JS/TS or bounded discovery; output is outside root."""
    source = Path(root)
    output = _output_directory(source, Path(output_dir))
    try:
        _publish(output, MANIFEST_NAME, _json({"state": "INCOMPLETE"}))
        inventory: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        errors: list[str] = []
        entries = ignored = total = 0
        descriptor: int | None = None
        try:
            descriptor = _open_directory(source)
            if files is None:
                selections, entries, ignored = _discover(descriptor)
            else:
                if isinstance(files, (str, bytes)) or not 1 <= len(files) <= MAX_FILES:
                    raise AgentInputError("invalid selected-file count")
                if not all(isinstance(item, str) for item in files):
                    raise AgentInputError("invalid input selection")
                selections = sorted(set(files))
            if not selections:
                raise AgentInputError("no supported source files selected")
            for relative in selections:
                raw = _selected_file(descriptor, relative)
                total += len(raw)
                if total > MAX_TOTAL_BYTES:
                    raise AgentInputError("source exceeds total-byte bound")
                path_digest = _sha(relative.encode("utf-8", errors="surrogatepass"))
                alias = "source-" + path_digest + Path(relative).suffix.lower()
                inventory.append({"path": alias, "source_path_sha256": path_digest,
                                  "bytes": len(raw), "sha256": _sha(raw)})
                try:
                    text = raw.decode("utf-8", errors="strict")
                except UnicodeDecodeError:
                    raise AgentInputError("source is not valid UTF-8") from None
                signals, issues = inspect_text(text)
                errors.extend(issues)
                for signal in signals:
                    if len(findings) >= MAX_FINDINGS:
                        raise AgentInputError("finding count exceeds evidence bound")
                    item = dict(signal)
                    item.update(path=alias, title=RULES[item["rule_id"]],
                                classification="REVIEW_REQUIRED", confidence="CONDITIONAL_STATIC")
                    item["id"] = "WT-AGENT-" + _sha(_json(item))[:20].upper()
                    findings.append(item)
            # Detect ordinary concurrent mutation across the inspection window.
            # This is bounded double collection, not an atomic filesystem snapshot.
            if files is None:
                final_selection, final_entries, final_ignored = _discover(descriptor)
                if (final_selection, final_entries, final_ignored) != (selections, entries, ignored):
                    raise AgentInputError("source inventory changed during inspection")
            for relative, item in zip(selections, inventory):
                if _sha(_selected_file(descriptor, relative)) != item["sha256"]:
                    raise AgentInputError("source bytes changed during inspection")
            current_root = _open_directory(source)
            try:
                initial, current = os.fstat(descriptor), os.fstat(current_root)
                if (initial.st_dev, initial.st_ino) != (current.st_dev, current.st_ino):
                    raise AgentInputError("source root changed during inspection")
            finally:
                os.close(current_root)
        except Exception:
            # Exception messages may contain filenames, source text or literals.
            errors.append("input unavailable, unsafe, unsupported, changed, or outside bounds")
        finally:
            if descriptor is not None:
                os.close(descriptor)
        findings = sorted({item["id"]: item for item in findings}.values(),
                          key=lambda item: (item["path"], item["line"], item["rule_id"]))
        errors = sorted(set(errors))
        status, code = (("INCONCLUSIVE", 2) if errors else
                        ("REVIEW_REQUIRED", 1) if findings else ("NO_PATTERN_MATCH", 0))
        digest = _sha(_json(inventory))
        report = {
            "schema": "wolftrap.stage5.1.agent-scan/v1",
            "target_code_executed": False, "external_systems_contacted": False,
            "model_used": False, "inspected_source_modified": False,
            "qualification": {"status": status, "complete_input": not errors,
                              "confirmed_vulnerabilities": 0, "limited_not_exhaustive": True},
            "coverage": {"supported_extensions": list(SUFFIXES),
                         "excluded_directories": list(EXCLUDED_DIRECTORIES),
                         "input_files": inventory, "input_digest": digest,
                         "directory_entries_seen": entries, "entries_excluded_or_unsupported": ignored,
                         "selection_mode": "explicit" if files is not None else "bounded_discovery",
                         "limits": {"files": MAX_FILES, "file_bytes": MAX_FILE_BYTES,
                                    "total_bytes": MAX_TOTAL_BYTES, "entries": MAX_ENTRIES,
                                    "depth": MAX_DEPTH},
                         "location_encoding": "sha256(root-relative UTF-8 path), plus extension and line"},
            "limitations": ["Conservative lexical recognizers, not complete program-flow analysis.",
                            "No match is not a security certification.",
                            "Output moderation does not establish tool authorization.",
                            "Syntactic mock success does not prove application-wide missing authentication.",
                            "Credential values and source text are never included in evidence."],
            "summary": {"files_inspected": len(inventory), "findings": len(findings), "errors": len(errors)},
            "findings": findings, "errors": errors,
        }
        rendered = _render(report)
        for name, raw in rendered.items():
            _publish(output, name, raw)
        _publish(output, MANIFEST_NAME, _json({
            "schema": "wolftrap.stage5.1.agent-manifest/v1", "state": "COMPLETE",
            "qualification_status": status, "input_digest": digest,
            "files": {name: {"bytes": len(raw), "sha256": _sha(raw)}
                      for name, raw in sorted(rendered.items())}}))
        return AgentScanOutcome(report, code)
    finally:
        os.close(output)


def _validate_report(report: dict[str, Any]) -> None:
    if report["schema"] != "wolftrap.stage5.1.agent-scan/v1":
        raise ValueError
    findings, errors = report["findings"], report["errors"]
    inventory = report["coverage"]["input_files"]
    if (not isinstance(findings, list) or len(findings) > MAX_FINDINGS
            or not isinstance(errors, list) or not isinstance(inventory, list)
            or len(inventory) > MAX_FILES
            or any(type(issue) is not str for issue in errors)):
        raise ValueError
    status = "INCONCLUSIVE" if errors else "REVIEW_REQUIRED" if findings else "NO_PATTERN_MATCH"
    if (report["qualification"] != {"status": status, "complete_input": not errors,
                                    "confirmed_vulnerabilities": 0, "limited_not_exhaustive": True}
            or report["summary"] != {"files_inspected": len(inventory), "findings": len(findings),
                                     "errors": len(errors)}
            or any(report[key] is not False for key in ("target_code_executed",
                "external_systems_contacted", "model_used", "inspected_source_modified"))):
        raise ValueError
    paths = set()
    for item in inventory:
        if (not re.fullmatch(r"[0-9a-f]{64}", item["source_path_sha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or item["path"] not in {"source-" + item["source_path_sha256"] + suffix for suffix in SUFFIXES}
                or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= MAX_FILE_BYTES):
            raise ValueError
        paths.add(item["path"])
    if len(paths) != len(inventory):
        raise ValueError
    for item in findings:
        identity = {key: value for key, value in item.items() if key != "id"}
        if (item["rule_id"] not in RULES or item["title"] != RULES[item["rule_id"]]
                or item["classification"] != "REVIEW_REQUIRED"
                or item["confidence"] != "CONDITIONAL_STATIC"
                or type(item["line"]) is not int or item["line"] < 1
                or item["path"] not in paths
                or item["id"] != "WT-AGENT-" + _sha(_json(identity))[:20].upper()):
            raise ValueError


def verify_agent_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    """Verify the fixed artifact set and input/status bindings without target access."""
    try:
        directory = _open_directory(Path(evidence_dir))
        try:
            manifest = json.loads(_read_file(directory, MANIFEST_NAME, 16384))
            if (manifest.get("state") != "COMPLETE"
                    or manifest.get("schema") != "wolftrap.stage5.1.agent-manifest/v1"
                    or set(manifest.get("files", {})) != {REPORT_NAME, MARKDOWN_NAME, SARIF_NAME}):
                raise ValueError
            payloads = {}
            for name in (REPORT_NAME, MARKDOWN_NAME, SARIF_NAME):
                raw = _read_file(directory, name, 16 * 1024 * 1024)
                if manifest["files"][name] != {"bytes": len(raw), "sha256": _sha(raw)}:
                    raise ValueError
                payloads[name] = raw
            report = json.loads(payloads[REPORT_NAME])
            _validate_report(report)
            if (report["schema"] != "wolftrap.stage5.1.agent-scan/v1"
                    or report["qualification"]["status"] != manifest["qualification_status"]
                    or report["coverage"]["input_digest"] != manifest["input_digest"]
                    or _sha(_json(report["coverage"]["input_files"])) != manifest["input_digest"]
                    or _render(report) != payloads):
                raise ValueError
            return report
        finally:
            os.close(directory)
    except Exception:
        raise ValueError("agent evidence is incomplete, unsafe or inconsistent") from None

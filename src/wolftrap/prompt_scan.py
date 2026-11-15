"""Stage 5.3 bounded, read-only prompt-document source inspection.

This scanner deliberately does not interpret model instructions as commands.
It reuses WolfTrap's no-follow descriptor I/O and fixed, source-free evidence
publication, while keeping a separate input grammar from Stage 5.1 and 5.2.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .agent_scan import (AgentInputError, EXCLUDED_DIRECTORIES, _json,
                         _open_directory, _output_directory, _publish, _read_file, _sha)
from .prompt_rules import RULES, inspect_prompt_document


MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 24 * 1024 * 1024
MAX_FILES = 128
MAX_ENTRIES = 2048
MAX_DEPTH = 12
MAX_FINDINGS = 1024
EXTENSIONS = (".md", ".txt", ".mkd", ".json", "")
REPORT_NAME = "prompt-scan.json"
MARKDOWN_NAME = "prompt-scan.md"
SARIF_NAME = "prompt-scan.sarif"
MANIFEST_NAME = "prompt-scan.manifest.json"
SCHEMA = "wolftrap.stage5.3.prompt-scan/v1"
MANIFEST_SCHEMA = "wolftrap.stage5.3.prompt-manifest/v1"
CONTEXTS = {
    "WT-PROMPT-001": "DOCUMENT_PRIORITY_OVERRIDE",
    "WT-PROMPT-002": "READER_INSTRUCTION_DISCLOSURE",
    "WT-PROMPT-003": "UNTRUSTED_PRIORITY_CLAIM",
    "WT-PROMPT-004": "CREDENTIAL_TRANSFER_REQUEST",
}


@dataclass(frozen=True)
class PromptScanOutcome:
    report: dict[str, Any]
    exit_code: int


def _supported(relative: str) -> bool:
    path = Path(relative)
    return path.suffix.lower() in EXTENSIONS and not path.name.startswith(".")


def _selected_file(root: int, relative: str) -> bytes:
    if not isinstance(relative, str) or not relative or "\x00" in relative:
        raise AgentInputError("invalid selection")
    path = Path(relative)
    if (path.is_absolute() or relative != path.as_posix()
            or ".." in path.parts or any(part in EXCLUDED_DIRECTORIES for part in path.parts)
            or len(path.parts) > MAX_DEPTH or not _supported(relative)):
        raise AgentInputError("unsafe or unsupported selection")
    directory = os.dup(root)
    try:
        for part in path.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
        return _read_file(directory, path.name, MAX_FILE_BYTES)
    finally:
        os.close(directory)


def _discover(root: int) -> tuple[list[str], int, int]:
    selections: list[str] = []
    entries_seen = ignored = 0

    def walk(directory: int, prefix: str, depth: int) -> None:
        nonlocal entries_seen, ignored
        if depth > MAX_DEPTH:
            raise AgentInputError("source exceeds directory-depth bound")
        before = os.fstat(directory)
        names: list[str] = []
        with os.scandir(directory) as entries:
            for entry in entries:
                entries_seen += 1
                if entries_seen > MAX_ENTRIES:
                    raise AgentInputError("source exceeds entry bound")
                names.append(entry.name)
        for name in sorted(names):
            metadata = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if name in EXCLUDED_DIRECTORIES:
                ignored += 1
                continue
            if stat.S_ISLNK(metadata.st_mode):
                raise AgentInputError("source contains a symlink")
            relative = prefix + name
            if stat.S_ISDIR(metadata.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
                try:
                    walk(child, relative + "/", depth + 1)
                finally:
                    os.close(child)
            elif _supported(relative):
                if not stat.S_ISREG(metadata.st_mode):
                    raise AgentInputError("selected source is not regular")
                selections.append(relative)
                if len(selections) > MAX_FILES:
                    raise AgentInputError("source exceeds document-count bound")
            else:
                ignored += 1
        after = os.fstat(directory)
        if (before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns):
            raise AgentInputError("source changed during discovery")

    walk(root, "", 0)
    return sorted(selections), entries_seen, ignored


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    lines = ["# WolfTrap 5.3 untrusted prompt-document triage", "",
             "Offline lexical inspection only. No successful exploit established.", "",
             "Status: " + report["qualification"]["status"], "",
             "Source paths are hashed; no prompt text or credential literals copied.", ""]
    for item in report["findings"]:
        lines.append(f"- {item['rule_id']} at {item['path']}:{item['line']} — "
                     f"{item['title']} ({item['context']})")
    for issue in report["errors"]:
        lines.append("- Incomplete inspection: " + issue)
    lines.extend(["", "Findings require human review of provenance and trust context.",
                  "Quoted model prompts are not granted authority by being in a repository.", ""])
    sarif = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "WolfTrap scan-prompts", "rules": [
            {"id": key, "shortDescription": {"text": title}}
            for key, title in RULES.items()]}},
        "invocations": [{"executionSuccessful": not report["errors"]}],
        "results": [{
            "ruleId": item["rule_id"], "level": "warning",
            "message": {"text": item["title"] + ". Conditional review required."},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": item["path"]},
                "region": {"startLine": item["line"]}}}],
            "partialFingerprints": {"wolftrap/v1": item["id"]},
            "properties": {"classification": "REVIEW_REQUIRED", "confidence": "CONDITIONAL_STATIC",
                           "boundary": item["boundary"], "context": item["context"]},
        } for item in report["findings"]],
    }]}
    return {REPORT_NAME: _json(report),
            MARKDOWN_NAME: ("\n".join(lines) + "\n").encode("utf-8"),
            SARIF_NAME: _json(sarif)}


def scan_prompts(root: str | Path, output_dir: str | Path, *,
                 files: Sequence[str] | None = None) -> PromptScanOutcome:
    """Perform no-follow document inspection without executing target content."""
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
                if (isinstance(files, (str, bytes)) or not 1 <= len(files) <= MAX_FILES
                        or not all(isinstance(item, str) for item in files)):
                    raise ValueError
                selections = sorted(set(files))
            if not selections:
                raise ValueError
            for relative in selections:
                raw = _selected_file(descriptor, relative)
                total += len(raw)
                if total > MAX_TOTAL_BYTES or b"\x00" in raw:
                    raise ValueError
                text = raw.decode("utf-8", errors="strict")
                path_hash = _sha(relative.encode("utf-8", errors="surrogatepass"))
                alias = "source-" + path_hash + Path(relative).suffix.lower()
                inventory.append({"path": alias, "source_path_sha256": path_hash,
                                  "bytes": len(raw), "sha256": _sha(raw)})
                for signal in inspect_prompt_document(relative, text):
                    if len(findings) >= MAX_FINDINGS:
                        raise ValueError
                    item = dict(signal)
                    item.update(path=alias, title=RULES[item["rule_id"]],
                                classification="REVIEW_REQUIRED", confidence="CONDITIONAL_STATIC")
                    item["id"] = "WT-PROMPT-" + _sha(_json(item))[:20].upper()
                    findings.append(item)
            if files is None:
                if _discover(descriptor) != (selections, entries, ignored):
                    raise ValueError
            for relative, item in zip(selections, inventory):
                if _sha(_selected_file(descriptor, relative)) != item["sha256"]:
                    raise ValueError
            current_root = _open_directory(source)
            try:
                old, new = os.fstat(descriptor), os.fstat(current_root)
                if (old.st_dev, old.st_ino) != (new.st_dev, new.st_ino):
                    raise ValueError
            finally:
                os.close(current_root)
        except Exception:
            errors.append("input unavailable, unsafe, unsupported, changed, or outside bounds")
        finally:
            if descriptor is not None:
                os.close(descriptor)

        findings = sorted({item["id"]: item for item in findings}.values(),
                          key=lambda item: (item["path"], item["line"], item["rule_id"]))
        status, code = (("INCONCLUSIVE", 2) if errors else
                        ("REVIEW_REQUIRED", 1) if findings else ("NO_PATTERN_MATCH", 0))
        digest = _sha(_json(inventory))
        report = {
            "schema": SCHEMA,
            "target_code_executed": False, "external_systems_contacted": False,
            "model_used": False, "inspected_source_modified": False,
            "qualification": {"status": status, "complete_input": not errors,
                              "confirmed_vulnerabilities": 0, "limited_not_exhaustive": True},
            "coverage": {"supported_extensions": list(EXTENSIONS),
                         "extensionless_text": True,
                         "input_files": inventory, "input_digest": digest,
                         "selection_mode": "explicit" if files is not None else "bounded_discovery",
                         "directory_entries_seen": entries,
                         "entries_excluded_or_unsupported": ignored,
                         "limits": {"files": MAX_FILES, "file_bytes": MAX_FILE_BYTES,
                                    "total_bytes": MAX_TOTAL_BYTES, "entries": MAX_ENTRIES,
                                    "depth": MAX_DEPTH, "findings": MAX_FINDINGS},
                         "location_encoding": "sha256(root-relative UTF-8 path), plus suffix and line"},
            "limitations": [
                "Lexical patterns, not semantic understanding or a successful prompt-injection exploit.",
                "Prompt repositories can legitimately quote adversarial instructions; context needs review.",
                "Comments, fenced examples, quoted spans and unfamiliar encodings may evade detection.",
                "JSON string values are decoded, but keys and non-string values are not instruction-scanned.",
                "Escaped newlines in JSON values are attributed to the physical source string line.",
                "No authenticated origin of alleged vendor system prompts is established.",
                "No external execution, model queries, source excerpts, paths or credentials in evidence.",
                "NO_PATTERN_MATCH is not a security certification; unsupported formats are excluded.",
            ],
            "summary": {"files_inspected": len(inventory), "findings": len(findings),
                        "errors": len(errors)}, "findings": findings, "errors": errors,
        }
        rendered = _render(report)
        for name, raw in rendered.items():
            _publish(output, name, raw)
        _publish(output, MANIFEST_NAME, _json({
            "schema": MANIFEST_SCHEMA, "state": "COMPLETE",
            "qualification_status": status, "input_digest": digest,
            "files": {name: {"bytes": len(raw), "sha256": _sha(raw)}
                      for name, raw in sorted(rendered.items())},
        }))
        return PromptScanOutcome(report, code)
    finally:
        os.close(output)


def _validate_report(report: dict[str, Any]) -> None:
    if report["schema"] != SCHEMA:
        raise ValueError
    inventory, findings, errors = (report["coverage"]["input_files"],
                                    report["findings"], report["errors"])
    if (not isinstance(inventory, list) or len(inventory) > MAX_FILES
            or not isinstance(findings, list) or len(findings) > MAX_FINDINGS
            or not isinstance(errors, list) or any(type(error) is not str for error in errors)):
        raise ValueError
    status = "INCONCLUSIVE" if errors else "REVIEW_REQUIRED" if findings else "NO_PATTERN_MATCH"
    if (report["qualification"] != {"status": status, "complete_input": not errors,
                                    "confirmed_vulnerabilities": 0, "limited_not_exhaustive": True}
            or report["summary"] != {"files_inspected": len(inventory),
                                     "findings": len(findings), "errors": len(errors)}
            or any(report[key] is not False for key in ("target_code_executed",
                    "external_systems_contacted", "model_used", "inspected_source_modified"))):
        raise ValueError
    aliases: set[str] = set()
    for item in inventory:
        digest = item["source_path_sha256"]
        if (not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or item["path"] not in {"source-" + digest + extension
                                         for extension in EXTENSIONS}
                or type(item["bytes"]) is not int
                or not 0 <= item["bytes"] <= MAX_FILE_BYTES):
            raise ValueError
        aliases.add(item["path"])
    if len(aliases) != len(inventory):
        raise ValueError
    for item in findings:
        content = {key: value for key, value in item.items() if key != "id"}
        if (item["rule_id"] not in RULES or item["title"] != RULES[item["rule_id"]]
                or item["context"] != CONTEXTS[item["rule_id"]]
                or item["boundary"] != "UNTRUSTED_DOCUMENT_TEXT"
                or item["classification"] != "REVIEW_REQUIRED"
                or item["confidence"] != "CONDITIONAL_STATIC"
                or type(item["line"]) is not int or item["line"] < 1
                or item["path"] not in aliases
                or item["id"] != "WT-PROMPT-" + _sha(_json(content))[:20].upper()):
            raise ValueError


def verify_prompt_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    """Check integrity and deterministic binding; never assert source safety."""
    try:
        directory = _open_directory(Path(evidence_dir))
        try:
            manifest = json.loads(_read_file(directory, MANIFEST_NAME, 16384))
            if (manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("state") != "COMPLETE"
                    or set(manifest.get("files", {})) != {REPORT_NAME, MARKDOWN_NAME, SARIF_NAME}):
                raise ValueError
            artifacts: dict[str, bytes] = {}
            for name in (REPORT_NAME, MARKDOWN_NAME, SARIF_NAME):
                raw = _read_file(directory, name, 16 * 1024 * 1024)
                if manifest["files"][name] != {"bytes": len(raw), "sha256": _sha(raw)}:
                    raise ValueError
                artifacts[name] = raw
            report = json.loads(artifacts[REPORT_NAME])
            _validate_report(report)
            if (manifest["qualification_status"] != report["qualification"]["status"]
                    or manifest["input_digest"] != report["coverage"]["input_digest"]
                    or manifest["input_digest"] != _sha(_json(report["coverage"]["input_files"]))
                    or _render(report) != artifacts):
                raise ValueError
            return report
        finally:
            os.close(directory)
    except Exception:
        raise ValueError("prompt evidence is incomplete, unsafe or inconsistent") from None

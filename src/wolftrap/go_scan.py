"""Offline, bounded Go protected-effect source inspection and evidence replay."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .agent_scan import (
    EXCLUDED_DIRECTORIES, MAX_DEPTH, MAX_ENTRIES, MAX_FILE_BYTES, MAX_FILES,
    MAX_FINDINGS, MAX_TOTAL_BYTES, _discover, _json, _open_directory,
    _output_directory, _publish, _read_file, _selected_file, _sha,
)
from .go_rules import GoUnsupported, RULES, inspect_go_source

EXTENSIONS = (".go",)
REPORT_NAME = "go-authority-scan.json"
MARKDOWN_NAME = "go-authority-scan.md"
SARIF_NAME = "go-authority-scan.sarif"
MANIFEST_NAME = "go-authority-scan.manifest.json"
SCHEMA = "wolftrap.go-authority-scan/v1"
MANIFEST_SCHEMA = "wolftrap.go-authority-manifest/v1"
_SAFE_ERRORS = frozenset({
    "GO_SOURCE_BOUND_EXCEEDED", "GO_UNTERMINATED_BLOCK_COMMENT",
    "GO_MULTILINE_QUOTED_LITERAL", "GO_UNTERMINATED_QUOTED_LITERAL",
    "GO_NESTING_BOUND_EXCEEDED", "GO_UNBALANCED_BRACES",
    "GO_UNBALANCED_PARENTHESES", "GO_FUNCTION_BODY_UNRESOLVED",
    "GO_SIGNAL_BOUND_EXCEEDED",
    "INPUT_UNAVAILABLE_UNSAFE_UNSUPPORTED_CHANGED_OR_OUTSIDE_BOUNDS",
})


@dataclass(frozen=True)
class GoScanOutcome:
    report: dict[str, Any]
    exit_code: int


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    lines = [
        "# WolfTrap Go authority-boundary triage", "",
        "Offline lexical source review only. No confirmed vulnerability, exploit, or runtime test.",
        "", "Status: " + report["qualification"]["status"], "",
        "Locations use SHA-256 path aliases and source line numbers; source text is omitted.",
        "A permission callback is not necessarily a host-owned authorization decision.", "",
    ]
    for finding in report["findings"]:
        lines.append(
            f"- {finding['rule_id']} at {finding['path']}:{finding['line']}"
            f" — {finding['title']} ({finding['context']})"
        )
    for issue in report["errors"]:
        lines.append("- Incomplete inspection: " + issue)
    lines.extend([
        "", "Reviewers must independently establish reachability, trust, policy and actual effects.",
        "No pattern match is not a security certification. This tool does not execute Go code.", "",
    ])
    sarif = {
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "WolfTrap scan-go-authority", "rules": [
                {"id": key, "shortDescription": {"text": value}}
                for key, value in RULES.items()
            ]}},
            "invocations": [{"executionSuccessful": not report["errors"]}],
            "results": [{
                "ruleId": item["rule_id"], "level": "warning",
                "message": {"text": item["title"] + ". Conditional review required."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": item["path"]},
                    "region": {"startLine": item["line"]},
                }}],
                "partialFingerprints": {"wolftrap/v1": item["id"]},
                "properties": {"classification": "REVIEW_REQUIRED",
                               "confidence": "CONDITIONAL_STATIC",
                               "boundary": item["boundary"], "context": item["context"]},
            } for item in report["findings"]],
        }],
    }
    return {
        REPORT_NAME: _json(report),
        MARKDOWN_NAME: ("\n".join(lines) + "\n").encode("utf-8"),
        SARIF_NAME: _json(sarif),
    }


def scan_go_authority(root: str | Path, output_dir: str | Path, *,
                      files: Sequence[str] | None = None) -> GoScanOutcome:
    """Inspect only local Go source, emitting no source bytes or real path names."""
    source, destination = Path(root), Path(output_dir)
    output = _output_directory(source, destination)
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
                selections, entries, ignored = _discover(descriptor, suffixes=EXTENSIONS)
            else:
                if (isinstance(files, (str, bytes)) or not 1 <= len(files) <= MAX_FILES
                        or not all(isinstance(item, str) for item in files)):
                    raise ValueError
                selections = sorted(set(files))
            if not selections:
                raise ValueError
            for relative in selections:
                raw = _selected_file(descriptor, relative, suffixes=EXTENSIONS)
                total += len(raw)
                if total > MAX_TOTAL_BYTES:
                    raise ValueError
                path_digest = _sha(relative.encode("utf-8", errors="surrogatepass"))
                alias = "source-" + path_digest + ".go"
                inventory.append({
                    "path": alias, "source_path_sha256": path_digest,
                    "bytes": len(raw), "sha256": _sha(raw),
                })
                try:
                    text = raw.decode("utf-8", errors="strict")
                    signals = inspect_go_source(text)
                except GoUnsupported as exc:
                    if str(exc) not in _SAFE_ERRORS:
                        raise ValueError from None
                    errors.append(str(exc))
                    continue
                for signal in signals:
                    if len(findings) >= MAX_FINDINGS:
                        raise ValueError
                    item = dict(signal)
                    item.update({
                        "path": alias, "title": RULES[item["rule_id"]],
                        "classification": "REVIEW_REQUIRED",
                        "confidence": "CONDITIONAL_STATIC",
                    })
                    item["id"] = "WT-GO-" + _sha(_json(item))[:20].upper()
                    findings.append(item)
            if files is None:
                after, after_entries, after_ignored = _discover(descriptor, suffixes=EXTENSIONS)
                if (after, after_entries, after_ignored) != (selections, entries, ignored):
                    raise ValueError
            for relative, item in zip(selections, inventory):
                if _sha(_selected_file(descriptor, relative, suffixes=EXTENSIONS)) != item["sha256"]:
                    raise ValueError
            current = _open_directory(source)
            try:
                before, now = os.fstat(descriptor), os.fstat(current)
                if (before.st_dev, before.st_ino) != (now.st_dev, now.st_ino):
                    raise ValueError
            finally:
                os.close(current)
        except Exception:
            # Never include exception arguments: they can reveal source or paths.
            errors.append("INPUT_UNAVAILABLE_UNSAFE_UNSUPPORTED_CHANGED_OR_OUTSIDE_BOUNDS")
        finally:
            if descriptor is not None:
                os.close(descriptor)

        findings = sorted(
            {item["id"]: item for item in findings}.values(),
            key=lambda item: (item["path"], item["line"], item["rule_id"]),
        )
        errors = sorted(set(errors))
        status, code = (
            ("INCONCLUSIVE", 2) if errors
            else ("REVIEW_REQUIRED", 1) if findings
            else ("NO_PATTERN_MATCH", 0)
        )
        input_digest = _sha(_json(inventory))
        report = {
            "schema": SCHEMA, "target_code_executed": False,
            "external_systems_contacted": False, "model_used": False,
            "inspected_source_modified": False,
            "qualification": {"status": status, "complete_input": not errors,
                              "confirmed_vulnerabilities": 0, "limited_not_exhaustive": True},
            "coverage": {
                "supported_extensions": list(EXTENSIONS),
                "excluded_directories": list(EXCLUDED_DIRECTORIES),
                "input_files": inventory, "input_digest": input_digest,
                "directory_entries_seen": entries,
                "entries_excluded_or_unsupported": ignored,
                "selection_mode": "explicit" if files is not None else "bounded_discovery",
                "limits": {"files": MAX_FILES, "file_bytes": MAX_FILE_BYTES,
                           "total_bytes": MAX_TOTAL_BYTES, "entries": MAX_ENTRIES,
                           "depth": MAX_DEPTH},
                "location_encoding": "sha256(root-relative UTF-8 path), .go suffix and line",
            },
            "limitations": [
                "Lexical Go patterns only; no Go AST, control-flow or interprocedural data-flow proof.",
                "A tool's permissions, local callbacks and text matching do not prove host authority.",
                "Explicitly sandboxed effects elsewhere may make a signal benign.",
                "Undetected wrappers, indirect subprocess calls and network effects may be missed.",
                "No runtime/effect conformance, network connections, credentials or Go execution.",
                "No pattern match is not a security certification or an approval to execute.",
            ],
            "summary": {"files_inspected": len(inventory), "findings": len(findings),
                        "errors": len(errors)},
            "findings": findings, "errors": errors,
        }
        rendered = _render(report)
        for name, raw in rendered.items():
            _publish(output, name, raw)
        _publish(output, MANIFEST_NAME, _json({
            "schema": MANIFEST_SCHEMA, "state": "COMPLETE",
            "qualification_status": status, "input_digest": input_digest,
            "files": {name: {"bytes": len(raw), "sha256": _sha(raw)}
                      for name, raw in sorted(rendered.items())},
        }))
        return GoScanOutcome(report, code)
    finally:
        os.close(output)


def _validate_report(report: dict[str, Any]) -> None:
    if report["schema"] != SCHEMA:
        raise ValueError
    findings, errors, inventory = (
        report["findings"], report["errors"], report["coverage"]["input_files"],
    )
    if (not isinstance(findings, list) or len(findings) > MAX_FINDINGS
            or not isinstance(errors, list) or any(e not in _SAFE_ERRORS for e in errors)
            or not isinstance(inventory, list) or len(inventory) > MAX_FILES):
        raise ValueError
    status = "INCONCLUSIVE" if errors else "REVIEW_REQUIRED" if findings else "NO_PATTERN_MATCH"
    if (report["qualification"] != {"status": status, "complete_input": not errors,
                                     "confirmed_vulnerabilities": 0, "limited_not_exhaustive": True}
            or report["summary"] != {"files_inspected": len(inventory),
                                     "findings": len(findings), "errors": len(errors)}
            or any(report[k] is not False for k in (
                "target_code_executed", "external_systems_contacted", "model_used",
                "inspected_source_modified",
            ))):
        raise ValueError
    paths: set[str] = set()
    for item in inventory:
        if (not re.fullmatch(r"[0-9a-f]{64}", item["source_path_sha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or item["path"] != "source-" + item["source_path_sha256"] + ".go"
                or type(item["bytes"]) is not int or not 0 <= item["bytes"] <= MAX_FILE_BYTES):
            raise ValueError
        paths.add(item["path"])
    if len(paths) != len(inventory) or report["coverage"]["input_digest"] != _sha(_json(inventory)):
        raise ValueError
    for item in findings:
        identity = {key: value for key, value in item.items() if key != "id"}
        if (item["rule_id"] not in RULES or item["title"] != RULES[item["rule_id"]]
                or item["classification"] != "REVIEW_REQUIRED"
                or item["confidence"] != "CONDITIONAL_STATIC"
                or item["boundary"] != "GO_PROTECTED_EFFECT"
                or type(item["line"]) is not int or item["line"] < 1
                or item["path"] not in paths
                or item["id"] != "WT-GO-" + _sha(_json(identity))[:20].upper()):
            raise ValueError


def verify_go_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    """Reproduce report rendering and check all saved digest bindings."""
    try:
        directory = _open_directory(Path(evidence_dir))
        try:
            manifest = json.loads(_read_file(directory, MANIFEST_NAME, 16384))
            if (manifest.get("schema") != MANIFEST_SCHEMA
                    or manifest.get("state") != "COMPLETE"
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
                    or _render(report) != artifacts):
                raise ValueError
            return report
        finally:
            os.close(directory)
    except Exception:
        raise ValueError("go authority evidence is incomplete, unsafe or inconsistent") from None

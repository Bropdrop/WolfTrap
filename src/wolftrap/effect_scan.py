"""WolfTrap 5.2: bounded offline protected-effect and agent-instruction triage.

Reuses the descriptor-relative, no-follow file reader from Stage 5.1. The two
scanners have distinct commands and evidence schemas; Stage 5.1 is unchanged.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .agent_scan import (
    EXCLUDED_DIRECTORIES, MAX_DEPTH, MAX_ENTRIES, MAX_FILE_BYTES,
    MAX_FILES, MAX_FINDINGS, MAX_TOTAL_BYTES, _discover, _json,
    _open_directory, _output_directory, _publish, _read_file, _selected_file, _sha,
)
from .effect_rules import EXTENSIONS, RULES, inspect_effect_source

REPORT_NAME = "effect-scan.json"
MARKDOWN_NAME = "effect-scan.md"
SARIF_NAME = "effect-scan.sarif"
MANIFEST_NAME = "effect-scan.manifest.json"
SCHEMA = "wolftrap.stage5.2.effect-scan/v1"
MANIFEST_SCHEMA = "wolftrap.stage5.2.effect-manifest/v1"


@dataclass(frozen=True)
class EffectScanOutcome:
    report: dict[str, Any]
    exit_code: int


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    lines = ["# WolfTrap 5.2 protected-effect boundary triage", "",
             "Conditional, offline source-pattern review. No vulnerability or exploit confirmed.",
             "", "Status: " + report["qualification"]["status"], "",
             "SHA-256 path aliases hide original source paths; no source or credentials copied.", ""]
    for finding in report["findings"]:
        lines.append(f"- {finding['rule_id']} at {finding['path']}:{finding['line']} — "
                     f"{finding['title']} ({finding['context']})")
    for issue in report["errors"]:
        lines.append("- Incomplete inspection: " + issue)
    lines.extend(["", "Human review must establish intended scope and real execution controls.",
                  "Agent instructions cannot grant themselves protected-effect authority.", ""])

    sarif = {
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "WolfTrap scan-effects", "rules": [
                {"id": key, "shortDescription": {"text": value}}
                for key, value in RULES.items()]}},
            "invocations": [{"executionSuccessful": not report["errors"]}],
            "results": [{
                "ruleId": item["rule_id"], "level": "warning",
                "message": {"text": item["title"] + ". Conditional review required."},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": item["path"]},
                    "region": {"startLine": item["line"]}}}],
                "partialFingerprints": {"wolftrap/v1": item["id"]},
                "properties": {"classification": "REVIEW_REQUIRED",
                               "confidence": "CONDITIONAL_STATIC",
                               "boundary": item["boundary"], "context": item["context"]},
            } for item in report["findings"]],
        }],
    }
    return {REPORT_NAME: _json(report),
            MARKDOWN_NAME: ("\n".join(lines) + "\n").encode("utf-8"),
            SARIF_NAME: _json(sarif)}


def scan_effects(root: str | Path, output_dir: str | Path, *,
                 files: Sequence[str] | None = None) -> EffectScanOutcome:
    """Inspect bounded JS/TS/Python/shell and SKILL.md input without execution."""
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
                digest = _sha(relative.encode("utf-8", errors="surrogatepass"))
                alias = "source-" + digest + Path(relative).suffix.lower()
                inventory.append({"path": alias, "source_path_sha256": digest,
                                  "bytes": len(raw), "sha256": _sha(raw)})
                text = raw.decode("utf-8", errors="strict")
                for signal in inspect_effect_source(relative, text):
                    if len(findings) >= MAX_FINDINGS:
                        raise ValueError
                    finding = dict(signal)
                    finding.update(path=alias, title=RULES[finding["rule_id"]],
                                   classification="REVIEW_REQUIRED", confidence="CONDITIONAL_STATIC")
                    finding["id"] = "WT-EFFECT-" + _sha(_json(finding))[:20].upper()
                    findings.append(finding)
            if files is None:
                after, after_entries, after_ignored = _discover(descriptor, suffixes=EXTENSIONS)
                if (after, after_entries, after_ignored) != (selections, entries, ignored):
                    raise ValueError
            for relative, item in zip(selections, inventory):
                if _sha(_selected_file(descriptor, relative, suffixes=EXTENSIONS)) != item["sha256"]:
                    raise ValueError
            current_root = _open_directory(source)
            try:
                old, current = os.fstat(descriptor), os.fstat(current_root)
                if (old.st_dev, old.st_ino) != (current.st_dev, current.st_ino):
                    raise ValueError
            finally:
                os.close(current_root)
        except Exception:
            # No exception details: they can include paths, source, or secrets.
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
            "schema": SCHEMA,
            "target_code_executed": False, "external_systems_contacted": False,
            "model_used": False, "inspected_source_modified": False,
            "qualification": {"status": status, "complete_input": not errors,
                              "confirmed_vulnerabilities": 0, "limited_not_exhaustive": True},
            "coverage": {"supported_extensions": list(EXTENSIONS),
                         "markdown_scope": "SKILL.md only",
                         "excluded_directories": list(EXCLUDED_DIRECTORIES),
                         "input_files": inventory, "input_digest": digest,
                         "directory_entries_seen": entries,
                         "entries_excluded_or_unsupported": ignored,
                         "selection_mode": "explicit" if files is not None else "bounded_discovery",
                         "limits": {"files": MAX_FILES, "file_bytes": MAX_FILE_BYTES,
                                    "total_bytes": MAX_TOTAL_BYTES, "entries": MAX_ENTRIES,
                                    "depth": MAX_DEPTH},
                         "location_encoding": "sha256(root-relative UTF-8 path), plus extension and line"},
            "limitations": [
                "Lexical correlation only; not full control flow, data flow, DNS, or runtime isolation analysis.",
                "A missing network marker in one file does not prove network isolation is absent.",
                "BYOK browser storage and external uploads may be documented design choices.",
                "Agent skill instructions and user-confirmation prose do not grant execution authority.",
                "No match is not a security certification; unrecognized syntaxes may be missed.",
                "No target execution, exploit testing, source excerpts, paths, or credential values.",
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
        return EffectScanOutcome(report, code)
    finally:
        os.close(output)


def _validate_report(report: dict[str, Any]) -> None:
    if report["schema"] != SCHEMA:
        raise ValueError
    findings, errors, inventory = (report["findings"], report["errors"],
                                    report["coverage"]["input_files"])
    if (not isinstance(findings, list) or len(findings) > MAX_FINDINGS
            or not isinstance(errors, list) or any(type(issue) is not str for issue in errors)
            or not isinstance(inventory, list) or len(inventory) > MAX_FILES):
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
                or item["path"] not in {"source-" + item["source_path_sha256"] + suffix
                                         for suffix in EXTENSIONS}
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
                or item["id"] != "WT-EFFECT-" + _sha(_json(identity))[:20].upper()):
            raise ValueError


def verify_effect_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    """Validate closed evidence and its deterministic JSON/Markdown/SARIF binding."""
    try:
        directory = _open_directory(Path(evidence_dir))
        try:
            manifest = json.loads(_read_file(directory, MANIFEST_NAME, 16384))
            if (manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("state") != "COMPLETE"
                    or set(manifest.get("files", {})) != {REPORT_NAME, MARKDOWN_NAME, SARIF_NAME}):
                raise ValueError
            raw_artifacts: dict[str, bytes] = {}
            for name in (REPORT_NAME, MARKDOWN_NAME, SARIF_NAME):
                raw = _read_file(directory, name, 16 * 1024 * 1024)
                if manifest["files"][name] != {"bytes": len(raw), "sha256": _sha(raw)}:
                    raise ValueError
                raw_artifacts[name] = raw
            report = json.loads(raw_artifacts[REPORT_NAME])
            _validate_report(report)
            if (manifest["qualification_status"] != report["qualification"]["status"]
                    or manifest["input_digest"] != report["coverage"]["input_digest"]
                    or manifest["input_digest"] != _sha(_json(report["coverage"]["input_files"]))
                    or _render(report) != raw_artifacts):
                raise ValueError
            return report
        finally:
            os.close(directory)
    except Exception:
        raise ValueError("effect evidence is incomplete, unsafe or inconsistent") from None

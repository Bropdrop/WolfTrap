"""Read-only triage of *pre-sanitized* GitHub API event summaries.

This is not a network collector or a GitHub audit-log parser. The caller must
provide event categories and opaque process-session/repository/issue aliases.
Raw URLs, hostnames, identifiers, HTTP headers and payloads are rejected.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from .agent_scan import _json, _open_directory, _output_directory, _publish, _read_file, _sha
from .cloud_c2 import MAX_EVENTS, MAX_TIME, WINDOW


SCHEMA = "wolftrap.normalized-cloud-trace/v1"
REPORT_SCHEMA = "wolftrap.cloud-trace-review/v1"
MANIFEST_SCHEMA = "wolftrap.cloud-trace-manifest/v1"
REPORT_NAME = "cloud-trace-review.json"
MARKDOWN_NAME = "cloud-trace-review.md"
MANIFEST_NAME = "cloud-trace-review.manifest.json"
MAX_INPUT_BYTES = 64 * 1024
KINDS = frozenset({
    "issue_create", "bug_label_add", "bug_label_remove",
    "repo_poll", "source_map_put", "other",
})
RULES = {
    "WT-CLOUD-C2-003": "Issue-specific bug-label cycle with cross-repository polling",
    "WT-CLOUD-C2-004": "Command-repository polling followed by source-map-like results upload",
}
ALIAS = re.compile(r"[a-z][a-z0-9_-]{1,31}\Z")
FILE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}\.json\Z")
ISSUE_KINDS = frozenset({"issue_create", "bug_label_add", "bug_label_remove"})


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse_trace(raw: bytes) -> list[dict[str, Any]]:
    """Accept only bounded, anonymous event metadata; never return source text."""
    if not 1 <= len(raw) <= MAX_INPUT_BYTES or b"\x00" in raw:
        raise ValueError("trace is empty, binary or outside bounds")

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates,
                     parse_constant=reject_constant)
    if type(doc) is not dict or set(doc) != {"schema", "events"} or doc["schema"] != SCHEMA:
        raise ValueError("unsupported normalized trace schema")
    events = doc["events"]
    if type(events) is not list or not 1 <= len(events) <= MAX_EVENTS:
        raise ValueError("event count outside bounds")
    previous = -1
    for item in events:
        if type(item) is not dict or set(item) != {
                "at", "session", "repository", "issue", "kind"}:
            raise ValueError("raw or incomplete event fields are unsupported")
        at = item["at"]
        if type(at) is not int or not previous <= at <= MAX_TIME:
            raise ValueError("logical event time is invalid")
        previous = at
        if (type(item["session"]) is not str or not ALIAS.fullmatch(item["session"])
                or type(item["repository"]) is not str
                or not ALIAS.fullmatch(item["repository"])
                or type(item["kind"]) is not str or item["kind"] not in KINDS):
            raise ValueError("identifiers or operations are not sanitized")
        issue = item["issue"]
        if item["kind"] in ISSUE_KINDS:
            if type(issue) is not str or not ALIAS.fullmatch(issue):
                raise ValueError("issue-event identity is missing")
        elif issue is not None:
            raise ValueError("non-issue events must not name issues")
    return events


def _sequence(kinds: list[str], expected: tuple[str, ...]) -> bool:
    cursor = 0
    for kind in kinds:
        if kind == expected[cursor]:
            cursor += 1
            if cursor == len(expected):
                return True
    return False


def inspect_trace(events: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Correlate only within a pseudonymous process/session and issue pair."""
    findings: dict[tuple[str, str, str, str], dict[str, str]] = {}
    for session in sorted({event["session"] for event in events}):
        stream = [event for event in events if event["session"] == session]
        for index, start in enumerate(stream):
            if start["kind"] != "issue_create":
                continue
            result_repo, issue = start["repository"], start["issue"]
            following = [event for event in stream[index + 1:]
                         if event["at"] - start["at"] <= WINDOW]
            command_repos = sorted({event["repository"] for event in following
                                    if event["kind"] == "repo_poll"
                                    and event["repository"] != result_repo})
            for command_repo in command_repos:
                relevant: list[str] = []
                for event in following:
                    if (event["repository"] == result_repo
                            and event["issue"] == issue
                            and event["kind"] in ("bug_label_add", "bug_label_remove")):
                        relevant.append(event["kind"])
                    elif (event["repository"] == command_repo
                          and event["kind"] == "repo_poll"):
                        relevant.append("repo_poll")
                    elif (event["repository"] == result_repo
                          and event["kind"] == "source_map_put"):
                        relevant.append("source_map_put")
                matched: list[str] = []
                if _sequence(relevant, (
                        "bug_label_add", "repo_poll", "bug_label_remove", "repo_poll")):
                    matched.append("WT-CLOUD-C2-003")
                if _sequence(relevant, ("repo_poll", "source_map_put")):
                    matched.append("WT-CLOUD-C2-004")
                for rule_id in matched:
                    key = (session, result_repo, command_repo, rule_id)
                    findings[key] = {
                        "rule_id": rule_id,
                        "title": RULES[rule_id],
                        "session_alias": "session-" + _sha(session.encode())[:16],
                        "repository_pair_alias": "pair-" +
                            _sha((result_repo + "\x00" + command_repo).encode())[:16],
                        "classification": "REVIEW_REQUIRED",
                    }
    return [findings[key] for key in sorted(findings)]


def _review(raw: bytes | None, file: str) -> tuple[dict[str, Any], int]:
    errors: list[str] = []
    findings: list[dict[str, str]] = []
    events_seen = 0
    if raw is None:
        errors.append("input unavailable, unsafe, unsupported or outside bounds")
    else:
        try:
            events = parse_trace(raw)
            events_seen = len(events)
            findings = inspect_trace(events)
        except (ValueError, UnicodeDecodeError, TypeError):
            errors.append("input unavailable, unsafe, unsupported or outside bounds")
    status, code = (("INCONCLUSIVE", 2) if errors else
                    ("REVIEW_REQUIRED", 1) if findings else ("NO_PATTERN_MATCH", 0))
    report = {
        "schema": REPORT_SCHEMA,
        "qualification": {"status": status, "source_identity_verified": False,
                          "real_world_infection_detected": False,
                          "confirmed_vulnerabilities": 0},
        "target_code_executed": False, "network_contacted": False,
        "model_used": False, "source_modified": False,
        "input": {"file_alias": "file-" + _sha(file.encode())[:16],
                  "bytes": len(raw) if raw is not None else None,
                  "sha256": _sha(raw) if raw is not None else None,
                  "event_count": events_seen,
                  "limits": {"file_bytes": MAX_INPUT_BYTES, "events": MAX_EVENTS,
                             "logical_time": MAX_TIME, "correlation_window": WINDOW}},
        "summary": {"findings": len(findings), "errors": len(errors)},
        "findings": findings, "errors": errors,
        "limitations": [
            "Only already-sanitized event classes are accepted, not GitHub audit logs or raw HTTP traces.",
            "Session, repository, issue and event-kind provenance cannot be authenticated from a JSON file.",
            "The source must establish per-process/credential session aliases before inspection.",
            "A matched correlation is conditional; benign automation may match and malicious traffic may evade.",
            "NO_PATTERN_MATCH is not proof of safety. Incomplete input is INCONCLUSIVE.",
        ],
    }
    return report, code


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    lines = ["# WolfTrap normalized cloud-event review", "",
             "Pre-sanitized local input only. No source identity or infection confirmed.", "",
             "Status: " + report["qualification"]["status"], "",
             f"Events: {report['input']['event_count']}; findings: {report['summary']['findings']}", ""]
    for finding in report["findings"]:
        lines.append("- " + finding["rule_id"] + ": " + finding["title"] +
                     " (" + finding["session_alias"] + ")")
    for error in report["errors"]:
        lines.append("- Incomplete: " + error)
    lines.extend(["", "Limitations:", ""] +
                 ["- " + value for value in report["limitations"]] + [""])
    return {REPORT_NAME: _json(report), MARKDOWN_NAME: ("\n".join(lines)).encode()}


def _select_file(file: str) -> str:
    if type(file) is not str or FILE_NAME.fullmatch(file) is None:
        raise ValueError("input must be a simple .json filename")
    return file


def _read_input(root: Path, file: str) -> bytes:
    fd = _open_directory(root)
    try:
        return _read_file(fd, file, MAX_INPUT_BYTES)
    finally:
        os.close(fd)


def scan_cloud_trace(root: str | Path, file: str,
                     output_dir: str | Path) -> tuple[dict[str, Any], int]:
    """Inspect an authorized local sanitized trace without executing content."""
    file = _select_file(file)
    source = Path(root)
    out = _output_directory(source, Path(output_dir))
    try:
        raw: bytes | None = None
        try:
            raw = _read_input(source, file)
        except (OSError, ValueError):
            pass
        report, code = _review(raw, file)
        # Recheck the input after analysis; no source mutation is tolerated.
        try:
            if raw is not None and _read_input(source, file) != raw:
                report, code = _review(None, file)
        except (OSError, ValueError):
            report, code = _review(None, file)
        rendered = _render(report)
        for name, content in rendered.items():
            _publish(out, name, content)
        _publish(out, MANIFEST_NAME, _json({
            "schema": MANIFEST_SCHEMA, "state": "COMPLETE",
            "files": {name: {"bytes": len(content), "sha256": _sha(content)}
                      for name, content in sorted(rendered.items())},
        }))
        return report, code
    finally:
        os.close(out)


def verify_cloud_trace(root: str | Path, file: str,
                       evidence_dir: str | Path) -> dict[str, Any]:
    """Replay against the supplied original input; never trust report claims."""
    file = _select_file(file)
    raw: bytes | None = None
    try:
        raw = _read_input(Path(root), file)
    except (OSError, ValueError):
        pass
    report, _ = _review(raw, file)
    artifacts = _render(report)
    fd = _open_directory(Path(evidence_dir))
    try:
        try:
            manifest = json.loads(_read_file(fd, MANIFEST_NAME, 16384))
            if (manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("state") != "COMPLETE"
                    or set(manifest.get("files", {})) != {REPORT_NAME, MARKDOWN_NAME}):
                raise ValueError
            for name, content in artifacts.items():
                saved = _read_file(fd, name, 128 * 1024)
                if saved != content or manifest["files"][name] != {
                        "bytes": len(saved), "sha256": _sha(saved)}:
                    raise ValueError
            return report
        except Exception:
            raise ValueError("cloud-trace evidence is incomplete or inconsistent") from None
    finally:
        os.close(fd)

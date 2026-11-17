"""Offline GitHub-C2 behavioral challenge using synthetic, payload-free events.

The documented ShadowCloud/GitDoor pattern inspired this bounded experiment.
It neither implements a C2 client nor reads, executes, or contacts live targets.
Matches are conditional review signals, never attribution or proof of malware.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Sequence

from .agent_scan import _json, _open_directory, _publish, _read_file, _sha


SCHEMA = "wolftrap.synthetic-cloud-c2-challenge/v1"
MANIFEST_SCHEMA = "wolftrap.synthetic-cloud-c2-manifest/v1"
REPORT_NAME = "cloud-c2-challenge.json"
MARKDOWN_NAME = "cloud-c2-challenge.md"
MANIFEST_NAME = "cloud-c2-challenge.manifest.json"
MAX_EVENTS = 128
MAX_TIME = 10_000
WINDOW = 200  # Synthetic logical ticks; not a measured attacker polling interval.
KINDS = frozenset({
    "issue_create", "label_add", "label_remove", "repo_poll",
    "source_map_write", "other",
})
RULES = {
    "WT-CLOUD-C2-001": "Issue-label oscillation correlated with repository polling",
    "WT-CLOUD-C2-002": "Issue/poll sequence correlated with source-map-like upload",
}


def _event(at: int, actor: str, kind: str) -> dict[str, Any]:
    return {"at": at, "actor": actor, "kind": kind}


def _validate(events: Sequence[dict[str, Any]]) -> None:
    if not isinstance(events, (list, tuple)) or not 1 <= len(events) <= MAX_EVENTS:
        raise ValueError("synthetic event count is outside bounds")
    previous = -1
    for item in events:
        if type(item) is not dict or set(item) != {"at", "actor", "kind"}:
            raise ValueError("event must use the fixed synthetic schema")
        at = item["at"]
        if type(at) is not int or not previous <= at <= MAX_TIME:
            raise ValueError("synthetic logical time is invalid or unordered")
        previous = at
        if (type(item["actor"]) is not str
                or re.fullmatch(r"synthetic-host://[A-Za-z0-9_-]{1,32}", item["actor"]) is None
                or type(item["kind"]) is not str or item["kind"] not in KINDS):
            raise ValueError("real destinations, payloads, and unknown operations are prohibited")


def detect_cloud_c2(events: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Return conditional signatures from pre-normalized synthetic GitHub events.

    Inputs are not arbitrary HTTP logs. The caller must already distinguish a
    GitHub issue label update from a content write; this method does not inspect
    credentials, executable bytes, repository contents, URLs, or cloud traffic.
    """
    _validate(events)
    actors = sorted({item["actor"] for item in events})
    findings: list[dict[str, str]] = []
    for actor in actors:
        stream = [item for item in events if item["actor"] == actor]
        found: set[str] = set()
        for index, start in enumerate(stream):
            if start["kind"] != "issue_create":
                continue
            window = [item["kind"] for item in stream[index + 1:]
                      if item["at"] - start["at"] <= WINDOW]
            # Label changes must bracket separate content polls; simply
            # uploading a .js.map file or tagging an issue is not enough.
            stage = 0
            for kind in window:
                if stage == 0 and kind == "label_add":
                    stage = 1
                elif stage == 1 and kind == "repo_poll":
                    stage = 2
                elif stage == 2 and kind == "label_remove":
                    stage = 3
                elif stage == 3 and kind == "repo_poll":
                    stage = 4
                    break
            if stage == 4:
                found.add("WT-CLOUD-C2-001")
            observed_poll = False
            for kind in window:
                if kind == "repo_poll":
                    observed_poll = True
                elif kind == "source_map_write" and observed_poll:
                    found.add("WT-CLOUD-C2-002")
                    break
        for rule_id in sorted(found):
            findings.append({
                "rule_id": rule_id,
                "title": RULES[rule_id],
                "actor_alias": "synthetic-actor-" + _sha(actor.encode())[:16],
                "classification": "REVIEW_REQUIRED",
            })
    return {
        "status": "REVIEW_REQUIRED" if findings else "NO_PATTERN_MATCH",
        "event_count": len(events),
        "actor_count": len(actors),
        "findings": findings,
    }


def _cases() -> tuple[dict[str, Any], ...]:
    """Independent expected labels; no detector call creates these fixtures."""
    a, b = "synthetic-host://car-a", "synthetic-host://car-b"
    cases = (
        ("gitdoor-inspired-complete", ("WT-CLOUD-C2-001", "WT-CLOUD-C2-002"), (
            _event(1, a, "issue_create"), _event(2, a, "label_add"),
            _event(3, a, "repo_poll"), _event(4, a, "label_remove"),
            _event(5, a, "repo_poll"), _event(6, a, "source_map_write"))),
        ("label-poll-no-upload", ("WT-CLOUD-C2-001",), (
            _event(1, a, "issue_create"), _event(2, a, "label_add"),
            _event(3, a, "repo_poll"), _event(4, a, "label_remove"),
            _event(5, a, "repo_poll"))),
        ("upload-poll-correlation", ("WT-CLOUD-C2-002",), (
            _event(1, a, "issue_create"), _event(2, a, "repo_poll"),
            _event(3, a, "source_map_write"))),
        ("normal-issue-triage", (), (
            _event(1, a, "issue_create"), _event(2, a, "label_add"),
            _event(3, a, "repo_poll"))),
        ("ordinary-sourcemap-build", (), (
            _event(1, a, "source_map_write"), _event(2, a, "other"))),
        ("upload-before-poll", (), (
            _event(1, a, "issue_create"), _event(2, a, "source_map_write"),
            _event(3, a, "repo_poll"))),
        ("cross-actor-splicing", (), (
            _event(1, a, "issue_create"), _event(2, b, "label_add"),
            _event(3, b, "repo_poll"), _event(4, b, "label_remove"),
            _event(5, b, "repo_poll"), _event(6, b, "source_map_write"))),
        ("outside-correlation-window", (), (
            _event(1, a, "issue_create"), _event(202, a, "label_add"),
            _event(203, a, "repo_poll"), _event(204, a, "label_remove"),
            _event(205, a, "repo_poll"), _event(206, a, "source_map_write"))),
    )
    return tuple({"case_id": name, "expected_rule_ids": list(labels),
                  "events": list(trace)} for name, labels, trace in cases)


def evaluate_challenge() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for case in _cases():
        detection = detect_cloud_c2(case["events"])
        observed = sorted({item["rule_id"] for item in detection["findings"]})
        expected = sorted(case["expected_rule_ids"])
        results.append({"case_id": case["case_id"], "expected_rule_ids": expected,
                        "observed_rule_ids": observed, "matched": expected == observed,
                        "event_count": detection["event_count"],
                        "input_sha256": _sha(_json(case["events"]))})
    mismatches = sum(not item["matched"] for item in results)
    return {
        "schema": SCHEMA,
        "qualification": {"status": "PASSED_BOUNDED" if not mismatches else "DETECTION_GAP",
                          "real_world_infection_detected": False,
                          "real_world_exploit_confirmed": False},
        "limitations": [
            "All traces are author-created synthetic GitHub API event summaries.",
            "Only two conditional correlations are tested, not all malware C2 protocols.",
            "Event categories require trusted upstream normalization and do not establish attribution.",
            "Benign automation could match; malicious variations may evade these exact patterns.",
            "No repository, network endpoint, executable, or external system is accessed.",
        ],
        "summary": {"cases": len(results), "mismatches": mismatches,
                    "positive_controls": sum(bool(case["expected_rule_ids"]) for case in _cases()),
                    "negative_controls": sum(not case["expected_rule_ids"] for case in _cases())},
        "cases": results,
    }


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    summary = report["summary"]
    lines = ["# WolfTrap synthetic cloud-C2 challenge", "",
             "GitDoor-inspired local behavioral controls; no live malware testing.", "",
             "Status: " + report["qualification"]["status"], "",
             f"Cases: {summary['cases']}; mismatches: {summary['mismatches']}", "",
             "| Case | Expected | Observed | Match |", "| --- | --- | --- | --- |"]
    for case in report["cases"]:
        lines.append("| " + " | ".join((case["case_id"],
            ", ".join(case["expected_rule_ids"]) or "none",
            ", ".join(case["observed_rule_ids"]) or "none",
            "yes" if case["matched"] else "no")) + " |")
    lines.extend(["", "Limitations:", ""] +
                 ["- " + value for value in report["limitations"]] + [""])
    return {REPORT_NAME: _json(report), MARKDOWN_NAME: ("\n".join(lines)).encode()}


def run_cloud_c2_challenge(output_dir: str | Path) -> tuple[dict[str, Any], int]:
    """Save fixed evidence to a fresh directory, with a SHA-256 manifest."""
    fd = _open_directory(Path(output_dir), create=True)
    try:
        if os.listdir(fd):
            raise ValueError("cloud challenge evidence directory must be fresh or empty")
        report = evaluate_challenge()
        artifacts = _render(report)
        for name, content in artifacts.items():
            _publish(fd, name, content)
        _publish(fd, MANIFEST_NAME, _json({
            "schema": MANIFEST_SCHEMA, "state": "COMPLETE",
            "files": {name: {"bytes": len(raw), "sha256": _sha(raw)}
                      for name, raw in sorted(artifacts.items())},
        }))
        return report, 0 if report["summary"]["mismatches"] == 0 else 1
    finally:
        os.close(fd)


def verify_cloud_c2_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    """Independently regenerate the finite corpus and verify saved evidence."""
    fd = _open_directory(Path(evidence_dir))
    try:
        try:
            manifest = json.loads(_read_file(fd, MANIFEST_NAME, 16384))
            if (manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("state") != "COMPLETE"
                    or set(manifest.get("files", {})) != {REPORT_NAME, MARKDOWN_NAME}):
                raise ValueError
            expected = evaluate_challenge()
            artifacts = _render(expected)
            for name, value in artifacts.items():
                actual = _read_file(fd, name, 128 * 1024)
                if actual != value or manifest["files"][name] != {
                        "bytes": len(actual), "sha256": _sha(actual)}:
                    raise ValueError
            return expected
        except Exception:
            raise ValueError("cloud challenge evidence is inconsistent or incomplete") from None
    finally:
        os.close(fd)

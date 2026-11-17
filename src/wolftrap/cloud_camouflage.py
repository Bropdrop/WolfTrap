"""Deterministic, offline cloud-C2 lookalike and evasion research controls.

This is *only* event metadata. The synthetic intents are authored labels, not
assertions that any real GitHub automation or malicious implant was observed.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .agent_scan import _json, _open_directory, _publish, _read_file, _sha
from .cloud_trace import SCHEMA as TRACE_SCHEMA, inspect_trace, parse_trace


SCHEMA = "wolftrap.cloud-c2-camouflage-challenge/v1"
MANIFEST_SCHEMA = "wolftrap.cloud-c2-camouflage-manifest/v1"
REPORT_NAME = "cloud-c2-camouflage.json"
MARKDOWN_NAME = "cloud-c2-camouflage.md"
MANIFEST_NAME = "cloud-c2-camouflage.manifest.json"

LABEL = "WT-CLOUD-C2-003"
UPLOAD = "WT-CLOUD-C2-004"
GROUPS = (
    "pattern_positive", "benign_negative", "benign_lookalike", "evasion_variant",
)


def _step(at: int, kind: str, *, repository: str = "result",
          issue: str | None = None, session: str = "primary") -> tuple[Any, ...]:
    return at, session, repository, issue, kind


def _templates() -> tuple[tuple[Any, ...], ...]:
    """Authored controls, including *known* ambiguity and blind-spot cases.

    The expected rule IDs never come from the detector under test.
    """
    return (
        ("signature-complete", "pattern_positive", (LABEL, UPLOAD), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue"),
            _step(3, "repo_poll", repository="command"),
            _step(4, "bug_label_remove", issue="issue"),
            _step(5, "repo_poll", repository="command"),
            _step(6, "source_map_put"))),
        ("signature-label-only", "pattern_positive", (LABEL,), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue"),
            _step(3, "repo_poll", repository="command"),
            _step(4, "bug_label_remove", issue="issue"),
            _step(5, "repo_poll", repository="command"))),
        ("signature-upload-only", "pattern_positive", (UPLOAD,), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "repo_poll", repository="command"),
            _step(3, "source_map_put"))),
        ("signature-with-background", "pattern_positive", (LABEL, UPLOAD), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "other", repository="decoy", session="secondary"),
            _step(3, "bug_label_add", issue="issue"),
            _step(4, "repo_poll", repository="command"),
            _step(5, "other"),
            _step(6, "bug_label_remove", issue="issue"),
            _step(7, "repo_poll", repository="command"),
            _step(8, "source_map_put"))),
        ("signature-with-decoy-poll", "pattern_positive", (LABEL, UPLOAD), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue"),
            _step(3, "repo_poll", repository="command"),
            _step(4, "repo_poll", repository="decoy"),
            _step(5, "bug_label_remove", issue="issue"),
            _step(6, "repo_poll", repository="command"),
            _step(7, "source_map_put"))),

        ("benign-triage", "benign_negative", (), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue"),
            _step(3, "bug_label_remove", issue="issue"))),
        ("benign-build", "benign_negative", (), (
            _step(1, "other"),
            _step(2, "source_map_put"),
            _step(3, "repo_poll", repository="command"))),
        ("benign-poll-before-issue", "benign_negative", (), (
            _step(1, "repo_poll", repository="command"),
            _step(2, "issue_create", issue="issue"),
            _step(3, "source_map_put"))),
        ("benign-partial-label", "benign_negative", (), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue"),
            _step(3, "repo_poll", repository="command"),
            _step(4, "other"))),
        ("benign-separate-service", "benign_negative", (), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "repo_poll", repository="command", session="secondary"),
            _step(3, "source_map_put"))),

        # Benign *by construction* but indistinguishable from the event pattern.
        # These are admitted false-alarm exposures, not a measured FP rate.
        ("lookalike-triage-bot", "benign_lookalike", (LABEL,), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue"),
            _step(3, "repo_poll", repository="command"),
            _step(4, "bug_label_remove", issue="issue"),
            _step(5, "repo_poll", repository="command"))),
        ("lookalike-ci-source-map", "benign_lookalike", (UPLOAD,), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "repo_poll", repository="command"),
            _step(3, "source_map_put"))),
        ("lookalike-cross-repo-bot", "benign_lookalike", (LABEL, UPLOAD), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue"),
            _step(3, "repo_poll", repository="command"),
            _step(4, "bug_label_remove", issue="issue"),
            _step(5, "repo_poll", repository="command"),
            _step(6, "source_map_put"))),
        ("lookalike-maintenance-bot", "benign_lookalike", (LABEL,), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "other", repository="decoy"),
            _step(3, "bug_label_add", issue="issue"),
            _step(4, "repo_poll", repository="command"),
            _step(5, "other"),
            _step(6, "bug_label_remove", issue="issue"),
            _step(7, "repo_poll", repository="command"))),
        ("lookalike-multiple-issues", "benign_lookalike", (LABEL, UPLOAD), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue"),
            _step(3, "bug_label_add", issue="other_issue"),
            _step(4, "repo_poll", repository="command"),
            _step(5, "bug_label_remove", issue="issue"),
            _step(6, "repo_poll", repository="command"),
            _step(7, "source_map_put"))),

        # Threat-*inspired* metadata mutations. They carry no commands or C2.
        ("evasion-rotating-command-repo", "evasion_variant", (), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue"),
            _step(3, "repo_poll", repository="command"),
            _step(4, "bug_label_remove", issue="issue"),
            _step(5, "repo_poll", repository="decoy"))),
        ("evasion-issue-mismatch", "evasion_variant", (), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue"),
            _step(3, "repo_poll", repository="command"),
            _step(4, "bug_label_remove", issue="other_issue"),
            _step(5, "repo_poll", repository="command"))),
        ("evasion-session-split", "evasion_variant", (), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "bug_label_add", issue="issue", session="secondary"),
            _step(3, "repo_poll", repository="command", session="secondary"),
            _step(4, "bug_label_remove", issue="issue", session="secondary"),
            _step(5, "repo_poll", repository="command", session="secondary"))),
        ("evasion-unclassified-upload", "evasion_variant", (), (
            _step(1, "issue_create", issue="issue"),
            _step(2, "repo_poll", repository="command"),
            _step(3, "other"))),
        ("evasion-outside-window", "evasion_variant", (), (
            _step(1, "issue_create", issue="issue"),
            _step(202, "bug_label_add", issue="issue"),
            _step(203, "repo_poll", repository="command"),
            _step(204, "bug_label_remove", issue="issue"),
            _step(205, "repo_poll", repository="command"))),
    )


def _cases() -> tuple[dict[str, Any], ...]:
    cases = []
    for variant in range(8):
        multiplier, offset = 1 + variant % 3, 20 * variant
        repo_map = {"result": f"results-{variant}",
                    "command": f"commands-{variant}", "decoy": f"decoys-{variant}"}
        issue_map = {"issue": f"issue-{variant}",
                     "other_issue": f"alternate-{variant}"}
        session_map = {"primary": f"session-{variant}",
                       "secondary": f"other-session-{variant}"}
        for title, group, expected, template in _templates():
            events = [{"at": at * multiplier + offset,
                       "session": session_map[session],
                       "repository": repo_map[repository],
                       "issue": issue_map[issue] if issue is not None else None,
                       "kind": kind}
                      for at, session, repository, issue, kind in template]
            # The strict parser is part of the challenge contract; no raw data.
            parse_trace(_json({"schema": TRACE_SCHEMA, "events": events}))
            cases.append({"case_id": f"{title}-v{variant}", "group": group,
                          "expected_rule_ids": list(expected), "events": events})
    return tuple(cases)


def evaluate_camouflage_challenge() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    summary: dict[str, int] = {group: 0 for group in GROUPS}
    benign_flags = evasions_missed = mismatches = 0
    for case in _cases():
        observed = sorted({finding["rule_id"] for finding in inspect_trace(case["events"])})
        expected = sorted(case["expected_rule_ids"])
        matched = observed == expected
        mismatches += not matched
        summary[case["group"]] += 1
        if case["group"] == "benign_lookalike" and observed:
            benign_flags += 1
        if case["group"] == "evasion_variant" and not observed:
            evasions_missed += 1
        results.append({"case_id": case["case_id"], "group": case["group"],
                        "expected_rule_ids": expected, "observed_rule_ids": observed,
                        "matched": matched, "event_count": len(case["events"]),
                        "input_sha256": _sha(_json(case["events"]))})
    return {
        "schema": SCHEMA,
        "qualification": {
            "status": "PASSED_BOUNDED" if mismatches == 0 else "DETECTION_GAP",
            "real_world_infection_detected": False,
            "production_error_rates_measured": False,
        },
        "network_contacted": False, "target_code_executed": False,
        "source_modified": False, "model_used": False,
        "summary": {"cases": len(results), "mismatches": mismatches,
                    **summary, "benign_lookalikes_flagged": benign_flags,
                    "evasion_variants_unflagged": evasions_missed},
        "limitations": [
            "All labels, benign intent and threat-inspired variations are author-created.",
            "Benign lookalikes deliberately match narrow signals; false-alarm exposure is not a production false-positive rate.",
            "Threat-inspired variants deliberately evade narrow rules; this is a known blind spot, not confirmed malware.",
            "A passing challenge confirms authored expectations, not protection against real cloud-C2 campaigns.",
            "No live GitHub content, credentials, malware, external endpoints or cloud logs are processed.",
        ],
        "cases": results,
    }


def _render(report: dict[str, Any]) -> dict[str, bytes]:
    stats = report["summary"]
    lines = ["# WolfTrap cloud-C2 camouflage challenge", "",
             "Offline authored metadata only; no real infection or attribution.", "",
             "Status: " + report["qualification"]["status"], "",
             f"Cases: {stats['cases']}; expectation mismatches: {stats['mismatches']}",
             f"Benign lookalikes flagged: {stats['benign_lookalikes_flagged']}",
             f"Threat-inspired evasion variants unflagged: {stats['evasion_variants_unflagged']}",
             "", "| Case | Synthetic group | Expected | Observed | Match |",
             "| --- | --- | --- | --- | --- |"]
    for case in report["cases"]:
        lines.append("| " + " | ".join((case["case_id"], case["group"],
                     ", ".join(case["expected_rule_ids"]) or "none",
                     ", ".join(case["observed_rule_ids"]) or "none",
                     "yes" if case["matched"] else "no")) + " |")
    lines.extend(["", "Limitations:", ""] +
                 ["- " + item for item in report["limitations"]] + [""])
    return {REPORT_NAME: _json(report), MARKDOWN_NAME: ("\n".join(lines)).encode()}


def run_camouflage_challenge(output_dir: str | Path) -> tuple[dict[str, Any], int]:
    """Generate verifiable evidence in an empty, local output directory."""
    fd = _open_directory(Path(output_dir), create=True)
    try:
        if os.listdir(fd):
            raise ValueError("camouflage challenge evidence directory must be fresh or empty")
        report = evaluate_camouflage_challenge()
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


def verify_camouflage_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    """Regenerate the fixed corpus and reject modified or incomplete artifacts."""
    fd = _open_directory(Path(evidence_dir))
    try:
        try:
            manifest = json.loads(_read_file(fd, MANIFEST_NAME, 16384))
            if (manifest.get("schema") != MANIFEST_SCHEMA or manifest.get("state") != "COMPLETE"
                    or set(manifest.get("files", {})) != {REPORT_NAME, MARKDOWN_NAME}):
                raise ValueError
            report = evaluate_camouflage_challenge()
            for name, expected in _render(report).items():
                actual = _read_file(fd, name, 128 * 1024)
                if actual != expected or manifest["files"][name] != {
                        "bytes": len(actual), "sha256": _sha(actual)}:
                    raise ValueError
            return report
        except Exception:
            raise ValueError("camouflage challenge evidence is incomplete or inconsistent") from None
    finally:
        os.close(fd)

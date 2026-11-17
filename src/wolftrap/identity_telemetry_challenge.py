"""Run and verify the authored WolfTrap identity telemetry controls offline."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import sys
from pathlib import Path
from typing import Any

from .agent_scan import _json, _open_directory, _output_directory, _publish, _read_file, _sha
from .identity_telemetry import INCOMPLETE_REASONS, LIMITS, RULES, SCHEMA, inspect_identity_trace
from .revision import _git, repository_root


CORPUS_NAME = "identity-telemetry-controls.v1.json"
CORPUS_SCHEMA = "wolftrap.identity-telemetry-controls/v1"
REPORT_SCHEMA = "wolftrap.identity-telemetry-challenge/v1"
MANIFEST_SCHEMA = "wolftrap.identity-telemetry-manifest/v1"
REPORT_NAME = "identity-telemetry-challenge.json"
MARKDOWN_NAME = "identity-telemetry-challenge.md"
MANIFEST_NAME = "identity-telemetry-challenge.manifest.json"
LOCK_NAME = ".identity-telemetry-publication"
CORPUS_BYTES = 64 * 1024
ARTIFACT_BYTES = 256 * 1024
GROUPS = ("pattern_positive", "routine_negative", "correlation_negative",
          "benign_lookalike", "known_miss", "incomplete")
LIMITATIONS = (
    "Fictional inputs and authored expectations only. No live identity records were tested.",
    "Source, relationship, change-window and baseline labels are independent fixture inputs. "
    "The detector cannot authenticate those labels or establish a genuine approval.",
    "Expected tenant relationships and approved windows suppress only their own review signals. "
    "Unrecorded maintenance or legitimate scaling can still produce findings.",
    "The rules miss events without observable category changes, sequences outside the fixed "
    "window and causal order lost to time ties. A valid credential can look ordinary.",
    "These controls do not estimate production false-positive or false-negative rates. "
    "A conditional finding creates no authority and takes no enforcement action.",
)


def _source_revision() -> dict[str, Any]:
    """Read tracked WolfTrap checkout identity without opening untracked files."""
    root = repository_root().resolve()
    unavailable = {"commit_sha": None, "tree_sha": None, "tracked_dirty": None}
    try:
        if not (root / ".git").exists():
            return unavailable
        refs = _git(root, "rev-parse", "HEAD", "HEAD^{tree}").decode("ascii").splitlines()
        if len(refs) != 2 or not all(re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", item)
                                     for item in refs):
            return unavailable
        dirty = bool(_git(root, "-c", "core.fsmonitor=false", "status", "--porcelain=v1",
                          "--untracked-files=no"))
        evidence_sources = (
            "src/wolftrap/identity_telemetry.py",
            "src/wolftrap/identity_telemetry_challenge.py",
            "src/wolftrap/schemas/identity-telemetry-v1.schema.json",
            f"src/wolftrap/data/{CORPUS_NAME}",
        )
        tracked = _git(root, "ls-files", "--", *evidence_sources).decode("ascii").splitlines()
        dirty = dirty or set(tracked) != set(evidence_sources)
    except (OSError, RuntimeError, UnicodeError):
        return unavailable
    return {"commit_sha": refs[0], "tree_sha": refs[1], "tracked_dirty": dirty}


def _corpus_bytes() -> bytes:
    directory = _open_directory(Path(__file__).parent / "data")
    try:
        return _read_file(directory, CORPUS_NAME, CORPUS_BYTES)
    finally:
        os.close(directory)


def _validate_expectation(expected: Any) -> None:
    """Keep the report projection limited to rule IDs, row indices and enums."""
    error = "unsupported identity control expectation"
    if type(expected) is not dict or set(expected) != {"status", "findings", "inconclusive"}:
        raise ValueError(error)
    findings = expected["findings"]
    incomplete = expected["inconclusive"]
    if type(findings) is not list or type(incomplete) is not list:
        raise ValueError(error)
    status = "INCONCLUSIVE" if incomplete else ("REVIEW_REQUIRED" if findings else "NO_PATTERN_MATCH")
    if expected["status"] != status:
        raise ValueError(error)
    for finding in findings:
        if (type(finding) is not dict or set(finding) != {"rule_id", "event_indices"}
                or type(finding["rule_id"]) is not str or finding["rule_id"] not in RULES):
            raise ValueError(error)
        rows = finding["event_indices"]
        if (type(rows) is not list or not 1 <= len(rows) <= 3
                or any(type(row) is not int or not 0 <= row < LIMITS["events"] for row in rows)):
            raise ValueError(error)
    for issue in incomplete:
        if (type(issue) is not dict or set(issue) != {"event_index", "reason"}
                or type(issue["reason"]) is not str or issue["reason"] not in INCOMPLETE_REASONS):
            raise ValueError(error)
        row = issue["event_index"]
        if issue["reason"] == "UNSUPPORTED_INPUT":
            if row is not None:
                raise ValueError(error)
        elif type(row) is not int or not 0 <= row < LIMITS["events"]:
            raise ValueError(error)


def evaluate_identity_challenge() -> dict[str, Any]:
    """Compare exact rule and row references to a separately authored corpus."""
    before = _source_revision()
    raw = _corpus_bytes()
    document = json.loads(raw)
    cases = document["cases"]
    if document["schema"] != CORPUS_SCHEMA or not 1 <= len(cases) <= 64:
        raise ValueError("unsupported identity control corpus")

    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    groups = dict.fromkeys(GROUPS, 0)
    for case in cases:
        case_id = case["id"]
        group = case["group"]
        if (re.fullmatch(r"[a-z][a-z0-9-]{0,63}", case_id) is None
                or case_id in seen or group not in groups):
            raise ValueError("unsupported identity control metadata")
        seen.add(case_id)
        groups[group] += 1
        input_bytes = _json(case["input"])
        observed = inspect_identity_trace(input_bytes)
        expected = case["expected"]
        _validate_expectation(expected)
        results.append({
            "case_id": case_id, "group": group,
            "input_sha256": _sha(input_bytes), "input_bytes": len(input_bytes),
            "expected": expected, "observed": observed, "matches": observed == expected,
        })

    source_stable = before == _source_revision() and raw == _corpus_bytes()
    mismatches = sum(not case["matches"] for case in results)
    positive_rule_ids = {
        finding["rule_id"] for case in results if case["group"] == "pattern_positive"
        for finding in case["expected"]["findings"]
    }
    coverage_complete = positive_rule_ids == set(RULES) and all(groups.values())
    passed = (coverage_complete and not mismatches and source_stable
              and before["tracked_dirty"] is False)
    return {
        "schema": REPORT_SCHEMA,
        "input_schema": SCHEMA,
        "source_revision": before,
        "source_stable": source_stable,
        "environment": {
            "system": platform.system(), "machine": platform.machine(),
            "python": platform.python_version(), "implementation": platform.python_implementation(),
            "network_contacted": False, "models_used": False,
        },
        "limits": LIMITS,
        "corpus": {"schema": CORPUS_SCHEMA, "sha256": _sha(raw), "bytes": len(raw)},
        "qualification": {
            "status": "SYNTHETICALLY VERIFIED" if passed else "INCONCLUSIVE",
            "live_qualification": "NOT TESTED",
            "positive_rule_coverage": sorted(positive_rule_ids),
            "control_groups_complete": coverage_complete,
        },
        "summary": {"cases": len(results), "mismatches": mismatches, "groups": groups},
        "rules": RULES,
        "limitations": list(LIMITATIONS),
        "cases": results,
    }


def _artifacts(report: dict[str, Any]) -> dict[str, bytes]:
    summary = report["summary"]
    revision = report["source_revision"]
    environment = report["environment"]
    lines = [
        "# WolfTrap synthetic identity telemetry challenge", "",
        f"**{report['qualification']['status']}**. Live qualification **NOT TESTED**.", "",
        f"Source commit {revision['commit_sha']} and tree {revision['tree_sha']}.",
        f"Environment {environment['implementation']} {environment['python']} on "
        f"{environment['system']} {environment['machine']}.",
        f"Input schema {report['input_schema']}.",
        f"{summary['cases']} authored cases and {summary['mismatches']} expectation mismatches.", "",
        "## Control groups", "",
        *[f"- {name.replace('_', ' ').capitalize()} — {count}"
          for name, count in summary["groups"].items()],
        "", "## Limits", "",
        *[f"- {item}" for item in report["limitations"]], "",
        "The JSON report records exact expected and observed rule IDs and zero-based row references, "
        "the input and corpus hashes, and each configured bound.", "",
    ]
    files = {REPORT_NAME: _json(report), MARKDOWN_NAME: "\n".join(lines).encode()}
    files[MANIFEST_NAME] = _json({
        "schema": MANIFEST_SCHEMA, "state": "COMPLETE",
        "files": {name: {"bytes": len(data), "sha256": _sha(data)}
                  for name, data in sorted(files.items())},
    })
    return files


def run_identity_challenge(output_dir: str | Path) -> dict[str, Any]:
    report = evaluate_identity_challenge()
    fd = _output_directory(repository_root(), Path(output_dir))
    try:
        lock = os.open(LOCK_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=fd)
        try:
            if set(os.listdir(fd)) != {LOCK_NAME}:
                raise ValueError("identity evidence directory must be fresh or empty")
            for name, raw in _artifacts(report).items():
                _publish(fd, name, raw)
        finally:
            os.close(lock)
            os.unlink(LOCK_NAME, dir_fd=fd)
        return report
    finally:
        os.close(fd)


def verify_identity_challenge(evidence_dir: str | Path) -> dict[str, Any]:
    """Recompute the whole bundle from the pinned checkout and authored inputs."""
    report = evaluate_identity_challenge()
    expected = _artifacts(report)
    fd = _open_directory(Path(evidence_dir))
    try:
        if (set(os.listdir(fd)) != set(expected)
                or any(_read_file(fd, name, ARTIFACT_BYTES) != raw
                       for name, raw in expected.items())):
            raise ValueError("identity evidence is incomplete, modified or from another environment")
        return report
    finally:
        os.close(fd)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("run").add_argument("--output-dir", required=True)
    subcommands.add_parser("verify").add_argument("--evidence-dir", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "run":
            report = run_identity_challenge(args.output_dir)
        else:
            report = verify_identity_challenge(args.evidence_dir)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, RecursionError):
        print("INCONCLUSIVE: identity challenge input or evidence is unavailable or inconsistent.",
              file=sys.stderr)
        return 2
    summary = report["summary"]
    status = report["qualification"]["status"]
    print(f"{status}: {summary['cases']} authored controls; "
          f"{summary['mismatches']} expectation mismatch(es). Live qualification NOT TESTED.")
    if status == "SYNTHETICALLY VERIFIED":
        return 0
    return 1 if summary["mismatches"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

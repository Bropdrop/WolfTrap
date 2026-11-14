"""Atomic JSON and Markdown research report rendering."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping


REPORT_JSON_NAME = "wolftrap-report.json"
REPORT_MARKDOWN_NAME = "wolftrap-report.md"
REPORT_MANIFEST_NAME = "wolftrap-report.manifest.json"


class ReportIntegrityError(ValueError):
    """Raised when a report pair has no valid completion manifest."""


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise


def write_json_report(report: Mapping[str, Any], path: str | Path) -> Path:
    destination = Path(path)
    payload = json.dumps(
        report,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    ) + "\n"
    _atomic_write(destination, payload)
    return destination


def _md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown_report(report: Mapping[str, Any]) -> str:
    summary = report["summary"]
    revision = report["source_revision"]
    qualification = report["qualification"]
    coverage = report["coverage"]
    unit_tests = report.get("unit_tests", {})
    findings = report.get("findings", [])
    lines = [
        "# WolfTrap v0.1 Security Qualification Report",
        "",
        "> **Synthetic defensive research only.** This report does not establish a",
        "> real-world exploitable vulnerability or live validation of any external system.",
        "",
        f"Run ID: `{_md(report['run_id'])}`  ",
        f"Generated: `{_md(report['generated_at'])}`  ",
        f"Qualification: **{_md(qualification['status'])}**  ",
        f"System under test: `{_md(report['configuration']['system_id'])}`",
        "",
        "## Source identity",
        "",
        f"- Commit SHA: `{_md(revision['commit_sha'])}`",
        f"- Tree SHA: `{_md(revision['tree_sha'])}`",
        f"- Dirty worktree: `{_md(revision['dirty'])}`",
        f"- Diff digest: `{_md(revision['diff_digest'])}`",
        "",
        "## Results",
        "",
        "| Measure | Count |",
        "|---|---:|",
        f"| Cases generated | {summary['cases_generated']} |",
        f"| Cases attempted | {summary.get('cases_attempted', summary['cases_executed'])} |",
        f"| Cases executed | {summary['cases_executed']} |",
        f"| Cases passed | {summary['cases_passed']} |",
        f"| Cases failed | {summary['cases_failed']} |",
        f"| Cases skipped | {summary['cases_skipped']} |",
        f"| Internal errors | {summary['internal_errors']} |",
        f"| Findings | {summary['findings']} |",
        f"| Positive controls passed | {qualification['positive_controls_passed']} / {qualification['positive_controls_total']} |",
        f"| Negative controls passed | {qualification.get('negative_controls_passed', 0)} / {qualification.get('negative_controls_total', 0)} |",
        f"| Mixed threat controls passed | {qualification.get('mixed_threat_controls_passed', 0)} / {qualification.get('mixed_threat_controls_total', 0)} |",
        f"| All threat baselines passed | {qualification.get('threat_baselines_passed', 0)} / {qualification.get('threat_baselines_total', 0)} |",
        f"| Unit tests run | {_md(unit_tests.get('tests_run', 'not supplied'))} |",
        f"| Unit-test skips | {_md(unit_tests.get('skipped', 'not supplied'))} |",
        f"| Unit-test failures | {_md(unit_tests.get('failures', 'not supplied'))} |",
        f"| Unit-test errors | {_md(unit_tests.get('errors', 'not supplied'))} |",
        "",
        "## Bounded behavioral coverage",
        "",
        f"- Scenarios exercised: {len(coverage.get('scenario_ids', []))}",
        f"- ATT&CK techniques exercised: {len(coverage.get('attack_techniques', []))}",
        f"- Mutation axes exercised: {len(coverage.get('mutation_axes', []))}",
        f"- Interaction depths: `{_md(coverage.get('interaction_depths', {}))}`",
        f"- Commands evaluated: {coverage.get('commands_evaluated', 0)}",
        f"- Effects independently audited: {coverage.get('effects_audited', 0)}",
        f"- Schedule exploration truncated: `{_md(coverage.get('truncated', False))}`",
        "",
        "This is finite, bounded behavioral coverage; it is not an exhaustive claim.",
        "",
        f"Qualification coverage gates: `{_md(qualification.get('coverage_gates', {}))}`",
        "",
        "## Findings",
        "",
    ]
    if not findings:
        lines.append("No independently verified invariant violations were observed.")
    for finding in findings:
        lines.extend(
            [
                f"### {_md(finding['finding_id'])}",
                "",
                f"- Classification: **{_md(finding['classification'])}**",
                f"- Severity / confidence: `{_md(finding['severity'])}` / `{_md(finding['confidence'])}`",
                f"- Invariant: `{_md(finding['invariant'])}`",
                f"- Scenario(s): `{_md(', '.join(finding['scenario']['ids']))}`",
                f"- Expected: {_md(finding['expected_behavior']['summary'])}",
                f"- Observed: {_md(finding['observed_behavior']['summary'])}",
                f"- Reproduce: `{_md(finding['reproduction']['command'])}`",
                "",
            ]
        )
    lines.extend(
        [
            "## Model-hypothesis channel",
            "",
            f"Available: `{_md(report['model_hypotheses']['available'])}`; "
            f"used: `{_md(report['model_hypotheses']['used'])}`. "
            f"{_md(report['model_hypotheses']['reason'])}",
            "",
            "## Lifecycle claims",
            "",
            "| State | Value |",
            "|---|---|",
        ]
    )
    for name, value in report["lifecycle"].items():
        lines.append(f"| {_md(name)} | {_md(value)} |")
    lines.extend(
        [
            "",
            "Owner authority remains with Stackbleed — Governable Intelligence. No push,",
            "merge, deployment, external targeting, or live API experimentation is represented",
            "by this report.",
            "",
        ]
    )
    return "\n".join(lines)


def write_markdown_report(report: Mapping[str, Any], path: str | Path) -> Path:
    destination = Path(path)
    _atomic_write(destination, render_markdown_report(report))
    return destination


def write_report_pair(
    report: Mapping[str, Any], output_directory: str | Path
) -> tuple[Path, Path]:
    root = Path(output_directory)
    json_path = root / REPORT_JSON_NAME
    markdown_path = root / REPORT_MARKDOWN_NAME
    manifest_path = root / REPORT_MANIFEST_NAME
    # Render both forms before changing any existing evidence. The manifest is
    # deliberately invalidated first and completed last, so an interruption at
    # either report write leaves a pair that readers must reject.
    markdown_payload = render_markdown_report(report)
    json_payload = json.dumps(
        report,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        indent=2,
    ) + "\n"
    incomplete_manifest = {
        "manifest_schema_version": "1.0",
        "state": "INCOMPLETE",
        "run_id": report.get("run_id"),
        "reason": "report pair publication in progress",
    }
    _atomic_write(
        manifest_path,
        json.dumps(incomplete_manifest, sort_keys=True, indent=2) + "\n",
    )
    _atomic_write(markdown_path, markdown_payload)
    _atomic_write(json_path, json_payload)
    json_bytes = json_payload.encode("utf-8")
    markdown_bytes = markdown_payload.encode("utf-8")
    complete_manifest = {
        "manifest_schema_version": "1.0",
        "state": "COMPLETE",
        "run_id": report.get("run_id"),
        "qualification_status": report.get("qualification", {}).get("status"),
        "files": {
            REPORT_JSON_NAME: {
                "sha256": hashlib.sha256(json_bytes).hexdigest(),
                "bytes": len(json_bytes),
            },
            REPORT_MARKDOWN_NAME: {
                "sha256": hashlib.sha256(markdown_bytes).hexdigest(),
                "bytes": len(markdown_bytes),
            },
        },
    }
    _atomic_write(
        manifest_path,
        json.dumps(complete_manifest, sort_keys=True, indent=2) + "\n",
    )
    return json_path, markdown_path


def validate_report_pair(report_path: str | Path) -> Mapping[str, Any]:
    """Load a report only after verifying its completed evidence pair."""

    json_path = Path(report_path)
    root = json_path.parent
    markdown_path = root / REPORT_MARKDOWN_NAME
    manifest_path = root / REPORT_MANIFEST_NAME
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ReportIntegrityError("report completion manifest is unavailable") from exc
    if not isinstance(manifest, dict) or manifest.get("state") != "COMPLETE":
        raise ReportIntegrityError("report pair publication is not complete")
    if manifest.get("manifest_schema_version") != "1.0":
        raise ReportIntegrityError("report completion manifest version is unsupported")

    payloads: dict[str, bytes] = {}
    for name, path in (
        (REPORT_JSON_NAME, json_path),
        (REPORT_MARKDOWN_NAME, markdown_path),
    ):
        try:
            payload = path.read_bytes()
        except OSError as exc:
            raise ReportIntegrityError(f"report artifact is unavailable: {name}") from exc
        files = manifest.get("files")
        expected = files.get(name) if isinstance(files, dict) else None
        if not isinstance(expected, dict):
            raise ReportIntegrityError(f"report manifest has no record for {name}")
        if (
            expected.get("bytes") != len(payload)
            or expected.get("sha256") != hashlib.sha256(payload).hexdigest()
        ):
            raise ReportIntegrityError(f"report artifact does not match manifest: {name}")
        payloads[name] = payload
    try:
        report = json.loads(payloads[REPORT_JSON_NAME].decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReportIntegrityError("report JSON is invalid") from exc
    if not isinstance(report, dict):
        raise ReportIntegrityError("report JSON must be an object")
    qualification = report.get("qualification")
    qualification_status = (
        qualification.get("status") if isinstance(qualification, dict) else None
    )
    if (
        manifest.get("run_id") != report.get("run_id")
        or manifest.get("qualification_status") != qualification_status
    ):
        raise ReportIntegrityError("report identity does not match completion manifest")
    return report

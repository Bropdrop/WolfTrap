"""Fail-closed GitHub Action boundary for WolfTrap's offline build inspector.

Only scanner-owned evidence is uploaded. Target project code is never executed.
This module does not invoke shell commands, read tokens, or use network APIs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from .build_scan import MANIFEST_NAME, MARKDOWN_NAME, REPORT_NAME, SARIF_NAME, scan_build
from .report import write_json_report

ACTION_SUMMARY_NAME = "wolftrap-action.json"
SUPPORTED_REPORTS = frozenset({REPORT_NAME, MARKDOWN_NAME, SARIF_NAME})
_OUTPUT_KEY = re.compile(r"^[a-z_]+$")


@dataclass(frozen=True)
class ActionOutcome:
    status: str
    findings: int
    unknown_inputs: int
    scanner_exit_code: int
    exit_code: int
    reason: str


def _verify_completed_scan(evidence_root: Path, report: dict[str, object]) -> None:
    manifest = json.loads((evidence_root / MANIFEST_NAME).read_text(encoding="utf-8"))
    if manifest.get("state") != "COMPLETE" or set(manifest.get("files", {})) != SUPPORTED_REPORTS:
        raise ValueError("scanner completion manifest is missing or incomplete")
    for name, metadata in manifest["files"].items():
        path = evidence_root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("scanner evidence member must be a regular file")
        data = path.read_bytes()
        if metadata != {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}:
            raise ValueError("scanner evidence digest mismatch")
    qualification = report.get("qualification")
    coverage = report.get("coverage")
    if (
        not isinstance(qualification, dict)
        or not isinstance(coverage, dict)
        or qualification.get("status") != manifest.get("qualification_status")
        or coverage.get("input_digest") != manifest.get("input_digest")
        or report.get("target_code_executed") is not False
        or report.get("external_systems_contacted") is not False
        or report.get("model_used") is not False
    ):
        raise ValueError("scanner evidence status or safety declaration mismatch")


def _write_outputs(path: Path, values: dict[str, str]) -> None:
    if path.is_symlink():
        raise ValueError("GitHub output destination cannot be a symlink")
    for key, value in values.items():
        if not _OUTPUT_KEY.fullmatch(key) or "\n" in value or "\r" in value:
            raise ValueError("unsafe GitHub Action output value")
    with path.open("a", encoding="utf-8", newline="\n") as target:
        for key, value in values.items():
            target.write(f"{key}={value}\n")


def run_action(
    *,
    root: str | Path,
    output_dir: str | Path,
    fail_on_findings: str,
    github_output: str | Path | None = None,
) -> ActionOutcome:
    """Classify scan outcomes without turning unknown input into a clean PASS.

    Action mode only controls whether known findings fail CI; unknown or
    corrupted input always fails. Every result has a safe, limited summary.
    """
    output = Path(output_dir)
    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        raise ValueError("action evidence directory must be fresh, empty and non-symlink")
    output.mkdir(parents=True, exist_ok=True)
    status, findings, unknown, scanner_code = "INCONCLUSIVE", 0, 1, 2
    reason = "SCAN_NOT_COMPLETED"
    if fail_on_findings not in {"true", "false"}:
        reason = "INVALID_FAILURE_MODE"
    else:
        try:
            result = scan_build(root, output)
            _verify_completed_scan(output, result.report)
            status = str(result.report["qualification"]["status"])
            summary = result.report["summary"]
            findings = int(summary["findings"])
            unknown = int(summary["errors"])
            scanner_code = result.exit_code
            if (status, scanner_code) not in {
                ("NO_PATTERN_MATCH", 0), ("REVIEW_REQUIRED", 1), ("INCONCLUSIVE", 2)
            }:
                raise ValueError("scanner return code contradicts the report")
            reason = "SCANNER_COMPLETED"
        except Exception:
            # Never treat a parser error, broken manifest, unsupported root,
            # or I/O failure as a clean scan. Avoid reflecting sensitive paths.
            status, findings, unknown, scanner_code = "INCONCLUSIVE", 0, 1, 2
            reason = "INPUT_OR_EVIDENCE_FAILURE"
    exit_code = 2 if scanner_code == 2 else 1 if scanner_code == 1 and fail_on_findings == "true" else 0
    outcome = ActionOutcome(status, findings, unknown, scanner_code, exit_code, reason)
    write_json_report({
        "schema": "wolftrap.github-action-result/v1",
        "status": outcome.status,
        "findings": outcome.findings,
        "unknown_inputs": outcome.unknown_inputs,
        "scanner_exit_code": outcome.scanner_exit_code,
        "action_exit_code": outcome.exit_code,
        "reason": outcome.reason,
        "synthetic_or_local_static_only": True,
        "confirmed_vulnerabilities": 0,
        "target_code_executed": False,
        "external_targets_contacted": False,
    }, output / ACTION_SUMMARY_NAME)
    if github_output is not None:
        _write_outputs(Path(github_output), {
            "status": outcome.status,
            "findings": str(outcome.findings),
            "unknown_inputs": str(outcome.unknown_inputs),
            "scanner_exit_code": str(outcome.scanner_exit_code),
            "evidence_dir": str(output.resolve()),
        })
    return outcome


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--fail-on-findings", default="false")
    parser.add_argument("--github-output")
    args = parser.parse_args(argv)
    try:
        outcome = run_action(
            root=args.root,
            output_dir=args.output_dir,
            fail_on_findings=args.fail_on_findings,
            github_output=args.github_output,
        )
        print(f"{outcome.status}: {outcome.findings} review signals; {outcome.unknown_inputs} unknown inputs")
        print(f"WolfTrap evidence: {args.output_dir}")
        return outcome.exit_code
    except Exception as exc:
        print(f"WolfTrap Action blocked: {type(exc).__name__}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

"""Finite, deterministic attack-path detector challenge against synthetic CI.

The fixtures are never executed. The independent label comes from a tiny
declared workflow grammar, not from WolfTrap's static finding implementation.
"""

from __future__ import annotations

import hashlib
import json
import random
import tempfile
from pathlib import Path
from typing import Any

from .build_scan import MANIFEST_NAME as SCAN_MANIFEST, scan_build
from .report import _atomic_write, write_json_report

CHALLENGE_REPORT = "challenge-report.json"
CHALLENGE_CASES = "challenge-cases.json"
CHALLENGE_MARKDOWN = "challenge-report.md"
CHALLENGE_MANIFEST = "challenge.manifest.json"
_PIN = "11bd71901bbe5b1630ceea73d27597364c9af683"
_RUN_ID = "${{ github.event.workflow_run.id }}"
_TOKEN = "${{ github.token }}"
_KINDS = ("HIGH", "MEDIUM", "NONE", "INCONCLUSIVE")
_FOLDERS = ("drop", "build/out", "cache/pkg", "artifacts/stage")
_ARTIFACTS = ("handoff", "nightly", "release", "matrix")

_HIGH = (
    "bash {d}/install.sh",
    "bash -e {d}/install.sh",
    "bash -eux {d}/install.sh",
    "sh -e {d}/install.sh",
    "python -u {d}/setup.py",
    "python3 -B {d}/setup.py",
    "node --trace-warnings {d}/entry.js",
    "env bash {d}/install.sh",
    "env python3 -u {d}/setup.py",
    "source {d}/activate.sh",
    "./{d}/entrypoint",
    "echo preparing; bash -e {d}/install.sh",
    "bash --noprofile {d}/install.sh",
    "env node --trace-warnings {d}/entry.js",
    "echo preparing; python3 -B {d}/setup.py",
    "sh {d}/install.sh",
)
_MEDIUM = (
    "cat {d}/coverage.json", "bash local/setup.sh", "echo review-only", "",
    "sha256sum {d}/manifest.json", "python -c 'print(1)'",
    "head -n 5 {d}/report.txt", "grep WARN {d}/log.txt",
)
_NONE = (
    "read_only", "wrong_artifact", "current_run", "push_guard",
    "push_source", "no_upload", "no_download", "no_token",
    "no_run_id", "wrong_workflow", "step_guard", "no_privileges",
    "no_upload_path", "constant_run", "different_artifact", "no_pr_event",
)
_UNKNOWN = ("duplicate_producer", "dynamic_upload", "dynamic_download", "cross_repository")


def _json_bytes(obj: Any) -> bytes:
    return (json.dumps(obj, sort_keys=True, ensure_ascii=False, allow_nan=False, indent=2) + "\n").encode()


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _case(index: int, rng: random.Random) -> dict[str, Any]:
    kind = _KINDS[index % len(_KINDS)]
    variant = index // len(_KINDS)
    folder = rng.choice(_FOLDERS)
    artifact = rng.choice(_ARTIFACTS)
    options: dict[str, Any] = {
        "folder": folder, "artifact": artifact,
        "run": "cat " + folder + "/manifest.json",
        "producer_event": "pull_request", "permission": "write",
        "upload": True, "download": True, "run_id": _RUN_ID,
        "download_token": True, "consumer_workflow": "PR Build",
        "upload_name": artifact, "download_name": artifact,
    }
    if kind == "HIGH":
        style = _HIGH[variant % len(_HIGH)]
        options["run"] = style.format(d=folder)
    elif kind == "MEDIUM":
        style = _MEDIUM[variant % len(_MEDIUM)]
        options["run"] = style.format(d=folder)
    elif kind == "NONE":
        style = _NONE[variant % len(_NONE)]
        if style == "read_only": options["permission"] = "read"
        if style in {"wrong_artifact", "different_artifact"}: options["download_name"] = "unrelated"
        if style == "current_run": options["run_id"] = "${{ github.run_id }}"
        if style == "push_guard": options["job_guard"] = "github.event.workflow_run.event == 'push'"
        if style == "push_source": options["producer_event"] = "push"
        if style == "no_upload": options["upload"] = False
        if style == "no_download": options["download"] = False
        if style == "no_token": options["download_token"] = False
        if style == "no_run_id": options["run_id"] = ""
        if style == "wrong_workflow": options["consumer_workflow"] = "Other Build"
        if style == "step_guard": options["step_guard"] = "github.event.workflow_run.event != 'pull_request'"
        if style == "no_privileges": options["permission"] = "none"
        if style == "no_upload_path": options["upload_path"] = ""
        if style == "constant_run": options["run_id"] = "12345"
        if style == "no_pr_event": options["producer_event"] = "workflow_dispatch"
    else:
        style = _UNKNOWN[variant % len(_UNKNOWN)]
        if style == "duplicate_producer": options["duplicate_producer"] = True
        if style == "dynamic_upload": options["upload_name"] = "${{ github.run_id }}"
        if style == "dynamic_download": options["download_name"] = "${{ inputs.artifact }}"
        if style == "cross_repository": options["repository"] = "example/another-repo"

    # Independent labels describe the *generated grammar*, not scanner output.
    return {
        "id": f"CHALLENGE-{index:04d}", "expected": kind, "mutation": style,
        "synthetic_only": True, "parameters": options,
        "workflows": _render_case(options, extra_job=bool(rng.getrandbits(1))),
    }


def _render_case(o: dict[str, Any], *, extra_job: bool) -> dict[str, str]:
    producer = [
        "name: PR Build", f"on: {o['producer_event']}",
        "permissions:", "  contents: read", "jobs:", "  pack:", "    steps:",
    ]
    if o["upload"]:
        producer.extend([
            f"      - uses: actions/upload-artifact@{_PIN}", "        with:",
            f"          name: '{o['upload_name']}'",
            f"          path: {o.get('upload_path', 'build-output')}",
        ])
    else:
        producer.append("      - run: echo safe")
    if extra_job:
        producer.extend(["  lint:", "    steps:", "      - run: echo safe"])

    consumer = [
        "name: Privileged Report", "on:", "  workflow_run:",
        f"    workflows: ['{o['consumer_workflow']}']", "    types: [completed]",
        "permissions:", f"  contents: {o['permission']}", "jobs:", "  review:",
    ]
    if o.get("job_guard"):
        consumer.append(f"    if: {o['job_guard']}")
    consumer.extend(["    steps:", "      - run: echo bounded-preflight"])
    if o["download"]:
        consumer.append(f"      - uses: actions/download-artifact@{_PIN}")
        if o.get("step_guard"):
            consumer.append(f"        if: {o['step_guard']}")
        consumer.append("        with:")
        if o["run_id"]:
            consumer.append(f"          run-id: {o['run_id']}")
        if o["download_token"]:
            consumer.append(f"          github-token: {_TOKEN}")
        consumer.extend([
            f"          name: '{o['download_name']}'",
            f"          path: {o['folder']}",
        ])
        if o.get("repository"):
            consumer.append(f"          repository: {o['repository']}")
    if o["run"]:
        consumer.append(f"      - run: {o['run']}")
    workflow_map = {
        "pr.yml": "\n".join(producer) + "\n",
        "privileged.yml": "\n".join(consumer) + "\n",
    }
    if o.get("duplicate_producer"):
        workflow_map["duplicate.yml"] = workflow_map["pr.yml"]
    return workflow_map


def _check_scan_evidence(root: Path, report: dict[str, Any]) -> bool:
    manifest = json.loads((root / SCAN_MANIFEST).read_text(encoding="utf-8"))
    if manifest.get("state") != "COMPLETE":
        return False
    for filename, metadata in manifest["files"].items():
        raw = (root / filename).read_bytes()
        if metadata != {"bytes": len(raw), "sha256": _sha(raw)}:
            return False
    return (
        not report["target_code_executed"]
        and not report["external_systems_contacted"]
        and not report["model_used"]
        and manifest["input_digest"] == report["coverage"]["input_digest"]
    )


def _render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# WolfTrap Stage 5 — offline detector evasion tournament", "",
        "> All workflows are synthetic. No target code, secrets, network, or commands are executed.",
        "> A passing tournament is not a security certification.", "",
        f"Status: **{report['qualification']['status']}**  ",
        f"Seed: `{report['configuration']['seed']}`  ",
        f"Cases: `{report['summary']['cases']}`  ",
        f"Mismatches: `{report['summary']['mismatches']}`", "",
        "| Independent label | Cases | Matched expectation |", "| --- | ---: | ---: |",
    ]
    for kind in _KINDS:
        item = report["summary"]["by_expected"][kind]
        lines.append(f"| {kind} | {item['total']} | {item['matched']} |")
    lines.extend(["", "## Differential gaps", ""])
    gaps = [x for x in report["cases"] if not x["matched"]]
    if not gaps:
        lines.append("No gaps within this finite generated grammar.")
    for case in gaps[:32]:
        lines.append(f"- `{case['id']}` `{case['mutation']}` expected {case['expected']}; observed {case['observed']}")
    if len(gaps) > 32:
        lines.append(f"- {len(gaps) - 32} additional gaps are recorded in JSON.")
    lines.extend(["", "The replayable complete synthetic YAML case set is `challenge-cases.json`.",
                  "Check SHA-256 digests in `challenge.manifest.json` before using its results.", ""])
    return "\n".join(lines)


def run_challenge(*, seed: int, count: int, output_dir: str | Path) -> tuple[dict[str, Any], int]:
    """Run only known synthetic workflow grammar through the real scanner."""
    if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF:
        raise ValueError("seed must be a 32-bit unsigned integer")
    if type(count) is not int or not 64 <= count <= 256 or count % 4:
        raise ValueError("cases must be a multiple of four between 64 and 256")
    output = Path(output_dir)
    if output.is_symlink() or (output.exists() and (not output.is_dir() or any(output.iterdir()))):
        raise ValueError("challenge output must be a fresh or empty non-symlink directory")
    output.mkdir(parents=True, exist_ok=True)
    write_json_report({"state": "INCOMPLETE"}, output / CHALLENGE_MANIFEST)
    rng = random.Random(seed)
    corpus = [_case(i, rng) for i in range(count)]
    results: list[dict[str, Any]] = []
    for item in corpus:
        with tempfile.TemporaryDirectory(prefix="wolftrap-challenge-") as tmp:
            target = Path(tmp) / "synthetic"
            workflows = target / ".github/workflows"
            workflows.mkdir(parents=True)
            for filename, content in item["workflows"].items():
                (workflows / filename).write_text(content, encoding="utf-8")
            before = {f.name: f.read_bytes() for f in workflows.iterdir()}
            evidence = Path(tmp) / "evidence"
            result = scan_build(target, evidence)
            after = {f.name: f.read_bytes() for f in workflows.iterdir()}
            if before != after or not _check_scan_evidence(evidence, result.report):
                raise ValueError("scanner changed inputs or synthetic evidence failed integrity checks")
        signals = [finding for finding in result.report["findings"] if finding["rule_id"] == "WT-GHA-006"]
        observed = (
            "INCONCLUSIVE" if result.exit_code == 2
            else signals[0]["severity"] if len(signals) == 1
            else "NONE" if not signals else "AMBIGUOUS"
        )
        results.append({
            "id": item["id"], "mutation": item["mutation"],
            "expected": item["expected"], "observed": observed,
            "matched": observed == item["expected"],
            "input_sha256": {name: _sha(body.encode()) for name, body in sorted(item["workflows"].items())},
            "input_digest": result.report["coverage"]["input_digest"],
            "scan_status": result.report["qualification"]["status"],
        })
    counts = {
        kind: {"total": sum(c["expected"] == kind for c in results),
               "matched": sum(c["expected"] == kind and c["matched"] for c in results)}
        for kind in _KINDS
    }
    mismatches = sum(not item["matched"] for item in results)
    status = "PASSED_BOUNDED" if mismatches == 0 else "DETECTOR_GAPS"
    report = {
        "schema": "wolftrap.stage5.challenge-report/v1",
        "purpose": "offline deterministic detection-evasion regression tournament",
        "configuration": {"seed": seed, "cases": count},
        "qualification": {
            "status": status, "synthetic_only": True, "external_targets": False,
            "target_code_executed": False, "limited_not_exhaustive": True,
            "confirmed_vulnerabilities": 0,
        },
        "summary": {"cases": count, "mismatches": mismatches, "by_expected": counts},
        "cases": results,
    }
    files = {
        CHALLENGE_REPORT: _json_bytes(report),
        CHALLENGE_CASES: _json_bytes({"schema": "wolftrap.stage5.saved-cases/v1", "cases": corpus}),
        CHALLENGE_MARKDOWN: _render_markdown(report).encode(),
    }
    for filename, raw in files.items():
        _atomic_write(output / filename, raw.decode("utf-8"))
    write_json_report({
        "schema": "wolftrap.stage5.challenge-manifest/v1", "state": "COMPLETE",
        "status": status,
        "files": {name: {"bytes": len(raw), "sha256": _sha(raw)} for name, raw in sorted(files.items())},
    }, output / CHALLENGE_MANIFEST)
    return report, 0 if not mismatches else 1


def verify_challenge_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    """Check completeness, hash integrity, and saved-case/report consistency."""
    root = Path(evidence_dir)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("challenge evidence must be a regular directory")
    manifest = json.loads((root / CHALLENGE_MANIFEST).read_text(encoding="utf-8"))
    if manifest.get("state") != "COMPLETE" or manifest.get("schema") != "wolftrap.stage5.challenge-manifest/v1":
        raise ValueError("challenge completion manifest is invalid or incomplete")
    expected_files = {CHALLENGE_REPORT, CHALLENGE_CASES, CHALLENGE_MARKDOWN}
    if set(manifest.get("files", {})) != expected_files:
        raise ValueError("challenge completion manifest has missing or unexpected files")
    for filename, metadata in manifest["files"].items():
        path = root / filename
        if path.is_symlink() or not path.is_file():
            raise ValueError("challenge evidence member is not a regular file")
        raw = path.read_bytes()
        if metadata != {"bytes": len(raw), "sha256": _sha(raw)}:
            raise ValueError("challenge evidence hash or byte count mismatch")
    report = json.loads((root / CHALLENGE_REPORT).read_text(encoding="utf-8"))
    saved = json.loads((root / CHALLENGE_CASES).read_text(encoding="utf-8"))
    if (report.get("schema") != "wolftrap.stage5.challenge-report/v1"
            or saved.get("schema") != "wolftrap.stage5.saved-cases/v1"
            or report["qualification"]["status"] != manifest["status"]):
        raise ValueError("challenge report or saved-case schema/status mismatch")
    if len(saved["cases"]) != report["summary"]["cases"] or len(report["cases"]) != len(saved["cases"]):
        raise ValueError("challenge saved cases do not match report counts")
    for original, observed in zip(saved["cases"], report["cases"]):
        if (original["id"] != observed["id"] or original["expected"] != observed["expected"]
                or original["mutation"] != observed["mutation"]
                or {name: _sha(body.encode()) for name, body in sorted(original["workflows"].items())}
                != observed["input_sha256"]):
            raise ValueError("challenge replay input does not match reported case")
    return report

"""Independent-label, offline qualification and saved-input replay for scan-agent.

Only synthetic fixture definitions are materialized. Application source is never
executed. A detector tournament is finite evidence, not a vulnerability claim.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from .agent_corpus import corpus_cases
from .agent_scan import scan_agent, verify_agent_evidence
from .report import _atomic_write, write_json_report

CHALLENGE_REPORT = "agent-challenge-report.json"
CHALLENGE_CASES = "agent-challenge-cases.json"
CHALLENGE_MARKDOWN = "agent-challenge-report.md"
CHALLENGE_MANIFEST = "agent-challenge.manifest.json"
_SCAN_FILES = (
    "agent-scan.json", "agent-scan.md", "agent-scan.sarif", "agent-scan.manifest.json"
)
_CATEGORIES = ("positive", "negative", "ambiguous", "evasion")
_STATUSES = {"NO_PATTERN_MATCH": 0, "REVIEW_REQUIRED": 1, "INCONCLUSIVE": 2}
_RULES = {"WT-AGENT-001", "WT-AGENT-002", "WT-AGENT-003"}
_MAX_EVIDENCE_BYTES = 32 * 1024 * 1024


def _encoded(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False,
                       indent=2) + "\n").encode("utf-8")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _metadata(raw: bytes) -> dict[str, Any]:
    return {"bytes": len(raw), "sha256": _sha(raw)}


def _relative(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ValueError("invalid synthetic fixture path")
    path = PurePosixPath(value)
    if (path.is_absolute() or "\\" in value or "\x00" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or len(path.parts) > 8
            or not re.fullmatch(r"[A-Za-z0-9_./-]+", value)):
        raise ValueError("synthetic fixture path is outside its root")
    return value


def _validate_cases(cases: Any) -> list[dict[str, Any]]:
    if not isinstance(cases, list) or not 96 <= len(cases) <= 256:
        raise ValueError("agent corpus requires between 96 and 256 cases")
    seen: set[str] = set()
    total = 0
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("synthetic case must be an object")
        identifier = case.get("id")
        if (not isinstance(identifier, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", identifier)
                or identifier in seen):
            raise ValueError("synthetic case identity is invalid or duplicated")
        seen.add(identifier)
        if (case.get("synthetic_only") is not True
                or case.get("category") not in _CATEGORIES
                or case.get("expected_status") not in _STATUSES):
            raise ValueError("synthetic case independent label is invalid")
        rules = case.get("expected_rules")
        if (not isinstance(rules, list) or any(rule not in _RULES for rule in rules)
                or len(set(rules)) != len(rules)):
            raise ValueError("synthetic case rule labels are invalid")
        files = case.get("files")
        if not isinstance(files, dict) or len(files) > 16:
            raise ValueError("synthetic file count is outside the fixture bound")
        for name, text in files.items():
            _relative(name)
            if not isinstance(text, str) or len(text.encode("utf-8")) > 256 * 1024:
                raise ValueError("synthetic source exceeds fixture bound")
            total += len(text.encode("utf-8"))
        selected = case.get("selected_files")
        if selected is not None and (
            not isinstance(selected, list) or len(selected) > 16
            or any(not isinstance(item, str) or len(item) > 200 for item in selected)
        ):
            raise ValueError("synthetic selection is outside the fixture bound")
        directives = case.get("directives", [])
        if not isinstance(directives, list) or len(directives) > 8:
            raise ValueError("synthetic directive count is outside the fixture bound")
        occupied = set(files)
        symlinks: set[str] = set()
        for directive in directives:
            if not isinstance(directive, dict):
                raise ValueError("synthetic directive must be an object")
            kind = directive.get("kind")
            if kind in {"missing", "path_escape"}:
                # These are scanner selection tests, never materialized paths.
                if not isinstance(directive.get("path"), str) or selected is None:
                    raise ValueError("missing or escape fixture lacks explicit selection")
                continue
            if kind not in {"invalid_utf8", "oversized", "symlink", "symlink_directory"}:
                raise ValueError("unsupported synthetic fixture directive")
            path = _relative(directive.get("path"))
            if path in occupied:
                raise ValueError("synthetic directive would overwrite an existing file")
            occupied.add(path)
            if kind == "invalid_utf8":
                value = directive.get("hex")
                if not isinstance(value, str) or len(value) > 128:
                    raise ValueError("invalid byte fixture exceeds its bound")
                bytes.fromhex(value)
            elif kind == "oversized":
                if (directive.get("character") != " "
                        or type(directive.get("count")) is not int
                        or not 1 <= directive["count"] <= 262145):
                    raise ValueError("oversize fixture exceeds its bound")
            else:
                target = _relative(directive.get("target"))
                if kind == "symlink" and target not in files:
                    raise ValueError("symlink fixture target is not a declared local file")
                if kind == "symlink_directory" and not any(
                    name.startswith(target + "/") for name in files
                ):
                    raise ValueError("symlink fixture target is not a declared local directory")
                symlinks.add(path)
        if any(name.startswith(link + "/") for name in occupied for link in symlinks):
            raise ValueError("synthetic fixture must not write through a symlink")
    if total > 4 * 1024 * 1024:
        raise ValueError("synthetic corpus source exceeds aggregate bound")
    if set(case["category"] for case in cases) != set(_CATEGORIES):
        raise ValueError("synthetic corpus must include all four control categories")
    if not any(case["expected_rules"] for case in cases):
        raise ValueError("synthetic corpus has no positive detector controls")
    if not any(case["expected_status"] == "NO_PATTERN_MATCH" for case in cases):
        raise ValueError("synthetic corpus has no negative detector controls")
    for rule in _RULES:
        if not any(case["expected_status"] == "REVIEW_REQUIRED"
                   and rule in case["expected_rules"] for case in cases):
            raise ValueError("synthetic corpus lacks a rule-family positive control")
        if not any(case["expected_status"] == "NO_PATTERN_MATCH"
                   and case.get("family") == rule for case in cases):
            raise ValueError("synthetic corpus lacks a rule-family negative control")
    return cases


def _materialize(case: dict[str, Any], target: Path) -> None:
    target.mkdir()
    for relative, text in sorted(case["files"].items()):
        path = target / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    # Symlinks are created last, and no materialized path has a symlink ancestor.
    directives = sorted(case.get("directives", []),
                        key=lambda item: item["kind"].startswith("symlink"))
    for directive in directives:
        kind = directive["kind"]
        if kind in {"missing", "path_escape"}:
            continue
        path = target / directive["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        if kind == "invalid_utf8":
            path.write_bytes(bytes.fromhex(directive["hex"]))
        elif kind == "oversized":
            path.write_bytes(b" " * directive["count"])
        else:
            destination = target / directive["target"]
            path.symlink_to(os.path.relpath(destination, path.parent),
                            target_is_directory=kind == "symlink_directory")


def _snapshot(root: Path) -> dict[str, Any]:
    """Hash bounded synthetic fixture bytes without following any symlink."""
    entries: dict[str, Any] = {}
    def walk(directory: Path) -> None:
        for path in sorted(directory.iterdir()):
            relative = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                entries[relative] = {"kind": "symlink", "target": os.readlink(path)}
            elif stat.S_ISDIR(mode):
                entries[relative] = {"kind": "directory"}
                walk(path)
            elif stat.S_ISREG(mode):
                entries[relative] = {"kind": "file", **_metadata(path.read_bytes())}
            else:
                raise ValueError("unexpected synthetic fixture member")
    walk(root)
    return entries


def _compare(case: dict[str, Any], status: str, rules: list[str]) -> dict[str, Any]:
    expected = set(case["expected_rules"])
    actual = set(rules)
    return {
        "expected_status": case["expected_status"],
        "observed_status": status,
        "expected_rules": sorted(expected),
        "observed_rules": sorted(actual),
        "missing_rules": sorted(expected - actual),
        "unexpected_rules": sorted(actual - expected),
        "matched": status == case["expected_status"] and actual == expected,
    }


def _bind_inputs(scan: dict[str, Any], snapshot: dict[str, Any]) -> None:
    """Cross-check scanner input digests against independent fixture bytes."""
    regular_files = {
        _sha(name.encode("utf-8")): value for name, value in snapshot.items()
        if value["kind"] == "file"
    }
    for item in scan["coverage"]["input_files"]:
        independent = regular_files.get(item["source_path_sha256"])
        if (independent is None or independent["bytes"] != item["bytes"]
                or independent["sha256"] != item["sha256"]):
            raise ValueError("scanner input evidence differs from synthetic fixture bytes")


def _summary(cases: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "cases": len(cases), "completed": len(results),
        "skipped": len(cases) - len(results),
        "mismatches": sum(not item["matched"] for item in results),
        "detection_misses": sum(len(item["missing_rules"]) for item in results),
        "unexpected_signals": sum(len(item["unexpected_rules"]) for item in results),
        "false_positive_controls": sum(
            item["expected_status"] == "NO_PATTERN_MATCH" and bool(item["unexpected_rules"])
            for item in results
        ),
        "status_gaps": sum(item["expected_status"] != item["observed_status"]
                           for item in results),
        "by_category": {
            category: {
                "total": sum(case["category"] == category for case in cases),
                "completed": sum(item["category"] == category for item in results),
                "matched": sum(item["category"] == category and item["matched"]
                               for item in results),
            } for category in _CATEGORIES
        },
        "by_rule": {
            rule: {
                "positive_controls": sum(rule in case["expected_rules"] for case in cases),
                "detection_misses": sum(rule in item["missing_rules"] for item in results),
                "unexpected_signals": sum(rule in item["unexpected_rules"] for item in results),
            } for rule in sorted(_RULES)
        },
    }


def _markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# WolfTrap Stage 5.1 — synthetic agent detector qualification", "",
        "Static review signals only. This finite corpus is not a live vulnerability test",
        "or certification of an inspected application.", "",
        f"Status: **{report['qualification']['status']}**",
        f"Seed: `{report['configuration']['seed']}`",
        f"Completed: {summary['completed']} / {summary['cases']}; skipped: {summary['skipped']}",
        f"Detection misses: {summary['detection_misses']}",
        f"False-positive controls: {summary['false_positive_controls']}",
        f"Other unexpected signals: {summary['unexpected_signals']}",
        f"Status gaps: {summary['status_gaps']}", "",
        "| Category | Expected cases | Completed | Exact matches |",
        "| --- | ---: | ---: | ---: |",
    ]
    for category in _CATEGORIES:
        item = summary["by_category"][category]
        lines.append(f"| {category} | {item['total']} | {item['completed']} | {item['matched']} |")
    lines.extend(["", "Expected labels originate in independent synthetic fixture definitions.",
                  "Full replayable inputs, per-case outcomes and scanner artifacts are retained.",
                  "Validate the completion manifest before interpreting this report.", ""])
    if "replay_verification" in report:
        lines.append("Saved-input replay matched: " + str(report["replay_verification"]["matched"]))
    return "\n".join(lines) + "\n"


def _fresh_output(output: Path) -> None:
    absolute = Path(os.path.abspath(output))
    for component in [absolute, *absolute.parents]:
        if component.is_symlink():
            raise ValueError("agent challenge output cannot contain symlink components")
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise ValueError("agent challenge output must be a fresh or empty directory")
    output.mkdir(parents=True, exist_ok=True)


def _publish(output: Path, report: dict[str, Any], cases: list[dict[str, Any]]) -> None:
    write_json_report({"state": "INCOMPLETE"}, output / CHALLENGE_MANIFEST)
    payloads = {
        CHALLENGE_REPORT: _encoded(report),
        CHALLENGE_CASES: _encoded({"schema": "wolftrap.agent.saved-cases/v1", "cases": cases}),
        CHALLENGE_MARKDOWN: _markdown(report).encode("utf-8"),
    }
    for name, payload in payloads.items():
        _atomic_write(output / name, payload.decode("utf-8"))
    inventory = {name: _metadata(raw) for name, raw in payloads.items()}
    for item in report["cases"]:
        for filename in _SCAN_FILES:
            relative = "cases/" + item["id"] + "/" + filename
            inventory[relative] = _metadata((output / relative).read_bytes())
    write_json_report({
        "schema": "wolftrap.agent.challenge-manifest/v1", "state": "COMPLETE",
        "status": report["qualification"]["status"],
        "files": dict(sorted(inventory.items())),
    }, output / CHALLENGE_MANIFEST)


def run_agent_challenge(*, seed: int, output_dir: str | Path,
                        replay_cases: list[dict[str, Any]] | None = None
                        ) -> tuple[dict[str, Any], int]:
    if type(seed) is not int or not 0 <= seed <= 0xFFFFFFFF:
        raise ValueError("agent challenge seed must be a 32-bit unsigned integer")
    cases = _validate_cases(corpus_cases(seed) if replay_cases is None else replay_cases)
    output = Path(output_dir)
    _fresh_output(output)
    write_json_report({"state": "INCOMPLETE"}, output / CHALLENGE_MANIFEST)
    results: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for case in cases:
        try:
            with tempfile.TemporaryDirectory(prefix="wolftrap-agent-fixture-") as temporary:
                target = Path(temporary) / "synthetic"
                _materialize(case, target)
                before = _snapshot(target)
                evidence = output / "cases" / case["id"]
                outcome = scan_agent(target, evidence, files=case.get("selected_files"))
                after = _snapshot(target)
                if before != after:
                    raise ValueError("scanner modified synthetic source")
                verified = verify_agent_evidence(evidence)
                if outcome.report != verified:
                    raise ValueError("scanner return differs from recorded evidence")
                _bind_inputs(verified, before)
                status = verified["qualification"]["status"]
                if outcome.exit_code != _STATUSES[status]:
                    raise ValueError("scanner status and exit code disagree")
                if any(verified.get(key) is not False for key in (
                    "target_code_executed", "external_systems_contacted", "model_used"
                )):
                    raise ValueError("scanner containment assertion is not closed")
                observed_rules = sorted({item["rule_id"] for item in verified["findings"]})
                result = {
                    "id": case["id"], "category": case["category"],
                    **_compare(case, status, observed_rules),
                    "input_definition_sha256": _sha(_encoded(case)),
                    "materialized_input": before,
                    "source_unchanged": True,
                    "scan_evidence": {name: _metadata((evidence / name).read_bytes())
                                      for name in _SCAN_FILES},
                }
                results.append(result)
        except Exception as exc:
            # Error messages may contain inspected text; retain a fixed marker only.
            errors.append({"case_id": case["id"], "code": "QUALIFICATION_STOPPED",
                           "error_type": type(exc).__name__, "fail_closed": True})
            break
    summary = _summary(cases, results)
    status = "ERROR" if errors else "DETECTOR_GAPS" if summary["mismatches"] else "PASSED_BOUNDED"
    report = {
        "schema": "wolftrap.agent.challenge-report/v1",
        "configuration": {"seed": seed, "cases": len(cases)},
        "qualification": {
            "status": status, "synthetic_only": True, "limited_not_exhaustive": True,
            "confirmed_vulnerabilities": 0, "target_code_executed": False,
            "external_systems_contacted": False, "model_used": False,
            "independent_fixture_labels": True,
        },
        "summary": summary, "cases": results, "errors": errors,
    }
    _publish(output, report, cases)
    return report, 2 if errors else 1 if summary["mismatches"] else 0


def _read_member(root: Path, relative: str) -> bytes:
    _relative(relative)
    if (".." in root.parts or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_DIRECTORY")):
        raise ValueError("safe challenge evidence traversal is unavailable")
    path = Path(os.path.abspath(root)) / relative
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(path.anchor, directory_flags)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, directory_flags, dir_fd=directory)
            os.close(directory)
            directory = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                             dir_fd=directory)
        with os.fdopen(descriptor, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > _MAX_EVIDENCE_BYTES:
                raise ValueError("challenge evidence is not a bounded regular file")
            raw = handle.read(_MAX_EVIDENCE_BYTES + 1)
            after = os.fstat(handle.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                raise ValueError("challenge evidence changed during read")
    finally:
        os.close(directory)
    if len(raw) > _MAX_EVIDENCE_BYTES:
        raise ValueError("challenge evidence exceeded its byte bound")
    return raw


def _json(raw: bytes) -> Any:
    def reject_constant(_: str) -> None:
        raise ValueError("challenge evidence contains non-finite JSON")
    return json.loads(raw.decode("utf-8"), parse_constant=reject_constant)


def _verified_evidence(evidence_dir: str | Path
                       ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    root = Path(evidence_dir)
    manifest = _json(_read_member(root, CHALLENGE_MANIFEST))
    if (not isinstance(manifest, dict) or manifest.get("state") != "COMPLETE"
            or manifest.get("schema") != "wolftrap.agent.challenge-manifest/v1"):
        raise ValueError("agent challenge manifest is incomplete or invalid")
    inventory = manifest.get("files")
    if not isinstance(inventory, dict) or not 3 <= len(inventory) <= 1027:
        raise ValueError("agent challenge inventory is invalid")
    if any(not isinstance(metadata, dict) or type(metadata.get("bytes")) is not int
           or not 0 <= metadata["bytes"] <= _MAX_EVIDENCE_BYTES
           for metadata in inventory.values()):
        raise ValueError("agent challenge evidence byte bounds are invalid")
    if sum(metadata["bytes"] for metadata in inventory.values()) > 64 * 1024 * 1024:
        raise ValueError("agent challenge evidence exceeds aggregate read bound")
    payloads: dict[str, bytes] = {}
    for name, metadata in inventory.items():
        raw = _read_member(root, name)
        if _metadata(raw) != metadata:
            raise ValueError("agent challenge evidence hash or byte count mismatch")
        payloads[name] = raw
    saved = _json(payloads[CHALLENGE_CASES])
    report = _json(payloads[CHALLENGE_REPORT])
    if saved.get("schema") != "wolftrap.agent.saved-cases/v1":
        raise ValueError("agent challenge saved-case schema is invalid")
    cases = _validate_cases(saved.get("cases"))
    if (report.get("schema") != "wolftrap.agent.challenge-report/v1"
            or report["qualification"]["status"] != manifest["status"]):
        raise ValueError("agent challenge report schema or status is invalid")
    qualification = report["qualification"]
    if (qualification.get("synthetic_only") is not True
            or qualification.get("limited_not_exhaustive") is not True
            or qualification.get("independent_fixture_labels") is not True
            or qualification.get("confirmed_vulnerabilities") != 0
            or any(qualification.get(key) is not False for key in (
                "target_code_executed", "external_systems_contacted", "model_used"
            ))):
        raise ValueError("agent challenge containment assertions are inconsistent")
    configuration = report["configuration"]
    if (configuration.get("cases") != len(cases)
            or type(configuration.get("seed")) is not int
            or not 0 <= configuration["seed"] <= 0xFFFFFFFF):
        raise ValueError("agent challenge configuration is inconsistent")
    expected_files = {CHALLENGE_REPORT, CHALLENGE_CASES, CHALLENGE_MARKDOWN}
    results = report["cases"]
    if not isinstance(results, list) or len(results) > len(cases):
        raise ValueError("agent challenge result count is invalid")
    for case, result in zip(cases, results):
        if (case["id"] != result["id"] or case["category"] != result["category"]
                or _sha(_encoded(case)) != result["input_definition_sha256"]
                or result["source_unchanged"] is not True):
            raise ValueError("agent challenge input and observation differ")
        comparison = _compare(case, result["observed_status"], result["observed_rules"])
        if any(result[key] != value for key, value in comparison.items()):
            raise ValueError("agent challenge independent comparison differs")
        with tempfile.TemporaryDirectory(prefix="wolftrap-agent-input-verify-") as temporary:
            target = Path(temporary) / "synthetic"
            _materialize(case, target)
            if _snapshot(target) != result["materialized_input"]:
                raise ValueError("agent challenge materialized input differs from saved definition")
        evidence = root / "cases" / case["id"]
        scan = verify_agent_evidence(evidence)
        if scan != _json(payloads["cases/" + case["id"] + "/agent-scan.json"]):
            raise ValueError("agent challenge scanner evidence changed during verification")
        _bind_inputs(scan, result["materialized_input"])
        if (scan["qualification"]["status"] != result["observed_status"]
                or sorted({item["rule_id"] for item in scan["findings"]}) != result["observed_rules"]):
            raise ValueError("agent challenge observation differs from scanner evidence")
        for name in _SCAN_FILES:
            relative = "cases/" + case["id"] + "/" + name
            expected_files.add(relative)
            if result["scan_evidence"][name] != inventory.get(relative):
                raise ValueError("agent challenge scanner evidence inventory differs")
    if set(inventory) != expected_files:
        raise ValueError("agent challenge evidence inventory is incomplete or unexpected")
    if report["summary"] != _summary(cases, results):
        raise ValueError("agent challenge counts are inconsistent")
    expected_status = (
        "ERROR" if report["errors"] else "DETECTOR_GAPS"
        if report["summary"]["mismatches"] else "PASSED_BOUNDED"
    )
    if len(results) != len(cases) and not report["errors"]:
        raise ValueError("agent challenge incomplete cases cannot qualify")
    if report["qualification"]["status"] != expected_status:
        raise ValueError("agent challenge qualification is inconsistent")
    replay = report.get("replay_verification")
    if replay is not None:
        if (not isinstance(replay, dict)
                or replay.get("saved_inputs_reexecuted") is not True
                or type(replay.get("matched")) is not bool
                or replay.get("original_cases_sha256") != _sha(_encoded(saved))
                or (not replay["matched"] and not any(
                    item.get("code") == "REPLAY_DIFFERED" for item in report["errors"]
                ))):
            raise ValueError("agent challenge replay assertions are inconsistent")
    if payloads[CHALLENGE_MARKDOWN] != _markdown(report).encode("utf-8"):
        raise ValueError("agent challenge Markdown rendering differs from evidence")
    return report, cases


def verify_agent_challenge_evidence(evidence_dir: str | Path) -> dict[str, Any]:
    """Validate bounded artifacts, independent labels and synthetic inputs."""
    try:
        return _verified_evidence(evidence_dir)[0]
    except Exception:
        raise ValueError("agent challenge evidence is incomplete, unsafe or inconsistent") from None


def replay_agent_challenge(evidence_dir: str | Path, output_dir: str | Path
                           ) -> tuple[dict[str, Any], int]:
    try:
        # Keep the exact verified in-memory saved cases: do not reopen a file
        # after verification and accidentally replay substituted bytes.
        original, cases = _verified_evidence(evidence_dir)
    except Exception:
        raise ValueError("agent challenge evidence is incomplete, unsafe or inconsistent") from None
    report, code = run_agent_challenge(
        seed=original["configuration"]["seed"], output_dir=output_dir, replay_cases=cases
    )
    matched = (report["cases"] == original["cases"]
               and report["summary"] == original["summary"]
               and report["errors"] == original["errors"])
    report["replay_verification"] = {
        "matched": matched, "saved_inputs_reexecuted": True,
        "original_cases_sha256": _sha(_encoded({"schema": "wolftrap.agent.saved-cases/v1", "cases": cases})),
    }
    if not matched:
        report["errors"].append({"code": "REPLAY_DIFFERED", "fail_closed": True})
        report["qualification"]["status"] = "ERROR"
        code = 2
    _publish(Path(output_dir), report, cases)
    return report, code

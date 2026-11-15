"""Bounded, offline inspection of local CI and container build definitions.

The scanner does not run target code, contact a service, or prove exploitation.
Every static signal requires human verification before a vulnerability claim.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .report import _atomic_write, write_json_report

MAX_WORKFLOWS = 64
MAX_WORKFLOW_DIRECTORY_ENTRIES = 256
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024
REPORT_NAME = "build-scan.json"
SARIF_NAME = "build-scan.sarif"
MARKDOWN_NAME = "build-scan.md"
MANIFEST_NAME = "build-scan.manifest.json"

RULES = {
    "WT-GHA-001": (
        "Privileged pull-request execution chain",
        "A privileged pull-request workflow checks out untrusted code and executes it.",
        "Separate privileged metadata handling from untrusted execution; minimize token permissions.",
    ),
    "WT-GHA-002": (
        "Untrusted expression interpolated into a shell script",
        "A potentially attacker-controlled event or free-form dispatch value enters a run script.",
        "Pass the value through an environment variable and validate it as data.",
    ),
    "WT-GHA-003": (
        "Mutable action reference",
        "An external action is not pinned to a full commit SHA.",
        "Pin reviewed actions to complete 40-character commit SHAs.",
    ),
    "WT-GHA-004": (
        "Workflow token permissions unknown",
        "Token privileges cannot be established from this workflow alone.",
        "Declare minimum workflow and job permissions explicitly.",
    ),
    "WT-GHA-005": (
        "Privileged artifact trust chain",
        "A workflow-run job downloads untrusted artifacts with write-capable authority.",
        "Treat cross-workflow artifacts as untrusted and avoid privileged consumption.",
    ),
    "WT-GHA-006": (
        "Pull-request artifact crosses a privileged workflow boundary",
        "A pull-request workflow can upload an artifact later downloaded from that run by a write-capable workflow.",
        "Validate the artifact's provenance and content before any privileged use; isolate PR build data from credentials and write tokens.",
    ),
    "WT-GHA-007": (
        "Pull-request execution on an explicitly self-hosted runner",
        "A pull-request-triggered job selects a self-hosted runner whose isolation and lifetime cannot be established from the workflow.",
        "Avoid PR-controlled jobs on persistent self-hosted runners; use isolated ephemeral runners and restrictive approval policies.",
    ),
    "WT-DOCKER-001": (
        "Base image not pinned by digest",
        "A tag-only base image can resolve to different bytes in a future build.",
        "Consider immutable digests and an explicit security-update process.",
    ),
    "WT-DOCKER-002": (
        "Remotely fetched build script executed",
        "A container build step pipes remotely obtained content to a shell.",
        "Use reviewed artifacts with verified integrity before controlled execution.",
    ),
}


@dataclass(frozen=True)
class BuildScanOutcome:
    report: dict[str, Any]
    exit_code: int


class UnscannableInput(ValueError):
    """Input outside supported inspection constraints."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value: Any, *, pretty: bool = True) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            indent=2 if pretty else None,
            separators=None if pretty else (",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _line(text: str, needle: str) -> int:
    for number, value in enumerate(text.splitlines(), 1):
        if needle.lower() in value.lower():
            return number
    return 1


def _factor(name: str, path: str, line: int) -> dict[str, Any]:
    return {"condition": name, "path": path, "line": line}


def _finding(
    rule_id: str,
    path: str,
    line: int,
    factors: list[dict[str, Any]],
    *,
    severity: str,
    trace: dict[str, Any] | None = None,
) -> dict[str, Any]:
    title, explanation, mitigation = RULES[rule_id]
    identity = {"rule": rule_id, "path": path, "factors": factors}
    if trace is not None:
        identity["trace"] = trace
    stable = _sha(_json_bytes(identity, pretty=False))
    optional_write = rule_id in {"WT-GHA-001", "WT-GHA-002"}
    counterfactuals = []
    if len(factors) > 1:
        for factor in factors:
            still_matches = optional_write and factor["condition"] == "write_capable_token"
            counterfactuals.append({
                "remove_condition": factor["condition"],
                "rule_still_matches": still_matches,
                "risk_after_removal": "MEDIUM_REVIEW" if still_matches else "NOT_DETECTED_IN_CURRENT_MODEL",
                "limitation": "Removing a detector factor is not proof that the build is secure.",
            })
    result = {
        "id": "WT-BUILD-" + stable[:20].upper(),
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "classification": "REVIEW_REQUIRED",
        "confidence": "CONDITIONAL_STATIC",
        "path": path,
        "line": line,
        "explanation": explanation,
        "mitigation": mitigation,
        "factors": factors,
        "counterfactuals": counterfactuals,
    }
    if trace is not None:
        result["trace"] = trace
    return result


def _yaml_document(text: str, *, with_nodes: bool = False) -> Any:
    try:
        import yaml
    except ImportError as exc:
        raise UnscannableInput("YAML parser unavailable; install the build-scan extra") from exc

    class BoundedLoader(yaml.BaseLoader):
        nodes = 0

        def compose_node(self, parent: Any, index: Any) -> Any:
            if self.check_event(yaml.AliasEvent):
                raise yaml.YAMLError("aliases disabled")
            self.nodes += 1
            if self.nodes > 4096:
                raise yaml.YAMLError("node count exceeded")
            return super().compose_node(parent, index)

        def construct_mapping(self, node: Any, deep: bool = False) -> dict[str, Any]:
            keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
            if (
                any(not isinstance(key, str) for key in keys)
                or len(set(keys)) != len(keys)
                or "<<" in keys
            ):
                raise yaml.YAMLError("duplicate, merge, or non-string workflow keys")
            return super().construct_mapping(node, deep=deep)

    loader = BoundedLoader(text)
    try:
        root_node = loader.get_single_node()
        document = loader.construct_document(root_node) if root_node is not None else None
    except yaml.YAMLError as exc:
        raise UnscannableInput("malformed or unsupported workflow YAML") from exc
    finally:
        loader.dispose()
    if not isinstance(document, dict) or "<<" in document:
        raise UnscannableInput("workflow mapping missing or merge keys unsupported")
    return (document, root_node) if with_nodes else document


def _workflow_locations(root_node: Any) -> tuple[dict[str, int], dict[tuple[str, int], int]]:
    """Use YAML scalar source marks, never first-occurrence text search.

    Distinguishes identical action references in separate jobs and ignores
    comments or similar values in unrelated YAML fields.
    """
    from yaml.nodes import MappingNode, ScalarNode, SequenceNode

    def child(node: Any, key: str) -> Any:
        if not isinstance(node, MappingNode):
            return None
        for name, value in node.value:
            if isinstance(name, ScalarNode) and name.value == key:
                return value
        return None

    jobs_node = child(root_node, "jobs")
    if not isinstance(jobs_node, MappingNode):
        raise UnscannableInput("workflow YAML source positions unavailable")
    job_lines: dict[str, int] = {}
    uses_lines: dict[tuple[str, int], int] = {}
    for name, job in jobs_node.value:
        if not isinstance(name, ScalarNode):
            raise UnscannableInput("workflow YAML job position unavailable")
        job_lines[name.value] = name.start_mark.line + 1
        steps = child(job, "steps")
        if steps is None:
            continue
        if not isinstance(steps, SequenceNode):
            raise UnscannableInput("workflow YAML steps position unavailable")
        for index, step in enumerate(steps.value):
            uses = child(step, "uses")
            if uses is not None:
                if not isinstance(uses, ScalarNode):
                    raise UnscannableInput("workflow YAML action position unavailable")
                uses_lines[name.value, index] = uses.start_mark.line + 1
    return job_lines, uses_lines


def _triggers(value: Any) -> set[str]:
    if isinstance(value, str) and value:
        return {value}
    if isinstance(value, list) and value and all(isinstance(item, str) and item for item in value):
        return set(value)
    if isinstance(value, dict) and value:
        return set(value)
    raise UnscannableInput("missing or unsupported workflow triggers")


def _writable(permissions: Any) -> bool:
    if permissions == "write-all":
        return True
    if permissions == "read-all":
        return False
    if isinstance(permissions, dict) and all(value in {"none", "read", "write"} for value in permissions.values()):
        return any(value == "write" for value in permissions.values())
    raise UnscannableInput("token permission semantics are unsupported")


def _self_hosted_runner(runs_on: Any) -> bool:
    """Recognize explicit self-hosted labels; reject dynamic PR job selectors.

    Custom runner names and runner groups cannot be attributed from local YAML.
    Their absence from findings must not be treated as proof of hosted isolation.
    """
    labels = runs_on.get("labels") if isinstance(runs_on, dict) else runs_on
    if labels is None:
        return False
    values = [labels] if isinstance(labels, str) else labels
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise UnscannableInput("pull-request runner label selector is unsupported")
    if any(value.strip().lower() == "self-hosted" for value in values):
        return True
    if any("${{" in value for value in values):
        raise UnscannableInput("pull-request runner label expression is unresolved")
    return False


def _untrusted_checkout(value: str) -> bool:
    return any(term in value.lower() for term in (
        "pull_request.head.sha",
        "pull_request.head.ref",
        "pull_request.head.repo",
        "github.head_ref",
        "refs/pull/",
    ))


def _executes_source(run: str) -> bool:
    return bool(re.search(
        r"(?i)(?:^|[\s;&|])(?:make|npm|pnpm|yarn|cargo|mvn|gradle|pytest|tox|python|bash|sh|go|\.\/)\b",
        run,
    ))


def _risky_expressions(run: str, free_form: set[str]) -> list[str]:
    expressions = re.findall(r"\x24\{\{\s*([^}]+?)\s*\}\}", run)
    event_markers = (
        "github.event.pull_request.title",
        "github.event.pull_request.body",
        "github.event.pull_request.head.ref",
        "github.event.issue.title",
        "github.event.issue.body",
        "github.event.comment.body",
        "github.head_ref",
    )
    results = []
    for expression in expressions:
        value = expression.strip().lower()
        if any(marker in value for marker in event_markers):
            results.append(expression.strip())
        if any(re.search(rf"\binputs\.{re.escape(name)}\b", value) for name in free_form):
            results.append(expression.strip())
    return sorted(set(results))


def _scan_workflow(path: str, text: str) -> list[dict[str, Any]]:
    document, root_node = _yaml_document(text, with_nodes=True)
    job_lines, uses_lines = _workflow_locations(root_node)
    triggers = _triggers(document.get("on"))
    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise UnscannableInput("missing or unsupported workflow jobs")
    dispatch = document.get("on", {}).get("workflow_dispatch") if isinstance(document.get("on"), dict) else None
    free_form: set[str] = set()
    if isinstance(dispatch, dict) and isinstance(dispatch.get("inputs", {}), dict):
        free_form = {
            name.lower()
            for name, details in dispatch.get("inputs", {}).items()
            if isinstance(name, str)
            and isinstance(details, dict)
            and details.get("type", "string") == "string"
        }

    findings: list[dict[str, Any]] = []
    for job_name, job in sorted(jobs.items()):
        if not isinstance(job, dict):
            raise UnscannableInput("unsupported workflow job shape")
        if triggers.intersection({"pull_request", "pull_request_target"}) and _self_hosted_runner(job.get("runs-on")):
            trigger = "pull_request_target" if "pull_request_target" in triggers else "pull_request"
            runner_line = _line(text, "self-hosted")
            findings.append(_finding(
                "WT-GHA-007", path, runner_line,
                [
                    _factor("pull_request_trigger", path, _line(text, trigger)),
                    _factor("explicit_self_hosted_runner", path, runner_line),
                ],
                severity="HIGH",
            ))
        steps = job.get("steps")
        if not isinstance(steps, list):
            raise UnscannableInput("reusable-workflow jobs require separate analysis")
        permissions = job.get("permissions", document.get("permissions"))
        writable = _writable(permissions) if permissions is not None else False
        if permissions is None:
            line = job_lines[str(job_name)]
            findings.append(_finding(
                "WT-GHA-004", path, line,
                [_factor("unknown_token_permissions", path, line)],
                severity="MEDIUM",
            ))

        untrusted_checkout_at: int | None = None
        untrusted_checkout_line = 1
        execution_line: int | None = None
        downloads_artifacts = False
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise UnscannableInput("unsupported workflow step shape")
            uses = step.get("uses", "")
            run = step.get("run", "")
            if not isinstance(uses, str) or not isinstance(run, str):
                raise UnscannableInput("unsupported action or run value")
            if uses and not uses.startswith("./"):
                if uses.startswith("docker://"):
                    pinned = bool(re.search(r"@sha256:[0-9a-fA-F]{64}$", uses))
                else:
                    pinned = bool(re.fullmatch(
                        r"[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_./-]+)?@[0-9a-fA-F]{40}",
                        uses,
                    ))
                if not pinned:
                    line = uses_lines.get((str(job_name), index))
                    if line is None:
                        raise UnscannableInput("workflow action source position unavailable")
                    findings.append(_finding(
                        "WT-GHA-003", path, line,
                        [_factor("mutable_action_ref", path, line)],
                        severity="MEDIUM",
                    ))
            if "actions/checkout@" in uses.lower():
                params = step.get("with", {})
                if not isinstance(params, dict):
                    raise UnscannableInput("unsupported checkout input shape")
                ref = str(params.get("ref", ""))
                repo = str(params.get("repository", ""))
                if _untrusted_checkout(ref) or _untrusted_checkout(repo):
                    untrusted_checkout_at = index
                    untrusted_checkout_line = _line(text, ref if _untrusted_checkout(ref) else repo)
            if "actions/download-artifact@" in uses.lower():
                downloads_artifacts = True
            if run:
                for expression in _risky_expressions(run, free_form):
                    line = _line(text, expression)
                    factors = [_factor("untrusted_expression_in_run_script", path, line)]
                    if writable:
                        factors.append(_factor("write_capable_token", path, _line(text, "permissions:")))
                    findings.append(_finding(
                        "WT-GHA-002", path, line, factors,
                        severity="HIGH" if writable else "MEDIUM",
                    ))
                if untrusted_checkout_at is not None and index > untrusted_checkout_at and _executes_source(run):
                    execution_line = _line(text, run.splitlines()[0].strip())

        if "pull_request_target" in triggers and untrusted_checkout_at is not None and execution_line is not None:
            factors = [
                _factor("privileged_pr_trigger", path, _line(text, "pull_request_target")),
                _factor("untrusted_head_checkout", path, untrusted_checkout_line),
                _factor("untrusted_code_execution", path, execution_line),
            ]
            if writable:
                factors.append(_factor("write_capable_token", path, _line(text, "permissions:")))
            findings.append(_finding(
                "WT-GHA-001", path, untrusted_checkout_line, factors,
                severity="HIGH" if writable else "MEDIUM",
            ))
        if "workflow_run" in triggers and downloads_artifacts and writable:
            factors = [
                _factor("cross_workflow_artifact_trigger", path, _line(text, "workflow_run")),
                _factor("artifact_download", path, _line(text, "actions/download-artifact@")),
                _factor("write_capable_token", path, _line(text, "permissions:")),
            ]
            findings.append(_finding(
                "WT-GHA-005", path, _line(text, "workflow_run"), factors,
                severity="MEDIUM",
            ))
    return findings


def _workflow_names(value: Any) -> tuple[str, ...]:
    """Extract exact workflow_run names, without guessing expression semantics."""
    if not isinstance(value, dict):
        raise UnscannableInput("workflow_run dependency names are unavailable")
    names = value.get("workflows")
    if isinstance(names, str):
        names = [names]
    if (
        not isinstance(names, list) or not names
        or any(not isinstance(name, str) or not name or "${{" in name for name in names)
    ):
        raise UnscannableInput("workflow_run dependency names are ambiguous")
    return tuple(names)


def _artifact_name(value: Any, *, default: str) -> str:
    if value is None:
        return default
    if not isinstance(value, str) or not value or "${{" in value:
        raise UnscannableInput("dynamic artifact name prevents deterministic path correlation")
    return value


def _pr_event_excluded(guard: Any) -> bool:
    """Only recognize two unambiguous whole-expression upstream event guards."""
    if not isinstance(guard, str):
        return False
    value = guard.strip()
    if value.startswith("${{") and value.endswith("}}"):
        value = value[3:-2].strip()
    return bool(re.fullmatch(
        r"github\.event\.workflow_run\.event\s*(?:!=\s*['\"]pull_request['\"]|==\s*['\"]push['\"])",
        value,
    ))


def _downloaded_code_executed(run: str, destination: str) -> bool:
    """Look for a direct script invocation *inside* a bounded downloaded directory.

    No shell is evaluated. An indirect execution or data-only consumer may be
    missed: a MEDIUM artifact-boundary signal is retained for such paths.
    """
    if not destination or destination in {".", "./"}:
        return False
    folder = destination.removeprefix("./").strip("/")
    if not folder or ".." in folder.split("/") or "${{" in folder:
        return False
    prefix = re.escape(folder) + r"/[A-Za-z0-9_./-]+"
    # Common interpreter flags and the `env` launcher should not hide a direct
    # invocation. Deliberately bounded: no shell expansion, pipelines or `-c`
    # evaluation. An unsupported invocation retains the MEDIUM review signal.
    interpreter = r"(?:bash|sh|python3?|node)"
    flags = r"(?:\s+(?:-[A-Za-z]{1,8}|--[a-z][a-z0-9-]{0,40})){0,3}"
    shell_invocation = rf"(?:env\s+)?{interpreter}{flags}\s+(?:\./)?{prefix}"
    source_invocation = rf"(?:source|\.)\s+(?:\./)?{prefix}"
    direct_invocation = rf"\./{prefix}"
    return bool(re.search(
        rf"(?m)(?:^|[;&|]\s*)(?:{shell_invocation}|{source_invocation}|{direct_invocation})(?=\s|$|[;&|])",
        run,
    ))


def _cross_workflow_artifact_paths(workflows: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Join exact named PR producers to write-capable artifact consumers.

    Correlation is deliberately finite: local workflows, explicit workflow
    names, GitHub's download-artifact run-id, and same-job use. Missing or
    unsupported linkage is never presented as an exploit or a complete audit.
    """
    parsed = [(path, text, _yaml_document(text)) for path, text in workflows]
    producers: dict[str, list[tuple[str, str, dict[str, Any]]]] = {}
    for path, text, document in parsed:
        name = document.get("name")
        if not isinstance(name, str) or not name or "${{" in name:
            continue
        if "pull_request" in _triggers(document.get("on")):
            producers.setdefault(name, []).append((path, text, document))

    findings: list[dict[str, Any]] = []
    for consumer_path, consumer_text, document in parsed:
        on = document.get("on")
        if "workflow_run" not in _triggers(on):
            continue
        jobs = document["jobs"]  # already schema-validated by _scan_workflow
        for job in jobs.values():
            if _pr_event_excluded(job.get("if")):
                continue
            permissions = job.get("permissions", document.get("permissions"))
            if permissions is None or not _writable(permissions):
                continue  # existing WT-GHA-004 handles unknown permission defaults
            steps = job["steps"]
            for index, step in enumerate(steps):
                uses = step.get("uses", "")
                if not uses.lower().startswith("actions/download-artifact@") or _pr_event_excluded(step.get("if")):
                    continue
                options = step.get("with", {})
                if not isinstance(options, dict):
                    raise UnscannableInput("artifact download inputs are unsupported")
                run_id = options.get("run-id")
                if not isinstance(run_id, str) or not re.fullmatch(
                    r"\$\{\{\s*github\.event\.workflow_run\.id\s*\}\}", run_id,
                ):
                    continue  # default run-id is *this* run, not the producer
                if not isinstance(options.get("github-token"), str) or not options["github-token"].strip():
                    continue
                repository = options.get("repository")
                if repository not in (None, "${{ github.repository }}"):
                    raise UnscannableInput("cross-repository artifact origin is outside scope")

                wanted = _artifact_name(options.get("name"), default="*")
                destination = options.get("path", ".")
                if not isinstance(destination, str):
                    raise UnscannableInput("artifact download path is unsupported")
                upstream_names = _workflow_names(on["workflow_run"])
                for upstream in upstream_names:
                    candidates = producers.get(upstream, [])
                    if len(candidates) > 1:
                        raise UnscannableInput("duplicate pull-request workflow names prevent unambiguous attribution")
                    if not candidates:
                        continue
                    producer_path, producer_text, producer = candidates[0]
                    for source_job in producer["jobs"].values():
                        for upload_step in source_job["steps"]:
                            upload_use = upload_step.get("uses", "")
                            if not upload_use.lower().startswith("actions/upload-artifact@"):
                                continue
                            upload_options = upload_step.get("with", {})
                            if not isinstance(upload_options, dict):
                                raise UnscannableInput("artifact upload inputs are unsupported")
                            upload_name = _artifact_name(upload_options.get("name"), default="artifact")
                            if wanted != "*" and wanted != upload_name:
                                continue
                            if not isinstance(upload_options.get("path"), str) or not upload_options["path"]:
                                continue  # no evidence that the upload would contain files

                            direct_run = next((
                                candidate["run"] for candidate in steps[index + 1:]
                                if isinstance(candidate.get("run"), str)
                                and _downloaded_code_executed(candidate["run"], destination)
                            ), None)
                            consumer_line = _line(consumer_text, uses)
                            producer_line = _line(producer_text, upload_use)
                            factors = [
                                _factor("pull_request_origin", producer_path, _line(producer_text, "pull_request")),
                                _factor("named_artifact_upload", producer_path, producer_line),
                                _factor("workflow_run_name_link", consumer_path, _line(consumer_text, "workflow_run")),
                                _factor("triggering_run_artifact_download", consumer_path, consumer_line),
                                _factor("write_capable_token", consumer_path, _line(consumer_text, "permissions:")),
                            ]
                            if direct_run is not None:
                                factors.append(_factor(
                                    "subsequent_downloaded_script_execution",
                                    consumer_path, _line(consumer_text, direct_run.splitlines()[0].strip()),
                                ))
                            trace = {
                                "producer_workflow": producer_path,
                                "consumer_workflow": consumer_path,
                                "artifact_name_sha256": _sha(upload_name.encode("utf-8")),
                                "direct_script_execution_detected": direct_run is not None,
                            }
                            findings.append(_finding(
                                "WT-GHA-006", consumer_path, consumer_line, factors,
                                severity="HIGH" if direct_run is not None else "MEDIUM",
                                trace=trace,
                            ))
    return findings


def _scan_container(path: str, text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    instructions: list[tuple[int, str]] = []
    pending = ""
    start_line = 1
    for number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not pending:
            start_line = number
        pending += " " + line.rstrip("\\").strip()
        if line.endswith("\\"):
            continue
        instructions.append((start_line, pending.strip()))
        pending = ""
    if pending:
        instructions.append((start_line, pending.strip()))
    for number, instruction in instructions:
        upper = instruction.upper()
        if upper.startswith("FROM "):
            parts = instruction.split()
            base_index = 2 if len(parts) > 2 and parts[1].startswith("--platform=") else 1
            if len(parts) <= base_index:
                raise UnscannableInput("incomplete container base instruction")
            image = parts[base_index]
            if image.lower() != "scratch" and not re.search(r"@sha256:[a-fA-F0-9]{64}$", image):
                findings.append(_finding(
                    "WT-DOCKER-001", path, number,
                    [_factor("tag_only_image", path, number)],
                    severity="LOW",
                ))
        elif upper.startswith("RUN ") and re.search(
            r"(?i)\b(?:curl|wget)\b[^|;\n]{0,400}\|\s*(?:sh|bash)\b",
            instruction,
        ):
            findings.append(_finding(
                "WT-DOCKER-002", path, number,
                [
                    _factor("remote_fetch", path, number),
                    _factor("immediate_shell_execution", path, number),
                ],
                severity="HIGH",
            ))
    return findings


def _source_files(root: Path) -> list[Path]:
    directory = root / ".github" / "workflows"
    for node in (root / ".github", directory):
        if node.is_symlink():
            raise UnscannableInput("workflow path includes a symlink")
    sources: list[Path] = []
    if directory.exists():
        if not directory.is_dir():
            raise UnscannableInput("workflow path is not a directory")
        entries: list[Path] = []
        for number, item in enumerate(directory.iterdir(), 1):
            if number > MAX_WORKFLOW_DIRECTORY_ENTRIES:
                raise UnscannableInput("workflow directory contains too many entries")
            entries.append(item)
        for item in sorted(entries):
            if item.is_dir():
                raise UnscannableInput("nested workflow directories are outside scope")
            if item.suffix.lower() in (".yml", ".yaml"):
                sources.append(item)
        if len(sources) > MAX_WORKFLOWS:
            raise UnscannableInput("too many workflows to inspect within bounded scope")
    for name in ("Dockerfile", "Containerfile"):
        file = root / name
        if file.exists() or file.is_symlink():
            sources.append(file)
    return sources


def _read_bounded_regular_file(path: Path) -> bytes:
    """No symlink-following final component; never read beyond the file bound."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise UnscannableInput("supported build input is not a regular file")
            if metadata.st_size > MAX_FILE_BYTES:
                raise UnscannableInput("a supported build file exceeded the per-file bound")
            raw = handle.read(MAX_FILE_BYTES + 1)
    except OSError as exc:
        raise UnscannableInput("supported build input could not be safely read") from exc
    if len(raw) > MAX_FILE_BYTES:
        raise UnscannableInput("a supported build file changed or exceeded its bound")
    return raw


def _markdown(report: dict[str, Any]) -> str:
    lines = [
        "# WolfTrap Stage 3: local build inspection",
        "",
        "> Read-only static triage. A finding is not a confirmed exploit; absence of",
        "> pattern matches is not evidence that a build is secure.",
        "",
        "Status: **" + report["qualification"]["status"] + "**",
        "Supported files inspected: " + str(report["summary"]["files_inspected"]),
        "Review-required findings: " + str(report["summary"]["findings"]),
        "Unknown inputs: " + str(report["summary"]["errors"]),
        "",
        "## Findings",
        "",
    ]
    for item in report["findings"]:
        lines.extend([
            "### " + item["rule_id"] + " — " + item["title"],
            "",
            "- Location: " + item["path"] + ":" + str(item["line"]),
            "- Severity: " + item["severity"] + " (conditional static)",
            "- Contributing factors: " + ", ".join(factor["condition"] for factor in item["factors"]),
            "- Recommendation: " + item["mitigation"],
            "",
        ])
    if not report["findings"]:
        lines.append("No supported static patterns matched. This is not a security certification.")
    if report["errors"]:
        lines.extend(["", "## Unknown or unsupported inputs", ""])
        lines.extend("- " + error for error in report["errors"])
    return "\n".join(lines) + "\n"


def _sarif(report: dict[str, Any]) -> dict[str, Any]:
    levels = {"HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "WolfTrap",
                "version": "0.1.0",
                "informationUri": "https://github.com/GovernableIntelligence/WolfTrap",
                "rules": [
                    {
                        "id": rule_id,
                        "shortDescription": {"text": title},
                        "fullDescription": {"text": explanation},
                    }
                    for rule_id, (title, explanation, _) in sorted(RULES.items())
                ],
            }},
            "results": [
                {
                    "ruleId": finding["rule_id"],
                    "level": levels[finding["severity"]],
                    "message": {"text": finding["explanation"] + " Human review is required."},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding["path"]},
                            "region": {"startLine": finding["line"]},
                        }
                    }],
                    "properties": {
                        "id": finding["id"],
                        "classification": finding["classification"],
                        "confidence": finding["confidence"],
                        "factors": [item["condition"] for item in finding["factors"]],
                    },
                }
                for finding in report["findings"]
            ],
        }],
    }


def scan_build(root: str | Path, output_dir: str | Path) -> BuildScanOutcome:
    """Read only supported local build definitions; write evidence *outside* root."""
    source_root = Path(root)
    output_root = Path(output_dir)
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError("scan root must be an existing non-symlink directory")
    source_root = source_root.resolve(strict=True)
    if output_root.is_symlink():
        raise ValueError("scan evidence output cannot be a symlink")
    resolved_output = output_root.resolve(strict=False)
    if resolved_output == source_root or resolved_output.is_relative_to(source_root):
        raise ValueError("scan evidence output must remain outside the inspected source")
    if output_root.exists() and (not output_root.is_dir() or any(output_root.iterdir())):
        raise ValueError("scan evidence output must be empty")
    output_root.mkdir(parents=True, exist_ok=True)
    write_json_report({"state": "INCOMPLETE", "stage3_schema_version": "1.0"}, output_root / MANIFEST_NAME)

    input_files: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: list[str] = []
    workflow_inputs: list[tuple[str, str]] = []
    total_bytes = 0
    try:
        for file in _source_files(source_root):
            relative = file.relative_to(source_root).as_posix()
            if file.is_symlink() or not file.is_file():
                raise UnscannableInput("supported build input is not a regular file")
            raw = _read_bounded_regular_file(file)
            total_bytes += len(raw)
            if total_bytes > MAX_TOTAL_BYTES:
                raise UnscannableInput("the aggregate build input exceeded the size bound")
            try:
                text = raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise UnscannableInput("supported build input is not UTF-8") from exc
            input_files.append({"path": relative, "bytes": len(raw), "sha256": _sha(raw)})
            if file.suffix.lower() in (".yml", ".yaml"):
                findings.extend(_scan_workflow(relative, text))
                workflow_inputs.append((relative, text))
            else:
                findings.extend(_scan_container(relative, text))
        findings.extend(_cross_workflow_artifact_paths(workflow_inputs))
        if not input_files:
            errors.append("No supported CI workflows or container build definitions found.")
    except UnscannableInput as exc:
        errors.append(str(exc))

    unique = {item["id"]: item for item in findings}
    findings = sorted(unique.values(), key=lambda item: (item["path"], item["line"], item["rule_id"]))
    status, code = (
        ("INCONCLUSIVE", 2) if errors
        else ("REVIEW_REQUIRED", 1) if findings
        else ("NO_PATTERN_MATCH", 0)
    )
    source_digest = _sha(_json_bytes(input_files, pretty=False))
    report = {
        "stage3_schema_version": "1.0",
        "purpose": "bounded read-only build configuration triage",
        "target_label": source_root.name,
        "target_code_executed": False,
        "external_systems_contacted": False,
        "model_used": False,
        "qualification": {
            "status": status,
            "complete_input": not errors,
            "confirmed_vulnerabilities": 0,
            "limited_not_exhaustive": True,
        },
        "coverage": {
            "supported": ["GitHub Actions YAML", "root Dockerfile", "root Containerfile"],
            "input_files": input_files,
            "input_digest": source_digest,
        },
        "summary": {"files_inspected": len(input_files), "findings": len(findings), "errors": len(errors)},
        "findings": findings,
        "errors": errors,
    }
    rendered = {
        REPORT_NAME: _json_bytes(report),
        SARIF_NAME: _json_bytes(_sarif(report)),
        MARKDOWN_NAME: _markdown(report).encode("utf-8"),
    }
    for name, content in rendered.items():
        _atomic_write(output_root / name, content.decode("utf-8"))
    write_json_report({
        "stage3_schema_version": "1.0",
        "state": "COMPLETE",
        "qualification_status": status,
        "input_digest": source_digest,
        "files": {
            name: {"bytes": len(data), "sha256": _sha(data)}
            for name, data in sorted(rendered.items())
        },
    }, output_root / MANIFEST_NAME)
    return BuildScanOutcome(report=report, exit_code=code)

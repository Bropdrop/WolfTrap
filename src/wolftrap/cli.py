"""Bounded command-line interface for WolfTrap synthetic research."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Mapping

from .execution import execute_case
from .model import ExperimentCase
from .report import (
    REPORT_MANIFEST_NAME,
    validate_report_pair,
    write_json_report,
    write_report_pair,
)
from .revision import capture_source_revision
from .runner import RunConfiguration, run_research
from .scenario import ScenarioValidationError, load_corpus
from .stage2 import STAGE2_MANIFEST, STAGE2_REPORT, Stage2Configuration, run_stage2
from .system import SYSTEMS


def _strict_json(path: Path) -> Any:
    def reject(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(path.read_text(encoding="utf-8"), parse_constant=reject)


def _unit_summary(
    path: str | None, current_revision: Mapping[str, Any]
) -> Mapping[str, Any] | None:
    if path is None:
        return None
    value = _strict_json(Path(path))
    if not isinstance(value, dict):
        raise ValueError("unit-test summary must be a JSON object")
    required = {"tests_run", "skipped", "failures", "errors", "successful"}
    if not required.issubset(value):
        raise ValueError("unit-test summary is missing required counts")
    for key in ("tests_run", "skipped", "failures", "errors"):
        if type(value[key]) is not int or value[key] < 0:
            raise ValueError(f"unit-test summary {key} must be non-negative")
    if value["tests_run"] < 1:
        raise ValueError("unit-test summary must contain at least one executed test")
    if value["failures"] or value["errors"] or value["successful"] is not True:
        raise ValueError("unit tests did not pass; research execution stopped safely")
    if (
        value.get("source_revision") != dict(current_revision)
        or value.get("source_revision_end") != dict(current_revision)
        or value.get("source_stable") is not True
    ):
        raise ValueError(
            "unit-test summary source revision does not match this research run"
        )
    return value


def _run(arguments: argparse.Namespace) -> int:
    revision = capture_source_revision()
    configuration = RunConfiguration(
        seed=arguments.seed,
        max_mutations=arguments.max_mutations,
        max_interactions=arguments.max_interactions,
        max_commands_per_case=arguments.max_commands_per_case,
        max_minimization_evaluations=arguments.max_minimization_evaluations,
        reproduction_attempts=arguments.reproduction_attempts,
        system_id=arguments.sut,
        scenario_ids=tuple(arguments.scenario or ()),
    )
    outcome = run_research(
        configuration,
        scenario_directory=arguments.scenario_directory,
        source_revision=revision,
        unit_test_summary=_unit_summary(
            arguments.unit_test_summary, revision.to_dict()
        ),
        reproduction_report_path=str(
            Path(arguments.output_dir) / "wolftrap-report.json"
        ),
    )
    json_path, markdown_path = write_report_pair(outcome.report, arguments.output_dir)
    summary = outcome.report["summary"]
    print(
        f"{outcome.report['qualification']['status']}: "
        f"{summary['cases_executed']}/{summary['cases_generated']} cases executed; "
        f"{summary['findings']} finding(s); {summary['internal_errors']} internal error(s)."
    )
    print(f"JSON: {json_path}")
    print(f"Markdown: {markdown_path}")
    print(f"Completion manifest: {Path(arguments.output_dir) / REPORT_MANIFEST_NAME}")
    return outcome.exit_code


def _list_scenarios(arguments: argparse.Namespace) -> int:
    scenarios = load_corpus(arguments.scenario_directory)
    if arguments.json:
        print(
            json.dumps(
                [
                    {
                        "scenario_id": item.scenario_id,
                        "version": item.scenario_version,
                        "category": item.category,
                        "title": item.title,
                        "definition_digest": item.definition_digest,
                    }
                    for item in scenarios
                ],
                sort_keys=True,
                indent=2,
            )
        )
    else:
        for item in scenarios:
            print(f"{item.scenario_id}\t{item.scenario_version}\t{item.title}")
    return 0


def _sweep(arguments: argparse.Namespace) -> int:
    """Run bounded, complete-pair synthetic campaigns without a model/API."""

    revision = capture_source_revision()
    outcome = run_stage2(
        Stage2Configuration(
            first_seed=arguments.seed,
            seed_count=arguments.seed_count,
            mutation_budget=arguments.mutation_budget,
            system_id=arguments.sut,
        ),
        output_dir=arguments.output_dir,
        unit_test_summary=_unit_summary(arguments.unit_test_summary, revision.to_dict()),
    )
    summary = outcome.report["summary"]
    pairs = outcome.report["pair_coverage"]
    print(
        f"{outcome.report['qualification']['status']}: "
        f"{summary['campaigns_executed']} seed(s), "
        f"{summary['cases_executed']} cases, "
        f"{pairs['unique_pairs_reached']}/{pairs['candidate_pairs']} scenario pairs, "
        f"{summary['findings']} synthetic finding(s)."
    )
    print(f"Summary: {Path(arguments.output_dir) / STAGE2_REPORT}")
    print(f"Completion manifest: {Path(arguments.output_dir) / STAGE2_MANIFEST}")
    return outcome.exit_code


def _reproduce(arguments: argparse.Namespace) -> int:
    if re.fullmatch(r"WOLFTRAP-F-[A-F0-9]{20}", arguments.finding_id) is None:
        raise ValueError("finding id has an invalid format")
    report = validate_report_pair(Path(arguments.report))
    if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
        raise ValueError("input is not a WolfTrap research report")
    matches = [
        item
        for item in report["findings"]
        if isinstance(item, dict) and item.get("finding_id") == arguments.finding_id
    ]
    if len(matches) != 1:
        raise ValueError("finding id must identify exactly one report finding")
    finding = matches[0]
    configuration = finding.get("test_configuration")
    if not isinstance(configuration, dict):
        raise ValueError("finding has no saved test configuration")
    saved_case = configuration.get("minimized_case")
    if not isinstance(saved_case, dict):
        raise ValueError("finding has no saved minimized case")
    case = ExperimentCase.from_dict(saved_case)
    expected_digest = configuration.get("minimized_case_digest")
    if case.digest != expected_digest:
        raise ValueError("saved minimized case digest does not match its evidence")
    system_id = str(configuration.get("system_id"))
    if system_id not in SYSTEMS:
        raise ValueError(f"saved finding names an unknown system: {system_id}")
    execution = execute_case(case, SYSTEMS[system_id])
    expected_fingerprint = finding["independent_effect_state_evidence"][
        "oracle_fingerprint"
    ]
    reproduced = (
        not execution.assessment.passed
        and execution.assessment.fingerprint == expected_fingerprint
    )
    current_revision = capture_source_revision()
    original_revision = finding.get("source_revision", {})
    source_matches = (
        isinstance(original_revision, dict)
        and original_revision.get("commit_sha") == current_revision.commit_sha
        and original_revision.get("tree_sha") == current_revision.tree_sha
        and original_revision.get("dirty") == current_revision.dirty
        and original_revision.get("diff_digest") == current_revision.diff_digest
    )
    result = {
        "reproduction_schema_version": "1.0",
        "finding_id": arguments.finding_id,
        "synthetic_only": True,
        "real_world_vulnerability_claim": False,
        "system_id": system_id,
        "saved_case_digest": expected_digest,
        "actual_case_digest": case.digest,
        "expected_oracle_fingerprint": expected_fingerprint,
        "actual_oracle_fingerprint": execution.assessment.fingerprint,
        "violation_reproduced": reproduced,
        "source_revision_matches": source_matches,
        "original_source_revision": original_revision,
        "current_source_revision": current_revision.to_dict(),
        "execution": execution.to_dict(include_trace=True),
    }
    output = Path(arguments.output_dir) / (
        f"wolftrap-reproduction-{arguments.finding_id}.json"
    )
    write_json_report(result, output)
    print(
        f"{'REPRODUCED' if reproduced else 'NOT_REPRODUCED'}: "
        f"{arguments.finding_id}; source match={source_matches}; evidence={output}"
    )
    if not source_matches:
        return 2
    return 1 if reproduced else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wolftrap",
        description=(
            "Bounded synthetic authorization adversarial research; no external targets."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run = subparsers.add_parser("run", help="run a bounded synthetic campaign")
    run.add_argument("--seed", type=int, default=20261113)
    run.add_argument("--max-mutations", type=int, default=32)
    run.add_argument("--max-interactions", type=int, default=8)
    run.add_argument("--max-commands-per-case", type=int, default=128)
    run.add_argument("--max-minimization-evaluations", type=int, default=64)
    run.add_argument("--reproduction-attempts", type=int, default=2)
    run.add_argument("--sut", choices=sorted(SYSTEMS), default="correct-v1")
    run.add_argument("--scenario", action="append")
    run.add_argument("--scenario-directory")
    run.add_argument("--unit-test-summary")
    run.add_argument("--output-dir", default="reports")
    run.set_defaults(handler=_run)

    sweep = subparsers.add_parser(
        "sweep", help="run autonomous full-pair synthetic research across bounded seeds"
    )
    sweep.add_argument("--seed", type=int, default=20261113)
    sweep.add_argument("--seed-count", type=int, default=3)
    sweep.add_argument("--mutation-budget", type=int, default=128)
    sweep.add_argument("--sut", choices=sorted(SYSTEMS), default="correct-v1")
    sweep.add_argument("--unit-test-summary")
    sweep.add_argument("--output-dir", default="reports/stage2")
    sweep.set_defaults(handler=_sweep)

    listing = subparsers.add_parser("list-scenarios", help="list local corpus entries")
    listing.add_argument("--scenario-directory")
    listing.add_argument("--json", action="store_true")
    listing.set_defaults(handler=_list_scenarios)

    reproduce = subparsers.add_parser(
        "reproduce", help="replay the exact minimized case saved with a finding"
    )
    reproduce.add_argument("--report", required=True)
    reproduce.add_argument("--finding-id", required=True)
    reproduce.add_argument("--output-dir", default="reports/reproduction")
    reproduce.set_defaults(handler=_reproduce)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        arguments = parser.parse_args(argv)
        return int(arguments.handler(arguments))
    except Exception as exc:
        print(f"wolftrap: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

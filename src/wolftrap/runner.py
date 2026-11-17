"""Bounded research campaign orchestration."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from platform import machine, python_implementation, python_version, system
from typing import Any, Mapping, Sequence

from .evidence import base_report_fields, build_finding, generated_at, stable_hash
from .execution import CaseExecution, execute_case
from .minimize import (
    MinimizationResult,
    minimize_counterexample,
    reproduce_counterexample,
)
from .model import ExperimentCase, FindingClassification, Scenario, scenario_to_case
from .revision import SourceRevision, capture_source_revision
from .scenario import load_corpus
from .system import SYSTEMS, CorrectSyntheticSystem
from .threat import (
    EXPECTED_FBI_TECHNIQUE_IDS,
    build_technique_evidence_matrix,
    load_technique_inventory,
)


@dataclass(frozen=True)
class RunConfiguration:
    seed: int = 20261113
    max_mutations: int = 32
    max_interactions: int = 8
    max_commands_per_case: int = 128
    max_minimization_evaluations: int = 64
    reproduction_attempts: int = 2
    system_id: str = "correct-v1"
    scenario_ids: tuple[str, ...] = ()

    def validate(self) -> None:
        if not 0 <= self.seed <= 9_223_372_036_854_775_807:
            raise ValueError("seed must be between 0 and 9223372036854775807")
        if not 32 <= self.max_mutations <= 256:
            raise ValueError("max_mutations must be between 32 and 256")
        if not 1 <= self.max_interactions <= 64:
            raise ValueError("max_interactions must be between 1 and 64")
        if not 16 <= self.max_commands_per_case <= 512:
            raise ValueError("max_commands_per_case must be between 16 and 512")
        if not 1 <= self.max_minimization_evaluations <= 256:
            raise ValueError("max_minimization_evaluations must be between 1 and 256")
        if not 2 <= self.reproduction_attempts <= 5:
            raise ValueError("reproduction_attempts must be between 2 and 5")
        if self.system_id not in SYSTEMS:
            raise ValueError(f"unknown synthetic system: {self.system_id}")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["scenario_ids"] = list(self.scenario_ids)
        return value


@dataclass(frozen=True)
class RunOutcome:
    report: dict[str, Any]
    exit_code: int


def _filter_scenarios(
    scenarios: Sequence[Scenario], selected: Sequence[str]
) -> list[Scenario]:
    if not selected:
        return list(scenarios)
    wanted = set(selected)
    available = {item.scenario_id for item in scenarios}
    missing = wanted - available
    if missing:
        raise ValueError(f"unknown scenario ids: {sorted(missing)}")
    return [item for item in scenarios if item.scenario_id in wanted]


def _validate_unit_test_summary(
    summary: Mapping[str, Any] | None, revision: SourceRevision
) -> bool:
    if summary is None:
        return False
    integer_fields = ("tests_run", "skipped", "failures", "errors")
    if any(type(summary.get(field)) is not int or summary[field] < 0 for field in integer_fields):
        raise ValueError("unit-test summary contains invalid counts")
    if (
        summary["tests_run"] < 1
        or summary["failures"] != 0
        or summary["errors"] != 0
        or summary.get("successful") is not True
        or summary.get("source_stable") is not True
        or summary.get("source_revision") != revision.to_dict()
        or summary.get("source_revision_end") != revision.to_dict()
    ):
        raise ValueError("unit-test summary does not prove a stable passing source revision")
    return True


def _explore(
    scenarios: Sequence[Scenario], configuration: RunConfiguration
) -> tuple[list[ExperimentCase], dict[str, Any]]:
    # Import here so schema-only callers do not initialize the generator.
    from .explorer import ExplorationBounds, explore

    bounds = ExplorationBounds(
        max_cases=len(scenarios) + configuration.max_mutations,
        max_interactions=configuration.max_interactions,
        max_commands_per_case=configuration.max_commands_per_case,
        max_schedules=max(5, min(32, configuration.max_mutations)),
        max_seeded_cases=configuration.max_mutations,
    )
    result = explore(tuple(scenarios), seed=configuration.seed, bounds=bounds)
    cases = list(result.cases)
    coverage = dict(result.coverage)
    return cases, coverage


def _select_primary(execution: CaseExecution):
    priorities = (
        "UNAUTHORIZED_EFFECT",
        "UNEXPECTED_EFFECT",
        "DUPLICATE",
        "POSITIVE_CONTROL",
        "MISSING_REQUIRED_EFFECT",
        "FINAL_LEDGER",
        "TASK_STATE_DIVERGENCE",
    )
    for prefix in priorities:
        for violation in execution.assessment.violations:
            if prefix in violation.code:
                return violation
    return execution.assessment.violations[0]


def _aggregate_coverage(
    cases: Sequence[ExperimentCase],
    executions: Sequence[CaseExecution],
    explorer_coverage: Mapping[str, Any],
) -> dict[str, Any]:
    commands = Counter(
        command.kind.value for case in cases for command in case.commands
    )
    phases: set[str] = set()
    denials: set[str] = set()
    effects_audited = 0
    invariant_evaluations = 0
    commands_evaluated = 0
    for execution in executions:
        item = execution.assessment.coverage
        phases.update(item.get("reference_phases_reached", ()))
        denials.update(item.get("reference_denial_reasons", ()))
        effects_audited += int(item.get("effects_audited", 0))
        invariant_evaluations += int(item.get("invariant_evaluations", 0))
        commands_evaluated += int(item.get("commands_evaluated", 0))
    known_axes = {
        "principal_identity",
        "permission_scope",
        "authorization_epoch",
        "operation_digest",
        "tool_arguments",
        "execution_ordering",
        "concurrent_requests",
        "revocation_timing",
        "simulated_crash",
        "retry_recovery",
        "scenario_composition",
    }
    axes = sorted(
        {
            label.removeprefix("axis:")
            for case in cases
            for label in case.mutation_labels
            if label.startswith("axis:") or label in known_axes
        }
    )
    depths = Counter(str(case.interaction_depth) for case in cases)
    relationships = Counter(
        reference.relationship
        for case in cases
        for reference in case.attack_references
    )
    generator_schedules = dict(explorer_coverage.get("schedules", {}))
    executed_schedule_labels = sorted(
        {
            label.removeprefix("schedule:")
            for case in cases
            for label in case.mutation_labels
            if label.startswith("schedule:")
        }
    )
    executed_crash_sites = sorted(
        {
            int(label.removeprefix("crash_site:"))
            for case in cases
            for label in case.mutation_labels
            if label.startswith("crash_site:")
        }
    )
    generator_interactions = dict(explorer_coverage.get("interactions", {}))
    executed_interactions = [case for case in cases if case.interaction_depth > 1]
    result = dict(explorer_coverage)
    result.update(
        {
            "scenario_ids": sorted(
                {scenario_id for case in cases for scenario_id in case.scenario_ids}
            ),
            "attack_techniques": sorted(
                {
                    reference.technique_id
                    for case in cases
                    for reference in case.attack_references
                }
            ),
            "attack_relationships": dict(sorted(relationships.items())),
            "mutation_axes": axes,
            "interaction_depths": dict(sorted(depths.items())),
            "command_kinds": dict(sorted(commands.items())),
            "commands_evaluated": commands_evaluated,
            "effects_audited": effects_audited,
            "invariant_evaluations": invariant_evaluations,
            "reference_phases_reached": sorted(phases),
            "reference_denial_reasons": sorted(denials),
            "schedules": {
                **generator_schedules,
                "executed": sum(
                    any(
                        label in {
                            "execution_ordering",
                            "concurrent_requests",
                            "revocation_timing",
                            "simulated_crash",
                            "retry_recovery",
                        }
                        or label.startswith("schedule:")
                        for label in case.mutation_labels
                    )
                    for case in cases
                ),
                "race_windows_reached": executed_schedule_labels,
                "crash_sites_reached": executed_crash_sites,
            },
            "interactions": {
                **generator_interactions,
                "executed": len(executed_interactions),
                "executed_pairs": [
                    list(case.scenario_ids) for case in executed_interactions
                ],
                "max_depth": max(
                    (case.interaction_depth for case in executed_interactions),
                    default=1,
                ),
            },
            "bounded_not_exhaustive": True,
            "truncated": bool(explorer_coverage.get("truncated", False)),
        }
    )
    return result


def _case_record(execution: CaseExecution) -> dict[str, Any]:
    return {
        "status": "PASS" if execution.assessment.passed else "FAIL",
        "scenario_ids": list(execution.case.scenario_ids),
        "scenario_versions": list(execution.case.scenario_versions),
        "control": execution.case.control,
        "mutation_labels": list(execution.case.mutation_labels),
        "interaction_depth": execution.case.interaction_depth,
        "case": execution.case.to_dict(),
        "execution": execution.to_dict(include_trace=True),
    }


def run_research(
    configuration: RunConfiguration,
    *,
    scenario_directory: str | Path | None = None,
    source_revision: SourceRevision | None = None,
    unit_test_summary: Mapping[str, Any] | None = None,
    reproduction_report_path: str = "reports/wolftrap-report.json",
) -> RunOutcome:
    configuration.validate()
    observed_start_revision = capture_source_revision()
    if source_revision is not None and source_revision != observed_start_revision:
        raise ValueError("supplied source revision does not match the working tree")
    revision = observed_start_revision
    unit_tests_valid = _validate_unit_test_summary(unit_test_summary, revision)
    loaded_corpus = load_corpus(scenario_directory)
    technique_inventory = load_technique_inventory(
        scenario_ids=(scenario.scenario_id for scenario in loaded_corpus)
    )
    scenarios = _filter_scenarios(loaded_corpus, configuration.scenario_ids)
    if configuration.scenario_ids:
        generated = [
            scenario_to_case(
                scenario,
                seed=int(
                    stable_hash(
                        {"seed": configuration.seed, "scenario": scenario.scenario_id}
                    )[:16],
                    16,
                ),
            )
            for scenario in scenarios
        ]
        explorer_coverage = {
            "engine": "targeted_baseline_only",
            "bounded_not_exhaustive": True,
            "truncated": True,
            "truncation_reasons": ["scenario_filter_disables_qualification_coverage"],
            "schedules": {
                "generated": 0,
                "race_windows_reached": [],
                "crash_sites_reached": [],
                "truncated": True,
            },
            "interactions": {"generated": 0, "max_depth": 1, "truncated": True},
        }
    else:
        generated, explorer_coverage = _explore(scenarios, configuration)
    baselines = [case for case in generated if case.mutation_labels == ("baseline",)]
    all_cases: list[ExperimentCase] = []
    seen_case_digests: set[str] = set()
    for case in generated:
        if len(case.commands) > configuration.max_commands_per_case:
            raise ValueError(
                f"case {case.case_id} exceeds max_commands_per_case"
            )
        if case.digest not in seen_case_digests:
            all_cases.append(case)
            seen_case_digests.add(case.digest)

    system_type: type[CorrectSyntheticSystem] = SYSTEMS[configuration.system_id]
    executions: list[CaseExecution] = []
    case_records: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    canonical_findings: dict[str, str] = {}
    attempted_cases = 0

    for index, case in enumerate(all_cases):
        attempted_cases += 1
        try:
            execution = execute_case(case, system_type)
            executions.append(execution)
            case_records.append(_case_record(execution))
            if execution.assessment.passed:
                continue
            target = execution.assessment.fingerprint
            original_recheck = reproduce_counterexample(
                case,
                system_type,
                target,
                attempts=configuration.reproduction_attempts,
            )
            if not all(item.reproduced for item in original_recheck):
                minimized = MinimizationResult(
                    original_case_id=case.case_id,
                    minimized_case=case,
                    target_fingerprint=target,
                    evaluations=1,
                    reduced_commands=0,
                    truncated=False,
                )
                reproductions = original_recheck
                classification = (
                    FindingClassification.NOT_REPRODUCED
                    if not any(item.reproduced for item in reproductions)
                    else FindingClassification.UNVERIFIED
                )
                evidence_execution = execution
            else:
                minimized = minimize_counterexample(
                    case,
                    system_type,
                    target,
                    max_evaluations=configuration.max_minimization_evaluations,
                )
                reproductions = reproduce_counterexample(
                    minimized.minimized_case,
                    system_type,
                    target,
                    attempts=configuration.reproduction_attempts,
                )
                classification = (
                    FindingClassification.CONFIRMED
                    if all(item.reproduced for item in reproductions)
                    else FindingClassification.UNVERIFIED
                )
                evidence_execution = execute_case(
                    minimized.minimized_case, system_type
                )
            violation = _select_primary(evidence_execution)
            duplicate_key = stable_hash(
                {
                    "invariant": violation.invariant,
                    "code": violation.code,
                    "minimized_case": minimized.minimized_case.digest,
                }
            )
            duplicate_of = canonical_findings.get(duplicate_key)
            if duplicate_of is not None and classification is FindingClassification.CONFIRMED:
                classification = FindingClassification.DUPLICATE
            finding = build_finding(
                violation=violation,
                original_execution=execution,
                evidence_execution=evidence_execution,
                minimized=minimized,
                reproductions=reproductions,
                classification=classification,
                source_revision=revision,
                campaign_seed=configuration.seed,
                run_configuration=configuration.to_dict(),
                reproduction_report_path=reproduction_report_path,
                duplicate_of=duplicate_of,
            )
            findings.append(finding)
            if duplicate_of is None and classification is FindingClassification.CONFIRMED:
                canonical_findings[duplicate_key] = finding["finding_id"]
        except Exception as exc:
            error_record = {
                    "case_index": index,
                    "case_id": case.case_id,
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                    "fail_closed": True,
                }
            partial_evidence = getattr(exc, "evidence", None)
            if partial_evidence is not None:
                error_record["partial_effect_evidence"] = partial_evidence
            errors.append(error_record)
            break

    observed_end_revision = capture_source_revision()
    if observed_end_revision != observed_start_revision:
        errors.append(
            {
                "case_index": len(executions),
                "case_id": "SOURCE-REVISION",
                "error_type": "SourceRevisionChanged",
                "message": "source revision changed during the research campaign",
                "fail_closed": True,
                "start": observed_start_revision.to_dict(),
                "end": observed_end_revision.to_dict(),
            }
        )

    executed_ids = {execution.case.case_id for execution in executions}
    baseline_positive = [
        case
        for case in baselines
        if case.control == "POSITIVE" and case.case_id in executed_ids
    ]
    passed_ids = {
        execution.case.case_id
        for execution in executions
        if execution.assessment.passed
    }
    positive_passed = sum(case.case_id in passed_ids for case in baseline_positive)
    positive_total = sum(case.control == "POSITIVE" for case in baselines)
    baseline_negative = [
        case
        for case in baselines
        if case.control == "NEGATIVE" and case.case_id in executed_ids
    ]
    negative_passed = sum(case.case_id in passed_ids for case in baseline_negative)
    negative_total = sum(case.control == "NEGATIVE" for case in baselines)
    baseline_mixed = [
        case
        for case in baselines
        if case.control == "MIXED" and case.case_id in executed_ids
    ]
    mixed_passed = sum(case.case_id in passed_ids for case in baseline_mixed)
    mixed_total = sum(case.control == "MIXED" for case in baselines)
    threat_baseline_total = negative_total + mixed_total
    threat_baseline_passed = negative_passed + mixed_passed
    cases_failed = sum(not item.assessment.passed for item in executions)
    cases_passed = len(executions) - cases_failed
    skipped = len(all_cases) - attempted_cases
    coverage = _aggregate_coverage(
        [execution.case for execution in executions], executions, explorer_coverage
    )
    required_scenarios = {
        "fbi-artex-positive-authorized-operation",
        "fbi-artex-identity-credential-substitution",
        "fbi-artex-privilege-escalation",
        "fbi-artex-supplier-origin-substitution",
        "fbi-artex-unauthorized-protected-resource",
        "fbi-artex-simulated-credential-persistence",
        "fbi-artex-revocation-expiry",
        "fbi-artex-concurrent-agents",
        "fbi-artex-replay-duplicate",
        "fbi-artex-unauthorized-transfer",
        "fbi-artex-delayed-crash-recovery",
    }
    required_axes = {
        "principal_identity",
        "permission_scope",
        "authorization_epoch",
        "operation_digest",
        "tool_arguments",
        "execution_ordering",
        "concurrent_requests",
        "revocation_timing",
        "simulated_crash",
        "retry_recovery",
    }
    schedule_coverage = coverage.get("schedules", {})
    required_race_windows = {
        "a-commit-first",
        "b-commit-first",
        "revoke-window-4",
        "recover-crash-site-4",
        "unknown-recovery",
    }
    coverage_gates = {
        "complete_fbi_corpus": required_scenarios.issubset(
            set(coverage.get("scenario_ids", ()))
        ),
        "all_mutation_axes": required_axes.issubset(
            set(coverage.get("mutation_axes", ()))
        ),
        "multi_stage_composition": int(
            coverage.get("interactions", {}).get("max_depth", 0)
        )
        >= 2,
        "required_race_windows": required_race_windows.issubset(
            set(schedule_coverage.get("race_windows_reached", ()))
        ),
        "crash_and_recovery_commands": {"CRASH", "RECOVER"}.issubset(
            set(coverage.get("command_kinds", {}))
        ),
        "positive_control": positive_total == 1 and positive_passed == 1,
        "negative_controls": negative_total >= 7
        and negative_passed == negative_total,
        "mixed_threat_controls": mixed_total >= 3 and mixed_passed == mixed_total,
        "all_threat_baselines": threat_baseline_total >= 10
        and threat_baseline_passed == threat_baseline_total,
        "complete_advisory_technique_inventory": (
            technique_inventory["technique_count"]
            == len(EXPECTED_FBI_TECHNIQUE_IDS)
        ),
        "unit_test_suite": unit_tests_valid,
    }
    coverage_qualified = all(coverage_gates.values())
    if errors:
        qualification_status = "ERROR"
        exit_code = 2
    elif findings or not coverage_qualified:
        qualification_status = "FAIL"
        exit_code = 1
    else:
        qualification_status = "PASS"
        exit_code = 0

    run_identity = {
        "revision": revision.to_dict(),
        "configuration": configuration.to_dict(),
        "case_digests": [case.digest for case in all_cases],
    }
    report = base_report_fields()
    report.update(
        {
            "run_id": "WOLFTRAP-R-" + stable_hash(run_identity)[:20].upper(),
            "generated_at": generated_at(),
            "source_revision": revision.to_dict(),
            "environment": {
                "python_implementation": python_implementation(),
                "python_version": python_version(),
                "operating_system": system(),
                "architecture": machine(),
            },
            "corpus": {
                "scenario_count": len(scenarios),
                "scenario_definition_digests": {
                    item.scenario_id: item.definition_digest for item in scenarios
                },
                "corpus_digest": "sha256:"
                + stable_hash(
                    [
                        [item.scenario_id, item.scenario_version, item.definition_digest]
                        for item in scenarios
                    ]
                ),
                "advisory_technique_inventory": technique_inventory,
                "advisory_technique_evidence": build_technique_evidence_matrix(
                    technique_inventory,
                    loaded_corpus,
                    baselines,
                    executions,
                    qualified=qualification_status == "PASS",
                ),
            },
            "configuration": configuration.to_dict(),
            "qualification": {
                "status": qualification_status,
                "positive_controls_total": positive_total,
                "positive_controls_passed": positive_passed,
                "negative_controls_total": negative_total,
                "negative_controls_passed": negative_passed,
                "mixed_threat_controls_total": mixed_total,
                "mixed_threat_controls_passed": mixed_passed,
                "threat_baselines_total": threat_baseline_total,
                "threat_baselines_passed": threat_baseline_passed,
                "coverage_gates": coverage_gates,
                "coverage_qualified": coverage_qualified,
                "deny_all_gate_semantics": (
                    "A positive control must independently commit exactly one effect."
                ),
                "oracle_independent_of_sut_policy": True,
                "bounded_not_exhaustive": True,
            },
            "summary": {
                "cases_generated": len(all_cases),
                "cases_attempted": attempted_cases,
                "cases_executed": len(executions),
                "cases_passed": cases_passed,
                "cases_failed": cases_failed,
                "cases_skipped": skipped,
                "internal_errors": len(errors),
                "findings": len(findings),
                "confirmed_findings": sum(
                    item["classification"] == "CONFIRMED" for item in findings
                ),
            },
            "unit_tests": dict(unit_test_summary)
            if unit_test_summary is not None
            else {
                "run_by_research_engine": False,
                "tests_run": None,
                "skipped": None,
                "failures": None,
                "errors": None,
            },
            "coverage": coverage,
            "cases": case_records,
            "findings": findings,
            "errors": errors,
            "lifecycle": {
                "DESIGNED": True,
                "IMPLEMENTED": True,
                "CHECKPOINTED": revision.commit_sha != "UNCOMMITTED" and not revision.dirty,
                "TESTED": unit_tests_valid and not errors,
                "LIVE VERIFIED": False,
                "REVIEWED": False,
                "MERGED": False,
                "DEPLOYED": False,
            },
        }
    )
    return RunOutcome(report=report, exit_code=exit_code)

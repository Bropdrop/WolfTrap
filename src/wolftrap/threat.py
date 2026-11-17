"""Pinned FBI advisory technique inventory and traceability validation."""

from __future__ import annotations

import json
from collections import defaultdict
from importlib.resources import files
from typing import Any, Iterable, Mapping

from .canonical import sha256_json
from .execution import CaseExecution
from .model import ExperimentCase, Scenario


_FBI_TABLE_BY_PDF_PAGE = {
    3: (
        "T1595", "T1580", "T1087.004", "T1069.003", "T1526",
        "T1190", "T1078", "T1133", "T1195", "T1199", "T1606.002",
        "T1552.001",
    ),
    4: (
        "T1505.003", "T1078.004", "T1098.001",
        "T1574.001", "T1036.005", "T1105", "T1059", "T1134.001",
        "T1098.003", "T1552.005", "T1606.002",
    ),
    5: (
        "T1606", "T1190", "T1558.003", "T1518.001",
        "T1555", "T1087.002", "T1552.006", "T1059.001", "T1550.003",
        "T1550.002", "T1021.006", "T1557.001", "T1114.002",
        "T1555.006", "T1530", "T1005", "T1074.001",
    ),
    6: ("T1074.002", "T1059", "T1090", "T1090.003", "T1572", "T1071.001"),
}
EXPECTED_FBI_TECHNIQUE_IDS = frozenset(
    technique_id
    for technique_ids in _FBI_TABLE_BY_PDF_PAGE.values()
    for technique_id in technique_ids
)


class ThreatInventoryError(ValueError):
    pass


def _reject_constant(value: str) -> None:
    raise ThreatInventoryError(f"non-finite JSON number: {value}")


def load_technique_inventory(
    *, scenario_ids: Iterable[str] | None = None
) -> dict[str, Any]:
    path = files("wolftrap").joinpath("data", "advisory-techniques-v1.json")
    raw = json.loads(path.read_text(encoding="utf-8"), parse_constant=_reject_constant)
    if not isinstance(raw, dict) or set(raw) != {
        "schema_version", "source", "interpretation", "techniques"
    }:
        raise ThreatInventoryError("technique inventory has an invalid root contract")
    if raw["schema_version"] != "1.0" or not isinstance(raw["interpretation"], str):
        raise ThreatInventoryError("technique inventory version/interpretation is invalid")
    source = raw["source"]
    expected_source = {
        "source_id": "FBI-FLASH-20261113-001",
        "publication_date": "2026-11-13",
        "url": "https://www.ic3.gov/CSA/2026/261113.pdf",
        "sha256": "3dd86a94d33b29c65f56b4307919b74358e63cfde33a600b61adce5794d169e2",
    }
    if source != expected_source:
        raise ThreatInventoryError("technique inventory source pin is invalid")
    techniques = raw["techniques"]
    if not isinstance(techniques, list):
        raise ThreatInventoryError("techniques must be an array")
    seen: set[str] = set()
    available_scenarios = None if scenario_ids is None else set(scenario_ids)
    for index, item in enumerate(techniques):
        if not isinstance(item, dict) or set(item) != {
            "technique_id", "name", "phase", "pages", "disposition",
            "experiment_ids", "rationale",
        }:
            raise ThreatInventoryError(f"technique[{index}] has an invalid contract")
        technique_id = item["technique_id"]
        if not isinstance(technique_id, str) or technique_id in seen:
            raise ThreatInventoryError("technique identifiers must be unique strings")
        seen.add(technique_id)
        if item["disposition"] not in {"SYNTHETIC_ABSTRACTION", "NOT_MODELED_V0.1"}:
            raise ThreatInventoryError(f"invalid disposition for {technique_id}")
        if not isinstance(item["pages"], list) or not item["pages"] or any(
            type(page) is not int or page < 1 for page in item["pages"]
        ):
            raise ThreatInventoryError(f"invalid page evidence for {technique_id}")
        expected_pages = [
            page
            for page, technique_ids in _FBI_TABLE_BY_PDF_PAGE.items()
            if technique_id in technique_ids
        ]
        if expected_pages and item["pages"] != expected_pages:
            raise ThreatInventoryError(f"page references differ from FBI table for {technique_id}")
        if not all(
            isinstance(item[key], str) and item[key]
            for key in ("name", "phase", "rationale")
        ):
            raise ThreatInventoryError(f"missing text evidence for {technique_id}")
        experiments = item["experiment_ids"]
        if (
            not isinstance(experiments, list)
            or not all(isinstance(value, str) and value for value in experiments)
            or len(experiments) != len(set(experiments))
        ):
            raise ThreatInventoryError(f"invalid experiment mapping for {technique_id}")
        if item["disposition"] == "SYNTHETIC_ABSTRACTION" and not experiments:
            raise ThreatInventoryError(f"modeled technique {technique_id} has no experiment")
        if item["disposition"] == "NOT_MODELED_V0.1" and experiments:
            raise ThreatInventoryError(f"excluded technique {technique_id} names an experiment")
        if available_scenarios is not None and set(experiments) - available_scenarios:
            raise ThreatInventoryError(f"{technique_id} maps to an unknown scenario")
    if seen != EXPECTED_FBI_TECHNIQUE_IDS:
        raise ThreatInventoryError(
            "technique inventory differs from the pinned FBI table: "
            f"missing={sorted(EXPECTED_FBI_TECHNIQUE_IDS - seen)}, "
            f"unexpected={sorted(seen - EXPECTED_FBI_TECHNIQUE_IDS)}"
        )
    return {
        **raw,
        "inventory_digest": "sha256:" + sha256_json(raw),
        "technique_count": len(techniques),
        "synthetic_abstraction_count": sum(
            item["disposition"] == "SYNTHETIC_ABSTRACTION" for item in techniques
        ),
        "not_modeled_v0_1_count": sum(
            item["disposition"] == "NOT_MODELED_V0.1" for item in techniques
        ),
    }


def build_technique_evidence_matrix(
    inventory: Mapping[str, Any],
    scenarios: Iterable[Scenario],
    baselines: Iterable[ExperimentCase],
    executions: Iterable[CaseExecution],
    *,
    qualified: bool,
) -> dict[str, Any]:
    """Link each advisory row to versioned baseline assertions and run evidence."""
    scenarios_by_id = defaultdict(list)
    for scenario in scenarios:
        scenarios_by_id[scenario.scenario_id].append(scenario)
    baseline_by_scenario = {
        (case.scenario_ids[0], case.scenario_versions[0]): case for case in baselines
    }
    executions_by_id = {result.case.case_id: result for result in executions}
    rows = []
    for technique in inventory["techniques"]:
        technique_id = technique["technique_id"]
        tests = []
        for scenario_id in technique["experiment_ids"]:
            for scenario in scenarios_by_id[scenario_id]:
                case = baseline_by_scenario.get((scenario_id, scenario.scenario_version))
                execution = executions_by_id.get(case.case_id) if case else None
                relationship = next(
                    (
                        reference.relationship
                        for reference in scenario.attack_references
                        if reference.technique_id == technique_id
                    ),
                    "DEFENSIVE_STRESSOR",
                )
                tests.append(
                    {
                        "scenario_id": scenario_id,
                        "scenario_version": scenario.scenario_version,
                        "scenario_definition_digest": scenario.definition_digest,
                        "relationship": relationship,
                        "control": scenario.expectation.control,
                        "assertions": list(scenario.expectation.invariants),
                        "planned_case_id": case.case_id if case else None,
                        "evidence_case_id": execution.case.case_id if execution else None,
                        "independent_oracle_passed": (
                            execution.assessment.passed if execution else None
                        ),
                    }
                )
        status = "NOT TESTED"
        if qualified and tests and all(
            test["independent_oracle_passed"] is True for test in tests
        ):
            status = "SYNTHETICALLY VERIFIED"
        elif any(test["planned_case_id"] is not None for test in tests):
            status = "INCONCLUSIVE"
        rows.append(
            {
                "technique_id": technique_id,
                "disposition": technique["disposition"],
                "limitation": technique["rationale"],
                "authority_property_status": status,
                "operational_technique_status": "NOT TESTED",
                "tests": tests,
            }
        )
    return {
        "schema_version": "1.0",
        "inventory_digest": inventory["inventory_digest"],
        "techniques": rows,
    }

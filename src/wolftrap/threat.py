"""Pinned FBI advisory technique inventory and traceability validation."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any, Iterable

from .canonical import sha256_json


EXPECTED_FBI_TECHNIQUE_IDS = frozenset(
    {
        "T1595", "T1580", "T1087.004", "T1069.003", "T1526",
        "T1190", "T1078", "T1133", "T1195", "T1199", "T1606.002",
        "T1552.001", "T1505.003", "T1078.004", "T1098.001",
        "T1574.001", "T1036.005", "T1105", "T1059", "T1134.001",
        "T1098.003", "T1552.005", "T1606", "T1558.003", "T1518.001",
        "T1555", "T1087.002", "T1552.006", "T1059.001", "T1550.003",
        "T1550.002", "T1021.006", "T1557.001", "T1114.002",
        "T1555.006", "T1530", "T1005", "T1074.001", "T1074.002",
        "T1090", "T1090.003", "T1572", "T1071.001",
    }
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
    available_scenarios = set(scenario_ids or ())
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
        if not all(
            isinstance(item[key], str) and item[key]
            for key in ("name", "phase", "rationale")
        ):
            raise ThreatInventoryError(f"missing text evidence for {technique_id}")
        experiments = item["experiment_ids"]
        if not isinstance(experiments, list) or not all(
            isinstance(value, str) and value for value in experiments
        ):
            raise ThreatInventoryError(f"invalid experiment mapping for {technique_id}")
        if item["disposition"] == "SYNTHETIC_ABSTRACTION" and not experiments:
            raise ThreatInventoryError(f"modeled technique {technique_id} has no experiment")
        if item["disposition"] == "NOT_MODELED_V0.1" and experiments:
            raise ThreatInventoryError(f"excluded technique {technique_id} names an experiment")
        if available_scenarios and set(experiments) - available_scenarios:
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

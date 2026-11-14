"""Autonomous, bounded, *synthetic-only* multi-seed research sweeps.

Stage 2 widens the v0.1 pairwise frontier without introducing a model,
network client, external target, or new effect authority.  Every constituent
campaign keeps its original complete evidence pair and reproduction cases.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .report import (
    REPORT_JSON_NAME,
    REPORT_MANIFEST_NAME,
    validate_report_pair,
    write_json_report,
    write_report_pair,
)
from .revision import capture_source_revision
from .runner import RunConfiguration, run_research
from .system import SYSTEMS


STAGE2_MANIFEST = "stage2-manifest.json"
STAGE2_REPORT = "stage2-summary.json"


@dataclass(frozen=True)
class Stage2Configuration:
    first_seed: int = 20261113
    seed_count: int = 3
    mutation_budget: int = 128
    system_id: str = "correct-v1"

    def validate(self) -> None:
        if type(self.first_seed) is not int or not 0 <= self.first_seed <= 9_223_372_036_854_775_807:
            raise ValueError("first_seed must be a bounded non-negative integer")
        if type(self.seed_count) is not int or not 1 <= self.seed_count <= 4:
            raise ValueError("seed_count must be between 1 and 4")
        if self.first_seed + self.seed_count - 1 > 9_223_372_036_854_775_807:
            raise ValueError("seed sweep exceeds the supported seed bound")
        if type(self.mutation_budget) is not int or not 96 <= self.mutation_budget <= 256:
            raise ValueError("mutation_budget must be between 96 and 256")
        if self.system_id not in SYSTEMS:
            raise ValueError("unknown synthetic system")


@dataclass(frozen=True)
class Stage2Outcome:
    report: dict[str, Any]
    exit_code: int


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run_stage2(
    configuration: Stage2Configuration,
    *,
    output_dir: str | Path,
    unit_test_summary: Mapping[str, Any] | None,
) -> Stage2Outcome:
    """Run a reproducible full-pair sweep; never infer success from a seed alone."""

    configuration.validate()
    root = Path(output_dir)
    if root.is_symlink():
        raise ValueError("stage 2 output directory cannot be a symlink")
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError("stage 2 output directory must be empty to preserve prior evidence")
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / STAGE2_MANIFEST
    # A crash or interruption must never leave an older COMPLETE marker valid.
    write_json_report({"state": "INCOMPLETE", "stage2_schema_version": "1.0"}, manifest_path)

    start_revision = capture_source_revision()
    campaign_records: list[dict[str, Any]] = []
    all_pairs: set[tuple[str, str]] = set()
    candidate_pair_count: int | None = None
    confirmed_fingerprints: set[str] = set()
    errors: list[str] = []

    for offset in range(configuration.seed_count):
        seed = configuration.first_seed + offset
        result = run_research(
            RunConfiguration(
                seed=seed,
                max_mutations=configuration.mutation_budget,
                max_interactions=55,
                system_id=configuration.system_id,
            ),
            source_revision=start_revision,
            unit_test_summary=unit_test_summary,
            reproduction_report_path=f"campaigns/seed-{seed}/{REPORT_JSON_NAME}",
        )
        directory = root / "campaigns" / f"seed-{seed}"
        report_path, _ = write_report_pair(result.report, directory)
        validated = validate_report_pair(report_path)
        if validated.get("source_revision") != start_revision.to_dict():
            raise ValueError("campaign source revision differs from the stage 2 source")

        coverage = validated["coverage"]["interactions"]
        pairs = {
            tuple(pair) for pair in coverage["executed_pairs"]
            if isinstance(pair, list) and len(pair) == 2
            and all(isinstance(item, str) for item in pair)
        }
        candidates = coverage["candidate_pairs"]
        if candidate_pair_count is None:
            candidate_pair_count = candidates
        elif candidate_pair_count != candidates:
            errors.append("scenario pair inventory changed between seeds")
        all_pairs.update(pairs)

        for finding in validated["findings"]:
            if finding.get("classification") == "CONFIRMED":
                fingerprint = finding["independent_effect_state_evidence"]["oracle_fingerprint"]
                confirmed_fingerprints.add(str(fingerprint))

        manifest_bytes = (directory / REPORT_MANIFEST_NAME).read_bytes()
        campaign_records.append(
            {
                "seed": seed,
                "status": validated["qualification"]["status"],
                "cases_executed": validated["summary"]["cases_executed"],
                "findings": validated["summary"]["findings"],
                "internal_errors": validated["summary"]["internal_errors"],
                "candidate_pairs": candidates,
                "executed_pairs": len(pairs),
                "pair_truncated": coverage["truncated"],
                "report_path": str(Path("campaigns") / f"seed-{seed}" / REPORT_JSON_NAME),
                "report_sha256": _sha256(report_path.read_bytes()),
                "manifest_sha256": _sha256(manifest_bytes),
            }
        )
        if result.exit_code == 2:
            errors.append(f"seed {seed}: constituent campaign stopped with ERROR")
            break

    end_revision = capture_source_revision()
    if end_revision != start_revision:
        errors.append("source revision changed during the multi-seed sweep")
    full_pairs = (
        candidate_pair_count == 55
        and len(all_pairs) == candidate_pair_count
        and all(
            record["executed_pairs"] == candidate_pair_count
            and record["pair_truncated"] is False
            for record in campaign_records
        )
    )
    all_seeds_ran = len(campaign_records) == configuration.seed_count
    if errors:
        status, exit_code = "ERROR", 2
    elif not all_seeds_ran or not full_pairs or any(record["status"] != "PASS" for record in campaign_records):
        status, exit_code = "FAIL", 1
    else:
        status, exit_code = "PASS", 0

    report: dict[str, Any] = {
        "stage2_schema_version": "1.0",
        "purpose": "bounded autonomous defensive research over synthetic systems only",
        "synthetic_only": True,
        "external_systems_tested": False,
        "source_revision": start_revision.to_dict(),
        "source_revision_end": end_revision.to_dict(),
        "configuration": asdict(configuration),
        "model_hypotheses": {
            "requested_provider": "OpenAI",
            "requested_model": "GPT-5.6 Sol",
            "requested_mode": "Daybreak Blue",
            "availability_verified": False,
            "enabled": False,
            "used": False,
            "reason": "Stage 2 has no model/API client; account access was not checked.",
        },
        "qualification": {
            "status": status,
            "all_seeds_executed": all_seeds_ran,
            "all_55_pairs_per_seed": full_pairs,
            "all_constituent_controls_passed": all(record["status"] == "PASS" for record in campaign_records),
            "bounded_not_exhaustive": True,
        },
        "summary": {
            "campaigns_executed": len(campaign_records),
            "cases_executed": sum(item["cases_executed"] for item in campaign_records),
            "findings": sum(item["findings"] for item in campaign_records),
            "distinct_confirmed_fingerprints": len(confirmed_fingerprints),
            "internal_errors": sum(item["internal_errors"] for item in campaign_records),
        },
        "pair_coverage": {
            "candidate_pairs": candidate_pair_count,
            "unique_pairs_reached": len(all_pairs),
            "complete_per_seed": full_pairs,
            "pairs": [list(pair) for pair in sorted(all_pairs)],
        },
        "campaigns": campaign_records,
        "errors": errors,
        "lifecycle": {
            "DESIGNED": True,
            "IMPLEMENTED": True,
            "CHECKPOINTED": start_revision.commit_sha != "UNCOMMITTED" and not start_revision.dirty,
            "TESTED": status != "ERROR",
            "LIVE VERIFIED": False,
            "REVIEWED": False,
            "MERGED": False,
            "DEPLOYED": False,
        },
    }
    report_path = write_json_report(report, root / STAGE2_REPORT)
    write_json_report(
        {
            "stage2_schema_version": "1.0",
            "state": "COMPLETE",
            "qualification_status": status,
            "report": STAGE2_REPORT,
            "report_sha256": _sha256(report_path.read_bytes()),
            "campaign_manifest_hashes": [item["manifest_sha256"] for item in campaign_records],
        },
        manifest_path,
    )
    return Stage2Outcome(report=report, exit_code=exit_code)

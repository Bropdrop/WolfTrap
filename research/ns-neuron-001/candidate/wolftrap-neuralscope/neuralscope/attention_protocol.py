"""Fixed, counterbalanced attention-head experiment; no model inference here.

The conditions share token counts but change ordering and distances. Their
contrast is a comparative intervention effect, not proof of a unique induction
mechanism. Opposite orientations reuse inputs and are not independent samples.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import math

from .evidence import canonical, write_json
from .study import _pin_copy


SCHEMA = "wolftrap.neuralscope.attention-protocol/v1"
GROUPS = (
    ("fruit", "discovery", "apple", "orange", "lemon"),
    ("weather", "discovery", "rain", "snow", "wind"),
    ("transport", "discovery", "car", "bus", "train"),
    ("drinks", "validation", "tea", "coffee", "milk"),
    ("metals", "validation", "iron", "steel", "copper"),
    ("royalty", "validation", "king", "queen", "prince"),
)
CONDITIONS = ("repeat", "control")
ORIENTATIONS = ("forward", "reverse")
OPERATIONS = ("restore", "reverse", "self_clean", "self_changed", "ablate")
SITES = tuple(f"blocks.{layer}.attn.head.{head}" for layer in range(6) for head in range(12))
MINIMUM_GAP = 0.05
MINIMUM_EFFECT = 0.01
SELF_ATOL = 1e-6


def build_attention_protocol(tokenizer, config, pin):
    """Tokenize all fixed discovery/validation text without reading outputs.

    Accepts either a Transformers tokenizer's list result or a local Rust
    tokenizers Encoding. Any mismatch stops the builder instead of changing or
    excluding an inconvenient lexical group.
    """
    identity = _pin_copy(pin)
    if not isinstance(config, Mapping) or any(config.get(k) != v for k, v in {
        "model_type": "gpt2", "n_layer": 6, "n_head": 12, "n_embd": 768, "vocab_size": 50257,
    }.items()):
        raise ValueError("the attention protocol requires standard six-layer DistilGPT2")
    if not callable(getattr(tokenizer, "encode", None)):
        raise ValueError("supply a verified local tokenizer")

    def encode(text):
        encoded = tokenizer.encode(text, add_special_tokens=False)
        ids = getattr(encoded, "ids", encoded)
        if not isinstance(ids, (list, tuple)) or not ids or any(
            type(value) is not int or not 0 <= value < config["vocab_size"] for value in ids
        ):
            raise ValueError("invalid token IDs returned by tokenizer")
        return list(ids)

    cases, lexical_groups = [], []
    for group_id, split, a, b, c in GROUPS:
        encoded_words = [encode(" " + word) for word in (a, b, c)]
        if any(len(ids) != 1 for ids in encoded_words) or len({tuple(ids) for ids in encoded_words}) != 3:
            raise ValueError("fixed words must map to three distinct single tokens: " + group_id)
        a_id, b_id, c_id = [ids[0] for ids in encoded_words]
        lexical_groups.append({"id": group_id, "split": split, "words": [a, b, c], "token_ids": [a_id, b_id, c_id]})
        for condition in CONDITIONS:
            clean_words = [a, b, a, b, a] if condition == "repeat" else [a, a, b, b, a]
            changed_words = [a, c, a, c, a] if condition == "repeat" else [a, a, c, c, a]
            clean_text, changed_text = " " + " ".join(clean_words), " " + " ".join(changed_words)
            clean_ids, changed_ids = encode(clean_text), encode(changed_text)
            token_map = dict(zip((a, b, c), (a_id, b_id, c_id), strict=True))
            if clean_ids != [token_map[word] for word in clean_words] or changed_ids != [token_map[word] for word in changed_words]:
                raise ValueError("tokenizer did not preserve the fixed five-token pattern: " + group_id)
            for orientation in ORIENTATIONS:
                forward = orientation == "forward"
                cases.append({
                    "id": f"{group_id}_{condition}_{orientation}", "group_id": group_id,
                    "split": split, "condition": condition, "orientation": orientation,
                    "clean_text": clean_text if forward else changed_text,
                    "changed_text": changed_text if forward else clean_text,
                    "clean_ids": clean_ids.copy() if forward else changed_ids.copy(),
                    "changed_ids": changed_ids.copy() if forward else clean_ids.copy(),
                    "target_id": b_id if forward else c_id, "alternative_id": c_id if forward else b_id,
                    "target_text": " " + (b if forward else c), "alternative_text": " " + (c if forward else b),
                    "positions": [4],
                })
    return {
        "schema": SCHEMA,
        "title": "DistilGPT2 counterbalanced repeated-token attention-head study",
        "builder_performs_inference": False,
        "model_identity": identity,
        "tokenizer_identity": {"repo_id": identity["repo_id"], "revision": identity["revision"],
                               "files": {name: record for name, record in identity["files"].items()
                                         if name in {"tokenizer.json", "tokenizer_config.json", "vocab.json", "merges.txt"}},
                               "add_special_tokens": False},
        "lexical_groups": lexical_groups, "cases": cases, "sites": list(SITES),
        "minimum_gap": MINIMUM_GAP,
        "selection": {
            "metric": "mean across three lexical groups and both orientations of (repeat restoration delta minus control restoration delta), in raw logits",
            "restoration_delta": "patched changed margin minus unpatched changed margin",
            "margin": "final-token logit(target) minus logit(alternative)",
            "minimum_specificity_score": MINIMUM_EFFECT,
            "minimum_repeated_mean": MINIMUM_EFFECT,
            "each_orientation_repeated_mean": "strictly greater than zero across all three discovery lexical groups",
            "repeat_baseline_gap": "strictly greater than 0.05 for every discovery repeated case; orientations share these underlying gaps",
            "control_gap_requirement": "none: raw control effects remain usable even when the control gap is zero or negative",
            "rule": "choose the eligible head with greatest specificity score; choose none if no head qualifies",
            "tie_break": "exact numeric ties: ascending layer, then ascending head",
            "eligible_sites": list(SITES),
            "validation_access": "freeze selection JSON and its SHA-256 before any validation forward pass; no replacement selection",
        },
        "validation": {
            "sites": "only the one head selected from discovery; skip if none selected",
            "operations": list(OPERATIONS),
            "minimum_specificity_score": MINIMUM_EFFECT,
            "minimum_repeated_mean": MINIMUM_EFFECT,
            "each_orientation_repeated_mean": "strictly greater than zero",
            "minimum_positive_group_specificity": 2,
            "group_specificity": "mean of repeat-minus-control restoration delta across both orientations for one lexical group",
            "repeat_baseline_gap": "strictly greater than 0.05 for each repeated case",
            "interpretation": "descriptive threshold flags for three held-out groups, not a statistical significance test or population claim",
            "self_patch_margin_atol": SELF_ATOL,
        },
        "reference_comparison": {
            "arithmetic": "CPU float32; deterministic evaluation; eager attention; no KV cache",
            "full_logit_max_abs_error": 1e-3, "full_logit_rmse": 1e-4,
            "activation_atol": 2e-4, "activation_rtol": 2e-4,
            "self_patch_margin_atol": SELF_ATOL,
            "hooked_baseline_vs_unhooked": "bitwise identical",
            "baseline_scope": "all unique sequences used in a reached stage: hooked and unhooked reference passes",
            "discovery_intervention_case": "fruit_repeat_forward",
            "discovery_intervention_sites": list(SITES),
            "discovery_operation": "restore",
            "validation_interventions": "all selected-head operations, conditions, and orientations",
            "patch_donor_policy": "each engine uses its own captured donor and recipient; baseline activations are compared separately",
            "argmax_requirement": "observed and reported, not a substitute for full numerical comparison",
            "failure_policy": "retain mismatches and stop interpretation; do not widen frozen tolerances",
        },
        "forward_pass_counts": {
            "discovery_unique_baselines": 12,
            "discovery_candidate_restore_passes": 864,
            "discovery_candidate_total": 876,
            "discovery_reference_hooked_baselines": 12,
            "discovery_reference_unhooked_baselines": 12,
            "discovery_reference_restore_passes": 72,
            "discovery_reference_total": 96,
            "validation_unique_baselines": 12,
            "validation_candidate_interventions": 60,
            "validation_candidate_total": 72,
            "validation_reference_hooked_baselines": 12,
            "validation_reference_unhooked_baselines": 12,
            "validation_reference_interventions": 60,
            "validation_reference_total": 84,
            "maximum_candidate_total": 948,
            "maximum_reference_total": 180,
            "maximum_combined_total": 1128,
            "no_selection_candidate_total": 876,
            "no_selection_reference_total": 96,
            "counts_assume": "reuse unique baselines across both orientations; reuse first discovery case candidate scans for reference comparison",
        },
        "evidence_policy": {
            "retain_all_records": True, "exclude_or_rewrite_unhelpful_cases": False,
            "retained_statistics": ["all 72 discovery head scores", "both orientation means", "per-group effects", "raw margins", "target and alternative ranks", "global top token", "pairwise preference changes"],
            "distinct_lexical_groups_per_split": 3,
            "orientations_independent": False,
            "population_confidence_interval": None,
            "inactive_head_assumption": "none",
            "freeze_requirement": "canonical local protocol before first inference, then canonical local selection before held-out inference; neither is an independently timestamped registry",
            "limitations": [
                "frequency-matched control changes token order and distances, so a positive difference is not proof of a unique induction mechanism",
                "discovery searches 72 candidates and its maximum can be optimistic; validation does not reselect",
                "orientations reuse the same inputs and must not be counted as independent lexical samples",
                "pairwise preference is different from vocabulary-wide highest-scoring token",
                "projected-head intervention effects are local to the tested checkpoint, inputs, and positions",
                "zero ablation can produce atypical internal activity",
            ],
        },
    }


def write_protocol(path, protocol):
    """Write a fresh protocol and return its canonical SHA-256."""
    if not isinstance(protocol, dict) or protocol.get("schema") != SCHEMA:
        raise ValueError("unsupported attention protocol")
    encoded = canonical(protocol)
    write_json(path, protocol)
    return hashlib.sha256(encoded).hexdigest()


def _cases(protocol, split):
    if not isinstance(protocol, dict) or protocol.get("schema") != SCHEMA:
        raise ValueError("unsupported attention protocol")
    if protocol.get("sites") != list(SITES) or protocol.get("minimum_gap") != MINIMUM_GAP:
        raise ValueError("attention site inventory or baseline threshold differs")
    entries = protocol.get("cases")
    if not isinstance(entries, list):
        raise ValueError("attention cases must be a list")
    expected = {(group, condition, orientation) for group, assigned, *_ in GROUPS if assigned == split
                for condition in CONDITIONS for orientation in ORIENTATIONS}
    result = {}
    for case in entries:
        if not isinstance(case, dict):
            raise ValueError("invalid attention case")
        if case.get("split") != split:
            continue
        key = (case.get("group_id"), case.get("condition"), case.get("orientation"))
        if key in result or key not in expected:
            raise ValueError("duplicate or unexpected attention case")
        result[key] = case
    if set(result) != expected:
        raise ValueError("missing registered attention cases")
    return result


def _finite(value, field):
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError("nonfinite or invalid attention measurement: " + field)
    return float(value)


def _close(a, b):
    return math.isclose(a, b, rel_tol=1e-8, abs_tol=1e-8)


def _row_key(row, cases):
    if not isinstance(row, dict):
        raise ValueError("attention measurement must be an object")
    if row.get("status", "PASS") != "PASS":
        raise ValueError("failed numeric measurement cannot support attention selection or assessment")
    key = (row.get("group_id"), row.get("condition"), row.get("orientation"))
    if key not in cases:
        raise ValueError("unexpected group, condition, or orientation in attention measurements")
    case = cases[key]
    if row.get("split", case["split"]) != case["split"]:
        raise ValueError("attention measurement split differs")
    if row.get("id", case["id"]) != case["id"]:
        raise ValueError("attention measurement case identity differs")
    clean = _finite(row.get("clean_margin"), "clean_margin")
    changed = _finite(row.get("changed_margin"), "changed_margin")
    gap = _finite(row.get("baseline_gap"), "baseline_gap")
    if not _close(gap, clean-changed):
        raise ValueError("baseline gap differs from retained margins")
    return key, clean, changed, gap


def _restore_effect(row, changed):
    restored = _finite(row.get("restored_margin", row.get("result_margin")), "restored_margin")
    effect = _finite(row.get("restoration_delta"), "restoration_delta")
    if not _close(effect, restored-changed):
        raise ValueError("restoration delta differs from retained margins")
    return effect


def _check_counterbalanced_baselines(baselines, group_ids):
    for group_id in group_ids:
        for condition in CONDITIONS:
            forward = baselines[(group_id, condition, "forward")]
            reverse = baselines[(group_id, condition, "reverse")]
            if not (_close(reverse[0], -forward[1]) and _close(reverse[1], -forward[0])
                    and _close(reverse[2], forward[2])):
                raise ValueError("counterbalanced baseline margins do not describe the same swapped inputs and answers")


def _effect_summary(restores, group_ids):
    """One selected head's complete condition×orientation observations."""
    groups, oriented = [], {orientation: {"repeat": [], "control": []} for orientation in ORIENTATIONS}
    for group_id in group_ids:
        pair = {orientation: {} for orientation in ORIENTATIONS}
        gaps = []
        for orientation in ORIENTATIONS:
            for condition in CONDITIONS:
                row = restores[(group_id, condition, orientation)]
                effect = row["effect"]
                oriented[orientation][condition].append(effect)
                pair[orientation][condition] = effect
                if condition == "repeat":
                    gaps.append(row["gap"])
            pair[orientation]["difference"] = pair[orientation]["repeat"]-pair[orientation]["control"]
        groups.append({"group_id": group_id, "orientations": pair,
                       "specificity_score": sum(pair[o]["difference"] for o in ORIENTATIONS)/2,
                       "repeated_mean": sum(pair[o]["repeat"] for o in ORIENTATIONS)/2,
                       "control_mean": sum(pair[o]["control"] for o in ORIENTATIONS)/2,
                       "repeat_gaps": gaps})
    orientation_means = {orientation: {
        "repeated": sum(oriented[orientation]["repeat"])/len(group_ids),
        "control": sum(oriented[orientation]["control"])/len(group_ids),
        "difference": sum(group["orientations"][orientation]["difference"] for group in groups)/len(group_ids),
    } for orientation in ORIENTATIONS}
    score = sum(group["specificity_score"] for group in groups)/len(groups)
    repeated = sum(group["repeated_mean"] for group in groups)/len(groups)
    control = sum(group["control_mean"] for group in groups)/len(groups)
    positive_baselines = all(gap > MINIMUM_GAP for group in groups for gap in group["repeat_gaps"])
    flags = {"specificity_floor_met": score >= MINIMUM_EFFECT,
             "repeated_effect_floor_met": repeated >= MINIMUM_EFFECT,
             "both_orientation_repeated_means_positive": all(values["repeated"] > 0 for values in orientation_means.values()),
             "all_repeated_baseline_gaps_above_floor": positive_baselines}
    reasons = [name for name, passed in flags.items() if not passed]
    return {"specificity_score": score, "repeated_mean": repeated, "control_mean": control,
            "orientation_means": orientation_means, "group_effects": groups,
            "threshold_flags": flags, "eligible": not reasons, "reasons": reasons,
            "positive_group_specificity_count": sum(group["specificity_score"] > 0 for group in groups),
            "lexical_groups": len(groups), "counterbalanced_orientations": 2,
            "orientations_are_independent_samples": False}


def select_head(discovery_records, protocol):
    """Select once from all 864 discovery measurements; never inspect validation."""
    cases = _cases(protocol, "discovery")
    if not isinstance(discovery_records, list) or len(discovery_records) != len(cases)*len(SITES):
        raise ValueError("selection requires every registered discovery case and all 72 heads")
    by_site = {site: {} for site in SITES}
    baselines = {}
    for row in discovery_records:
        key, clean, changed, gap = _row_key(row, cases)
        site = row.get("site")
        if site not in by_site or key in by_site[site] or row.get("operation", "restore") != "restore":
            raise ValueError("duplicate, unsupported, or non-restoration discovery measurement")
        baseline = (clean, changed, gap)
        if key in baselines and baseline != baselines[key]:
            raise ValueError("discovery baseline changed across heads")
        baselines[key] = baseline
        by_site[site][key] = {"effect": _restore_effect(row, changed), "gap": gap}
    group_ids = [group for group, split, *_ in GROUPS if split == "discovery"]
    _check_counterbalanced_baselines(baselines, group_ids)
    ranking = []
    for site in SITES:
        if set(by_site[site]) != set(cases):
            raise ValueError("discovery head is missing registered observations")
        ranking.append({"site": site, **_effect_summary(by_site[site], group_ids)})
    eligible = [row for row in ranking if row["eligible"]]
    chosen = max(eligible, key=lambda row: row["specificity_score"]) if eligible else None
    # Python's stable ordering preserves the ascending layer/head tie break.
    ranked = sorted(ranking, key=lambda row: -row["specificity_score"])
    for index, row in enumerate(ranked, 1):
        row["rank"] = index
    return {"schema": "wolftrap.neuralscope.attention-selection/v1",
            "protocol_sha256": hashlib.sha256(canonical(protocol)).hexdigest(),
            "status": "SELECTED" if chosen else "NO_ELIGIBLE_HEAD",
            "selected_site": chosen["site"] if chosen else None,
            "selected_specificity_score": chosen["specificity_score"] if chosen else None,
            "eligible_heads": len(eligible), "heads_considered": len(SITES),
            "discovery_records": len(discovery_records), "ranking": ranked,
            "score_unit": "raw logits: repeated-condition patch delta minus matched-control patch delta",
            "selection_uses_validation": False,
            "claim": "fixed practical discovery criteria across three lexical groups; no statistical significance or unique mechanism claim"}


def assess_validation(validation_records, protocol, selected_site):
    """Summarize the frozen selected head; report all held-out effects and controls."""
    cases = _cases(protocol, "validation")
    if selected_site is None:
        if validation_records != []:
            raise ValueError("validation records require a previously selected head")
        return {"schema": "wolftrap.neuralscope.attention-validation/v1", "status": "NOT_RUN_NO_SELECTION",
                "selected_site": None, "records": 0, "descriptive_criteria_met": None}
    if selected_site not in SITES:
        raise ValueError("unsupported selected head")
    if not isinstance(validation_records, list) or len(validation_records) != len(cases)*len(OPERATIONS):
        raise ValueError("validation must retain every registered case and all five operations")
    records, baselines, restores = {}, {}, {}
    self_max = 0.0
    for row in validation_records:
        key, clean, changed, gap = _row_key(row, cases)
        operation = row.get("operation")
        if row.get("site") != selected_site or operation not in OPERATIONS or (key, operation) in records:
            raise ValueError("validation changed the selected head or contains duplicate/unsupported operations")
        baseline = (clean, changed, gap)
        if key in baselines and baseline != baselines[key]:
            raise ValueError("validation baseline changed across operations")
        baselines[key] = baseline
        result_margin = _finite(row.get("result_margin"), "result_margin")
        if operation == "restore":
            effect = _restore_effect(row, changed)
            if not _close(result_margin, row.get("restored_margin", result_margin)):
                raise ValueError("restored margin differs from operation result")
            restores[key] = {"effect": effect, "gap": gap}
        if operation in ("self_clean", "self_changed"):
            original = clean if operation == "self_clean" else changed
            self_max = max(self_max, abs(result_margin-original))
            if "self_margin_delta" in row and not _close(_finite(row["self_margin_delta"], "self_margin_delta"), abs(result_margin-original)):
                raise ValueError("self-copy delta differs from retained margins")
        records[(key, operation)] = row
    expected = {(key, operation) for key in cases for operation in OPERATIONS}
    if set(records) != expected or set(restores) != set(cases):
        raise ValueError("missing validation operation")
    group_ids = [group for group, split, *_ in GROUPS if split == "validation"]
    _check_counterbalanced_baselines(baselines, group_ids)
    summary = _effect_summary(restores, group_ids)
    summary["threshold_flags"]["at_least_two_groups_have_positive_specificity"] = summary["positive_group_specificity_count"] >= 2
    summary["threshold_flags"]["self_copy_controls_pass"] = self_max <= SELF_ATOL
    criteria = all(summary["threshold_flags"].values())
    # Discovery eligibility is not re-applied to choose another head. The same
    # practical floors here are descriptive flags for the single frozen choice.
    summary.pop("eligible")
    summary["reasons"] = [name for name, passed in summary["threshold_flags"].items() if not passed]
    observed = []
    for key, case in cases.items():
        clean, changed, gap = baselines[key]
        entries = {operation: records[(key, operation)] for operation in OPERATIONS}
        restored = entries["restore"]["result_margin"]
        observed.append({"id": case["id"], "group_id": case["group_id"], "condition": case["condition"],
                         "orientation": case["orientation"], "clean_margin": clean, "changed_margin": changed,
                         "baseline_gap": gap, "restored_margin": restored,
                         "restoration_delta": restores[key]["effect"],
                         "normalized_restoration": restores[key]["effect"]/gap if gap > MINIMUM_GAP else None,
                         "reverse_margin": entries["reverse"]["result_margin"],
                         "reverse_delta": clean-entries["reverse"]["result_margin"],
                         "ablated_margin": entries["ablate"]["result_margin"],
                         "clean_prefers_target": clean > 0, "changed_prefers_alternative": changed < 0,
                         "patched_prefers_target": restored > 0,
                         "self_clean_delta": abs(entries["self_clean"]["result_margin"]-clean),
                         "self_changed_delta": abs(entries["self_changed"]["result_margin"]-changed),
                         "candidate_clean": entries["restore"].get("candidate_clean"),
                         "candidate_changed": entries["restore"].get("candidate_changed"),
                         "candidate_result": entries["restore"].get("candidate_result")})
    return {"schema": "wolftrap.neuralscope.attention-validation/v1",
            "protocol_sha256": hashlib.sha256(canonical(protocol)).hexdigest(),
            "status": "MEASURED", "selected_site": selected_site, "records": len(validation_records),
            **summary, "descriptive_criteria_met": criteria,
            "self_patch_max_margin_delta": self_max, "self_patch_margin_atol": SELF_ATOL,
            "cases": observed, "all_records_retained": True, "replacement_selection": False,
            "interpretation": "descriptive held-out comparison across three lexical groups; no p-value, population confidence interval, or unique induction-mechanism inference"}

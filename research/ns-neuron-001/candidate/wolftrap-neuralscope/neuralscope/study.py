"""Predeclared, small DistilGPT2 repeated-token intervention experiment.

The builder tokenizes fixed text; it never calls a model or reads its outputs.
Write the registration before inference, and retain its digest with the results.
The registration is an unsigned local record, not a timestamped preregistration
with an independent registry. Nothing here claims a pretrained head is inactive.
"""
from __future__ import annotations

from collections.abc import Mapping
import hashlib
import json
import math
import re

from .evidence import canonical, write_json


SCHEMA = "wolftrap.neuralscope.pretrained-study/v1"

# These choices are independent of any pretrained-model response. Leading spaces
# make the word pieces comparable to the next-token answer alternatives.
PATTERNS = (
    ("colors", "discovery", "red", "blue", "green"),
    ("animals", "discovery", "cat", "dog", "bird"),
    ("cities", "discovery", "Paris", "London", "Rome"),
    ("shades", "validation", "black", "white", "brown"),
    ("sky", "validation", "sun", "moon", "star"),
    ("numbers", "validation", "one", "two", "three"),
)


def _pin_copy(pin):
    if not isinstance(pin, Mapping):
        raise ValueError("the study requires a pinned model identity")
    if pin.get("repo_id") != "distilbert/distilgpt2":
        raise ValueError("this fixed study is for distilbert/distilgpt2")
    if not isinstance(pin.get("revision"), str) or not re.fullmatch(r"[0-9a-f]{40}", pin["revision"]):
        raise ValueError("model revision must be a complete hexadecimal commit")
    files = pin.get("files")
    required = {"config.json", "model.safetensors", "tokenizer.json"}
    if not isinstance(files, Mapping) or not required.issubset(files):
        raise ValueError("pin must include configuration, weights, and tokenizer identities")
    for name, record in files.items():
        if not isinstance(name, str) or not isinstance(record, Mapping):
            raise ValueError("invalid pinned file record")
        if type(record.get("bytes")) is not int or record["bytes"] < 0:
            raise ValueError("pinned file sizes must be nonnegative integers")
        if not isinstance(record.get("sha256"), str) or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"]):
            raise ValueError("pinned files require SHA-256 digests")
    # Preserve the supplied record, but sever mutable aliases and reject NaNs or
    # non-JSON values. File verification is the intake module's responsibility.
    return json.loads(canonical(dict(pin)))


def build_repetition_study(tokenizer, config, pin):
    """Return a deterministic registration and an ``evaluate``-compatible spec.

    ``tokenizer`` must have ``encode(text, add_special_tokens=False)``. Use the
    tokenizer from the locally verified pin. Every fixed case must tokenize to
    the expected five single-word tokens; a mismatch stops the entire builder.
    Cases are never silently dropped or replaced to obtain a favorable result.
    """
    model_identity = _pin_copy(pin)
    if not isinstance(config, Mapping) or any(config.get(k) != v for k, v in {
        "model_type": "gpt2", "n_layer": 6, "n_head": 12, "n_embd": 768,
        "vocab_size": 50257,
    }.items()):
        raise ValueError("the fixed study requires the standard six-layer DistilGPT2 configuration")
    if not callable(getattr(tokenizer, "encode", None)):
        raise ValueError("supply a local tokenizer with an encode method")

    def encode(text):
        value = tokenizer.encode(text, add_special_tokens=False)
        # The Rust tokenizers API returns Encoding; the Transformers API returns
        # list[int]. Both are supported without importing either dependency.
        ids = getattr(value, "ids", value)
        if not isinstance(ids, (list, tuple)) or not ids or any(
            type(x) is not int or not 0 <= x < config["vocab_size"] for x in ids
        ):
            raise ValueError("tokenizer returned invalid token IDs")
        return list(ids)

    cases = []
    for name, split, anchor, target, alternative in PATTERNS:
        clean_text = f" {anchor} {target} {anchor} {target} {anchor}"
        corrupt_text = f" {anchor} {alternative} {anchor} {alternative} {anchor}"
        clean, corrupt = encode(clean_text), encode(corrupt_text)
        target_ids, alternative_ids = encode(" " + target), encode(" " + alternative)
        if len(clean) != 5 or len(corrupt) != 5 or len(target_ids) != 1 or len(alternative_ids) != 1:
            raise ValueError("a fixed case does not have the required single-token words: " + name)
        if target_ids == alternative_ids or clean == corrupt:
            raise ValueError("the tokenizer collapsed distinct answer alternatives: " + name)
        if not (clean[0] == clean[2] == clean[4] == corrupt[0] == corrupt[2] == corrupt[4]
                and clean[1] == clean[3] == target_ids[0]
                and corrupt[1] == corrupt[3] == alternative_ids[0]):
            raise ValueError("tokenization does not preserve the registered repeated-token pattern: " + name)
        cases.append({
            "id": "repeat_" + name, "split": split,
            "clean_text": clean_text, "corrupt_text": corrupt_text,
            "target_text": " " + target, "alternative_text": " " + alternative,
            "clean_ids": clean, "corrupt_ids": corrupt,
            "target_id": target_ids[0], "alternative_id": alternative_ids[0],
            "positions": [4],
        })
    sites = [f"blocks.{layer}.mlp_out" for layer in range(6)]
    spec = {
        "schema": "wolftrap.neuralscope.cases/v1",
        "claim_scope": "six predeclared repeated-token contrasts in one pinned pretrained DistilGPT2; final-position MLP patches only",
        "minimum_gap": 0.05,
        "sites": sites,
        "cases": cases,
    }
    tokenizer_files = {name: record for name, record in model_identity["files"].items()
                       if name in {"tokenizer.json", "tokenizer_config.json", "vocab.json", "merges.txt"}}
    return {
        "schema": SCHEMA,
        "title": "DistilGPT2 fixed repeated-token continuation study",
        "builder_performs_inference": False,
        "freeze_requirement": "write and retain this registration's SHA-256 before the first pretrained-model inference; no independent timestamp is asserted",
        "model_identity": model_identity,
        "tokenizer_identity": {"repo_id": model_identity["repo_id"], "revision": model_identity["revision"],
                               "files": tokenizer_files, "add_special_tokens": False},
        "cases": spec,
        "protocol": {
            "hypothesis": "copying a final-position MLP output from the clean to the changed pattern can increase the clean continuation's logit contrast",
            "metric": "final-token logit(target) minus logit(alternative)",
            "normalization": "(patched_corrupt_margin-corrupt_margin)/(clean_margin-corrupt_margin)",
            "minimum_baseline_gap": 0.05,
            "relative_gap_floor": "1e-5 * max(abs(clean_margin),abs(corrupt_margin),1)",
            "baseline_behavior_support": "report clean_margin>0 and corrupt_margin<0 separately from a positive clean-minus-corrupt gap",
            "selection": "largest mean normalized restoration among all six MLP sites with all three discovery cases normalizable; select no site unless the best mean is strictly positive",
            "selection_tie_break": "first site in the predeclared ascending-layer list",
            "validation": "report the selected site's three untouched validation cases and every tested site; never select or adjust cases using validation outcomes",
            "controls": ["clean self-copy", "corrupt self-copy", "reverse donor patch", "zero ablation"],
            "inactive_control": "none: no pretrained component is assumed inactive",
            "self_patch_margin_atol": 1e-6,
            "retain_all_cases": True,
            "exclude_or_rewrite_failed_cases": False,
            "study_forward_passes": 192,
            "population_confidence_interval": None,
            "limits": ["six related synthetic contrasts are not independent population samples",
                       "selected sites are whole MLP outputs, not individual neurons or a complete circuit",
                       "zero ablation may be outside the model's ordinary activation distribution",
                       "restoration ratios are unbounded effect measures, not probabilities or safety scores"],
        },
        "reference_comparison": {
            "arithmetic": "CPU float32; deterministic evaluation; eager attention; no KV cache",
            "baseline_cases": "both inputs of all six cases, twelve full-logit arrays",
            "intervention_case": "repeat_colors",
            "intervention_positions": [4],
            "intervention_sites": ["blocks.0.attn.head.0", "blocks.2.attn.head.0", "blocks.5.attn.head.0", *sites],
            "intervention_operations": ["restore", "reverse", "self_clean", "self_corrupt", "ablate"],
            "forward_passes_per_engine": 57,
            "additional_unhooked_reference_baselines": 12,
            "total_reference_forward_passes": 69,
            "patch_donor_policy": "each engine uses its own captured donor and recipient; baseline activation discrepancies are checked separately",
            "full_logit_max_abs_error": 1e-3,
            "full_logit_rmse": 1e-4,
            "activation_atol": 2e-4,
            "activation_rtol": 2e-4,
            "self_patch_margin_atol": 1e-6,
            "hooked_baseline_vs_unhooked": "bitwise identical",
            "argmax_requirement": "not a gate: numerical tolerance and near-tie margins are reported",
            "failure_policy": "retain the failing comparison and stop interpretation; changing tolerances requires a separate declared experiment",
        },
    }


def write_registration(path, registration):
    """Write a new registration; return the digest of its canonical bytes."""
    if not isinstance(registration, dict) or registration.get("schema") != SCHEMA:
        raise ValueError("unsupported study registration")
    data = canonical(registration)
    write_json(path, registration)
    return hashlib.sha256(data).hexdigest()


def assess_behavior(result, registration):
    """Describe baseline support and discovery/validation effects without filtering.

    This summarizes a completed numeric experiment; it is not a replacement for
    evidence verification or replay. Results must contain every registered case
    in order and every registered site. Nonfinite measurements are rejected.
    """
    if not isinstance(registration, dict) or registration.get("schema") != SCHEMA:
        raise ValueError("unsupported study registration")
    spec = registration["cases"]
    expected_cases, sites = spec["cases"], spec["sites"]
    if not isinstance(result, dict) or result.get("schema") != "wolftrap.neuralscope.local-result/v1":
        raise ValueError("unsupported study result")
    rows = result.get("cases")
    if not isinstance(rows, list) or len(rows) != len(expected_cases):
        raise ValueError("the result must retain every registered case")
    finite = lambda x: type(x) in (float, int) and math.isfinite(x)
    records, selected_scores = [], {site: {"discovery": [], "validation": []} for site in sites}
    for row, case in zip(rows, expected_cases, strict=True):
        if not isinstance(row, dict) or row.get("id") != case["id"] or row.get("split") != case["split"]:
            raise ValueError("study cases or split assignments differ from the registration")
        clean, corrupt, gap = row.get("clean_margin"), row.get("corrupt_margin"), row.get("baseline_gap")
        if not all(finite(x) for x in (clean, corrupt, gap)) or not math.isclose(gap, clean-corrupt, rel_tol=1e-9, abs_tol=1e-9):
            raise ValueError("invalid baseline margins")
        threshold = max(float(spec["minimum_gap"]), 1e-5 * max(abs(clean), abs(corrupt), 1.0))
        valid = gap > threshold
        interventions = row.get("interventions")
        if not isinstance(interventions, list) or [r.get("site") for r in interventions if isinstance(r, dict)] != sites:
            raise ValueError("the result must retain every registered intervention site")
        if row.get("normalization_valid") is not valid:
            raise ValueError("normalization differs from the registered threshold")
        for intervention in interventions:
            restored = intervention.get("restored_margin")
            if not finite(restored):
                raise ValueError("invalid restored margin")
            normalized = (restored-corrupt)/gap if valid else None
            recorded = intervention.get("normalized_restoration")
            if ((normalized is None and recorded is not None)
                or (normalized is not None and (not finite(recorded) or not math.isclose(normalized, recorded, rel_tol=1e-8, abs_tol=1e-8)))):
                raise ValueError("restoration normalization differs from retained margins")
            selected_scores[intervention["site"]][case["split"]].append(normalized)
        records.append({"id": case["id"], "split": case["split"], "clean_margin": clean,
                        "corrupt_margin": corrupt, "baseline_gap": gap,
                        "clean_prefers_target": clean > 0, "corrupt_prefers_alternative": corrupt < 0,
                        "both_answer_preferences_present": clean > 0 and corrupt < 0,
                        "positive_normalizable_contrast": valid})
    ranking = []
    for site in sites:
        discovery = selected_scores[site]["discovery"]
        eligible = all(v is not None for v in discovery)
        ranking.append({"site": site, "discovery_usable_cases": sum(v is not None for v in discovery),
                        "discovery_mean": sum(discovery)/len(discovery) if eligible else None,
                        "validation_values": selected_scores[site]["validation"]})
    candidates = [item for item in ranking if item["discovery_mean"] is not None and item["discovery_mean"] > 0]
    selected = max(candidates, key=lambda item: item["discovery_mean"])["site"] if candidates else None
    if result.get("selected_site_using_discovery_only") != selected:
        raise ValueError("result selection differs from the registered discovery-only rule")
    selected_validation = selected_scores[selected]["validation"] if selected else []
    usable_validation = [value for value in selected_validation if value is not None]
    return {
        "schema": "wolftrap.neuralscope.pretrained-behavior/v1",
        "registration_sha256": hashlib.sha256(canonical(registration)).hexdigest(),
        "case_count": len(records), "cases": records,
        "split_summary": {split: {
            "cases": sum(row["split"] == split for row in records),
            "both_answer_preferences_present": sum(row["split"] == split and row["both_answer_preferences_present"] for row in records),
            "positive_normalizable_contrasts": sum(row["split"] == split and row["positive_normalizable_contrast"] for row in records),
        } for split in ("discovery", "validation")},
        "tested_sites": ranking,
        "selected_site": selected,
        "selected_validation_cases": len(selected_validation),
        "selected_validation_usable_cases": len(usable_validation),
        "selected_validation_mean": sum(usable_validation)/len(usable_validation) if len(usable_validation) == len(selected_validation) and usable_validation else None,
        "selection_outcome": "POSITIVE_DISCOVERY_EFFECT" if selected else "NO_POSITIVE_FULL_DISCOVERY_SELECTION",
        "all_cases_retained": True,
        "claim": "finite predeclared repeated-token contrasts and tested MLP outputs only; no population inference or security certification",
    }

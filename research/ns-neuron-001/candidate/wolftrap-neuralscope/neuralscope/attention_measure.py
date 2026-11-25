"""Bounded staged attention-head measurements using a frozen local protocol.

This module performs no downloads and never selects a head. Discovery visits only
registered discovery inputs. Validation requires an already selected registered
head. Opposite orientations reuse the same numeric baselines. Full baseline logits
and activations are retained; interventions retain their complete final-vocabulary
vector after checking that all earlier token logits are bitwise unchanged.

``output`` creates a fresh phase directory with traces and result.json. ``replay``
recomputes every retained numeric array and the phase report against that directory.
Any measurement, reference, self-control, or prefix-invariance failure stops the
phase, retaining the completed observations and marking the report incomplete.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import re

import numpy as np

from .evidence import canonical, read_json, write_json
from .experiment import _compare_trace, _save_arrays
from .qualification import _compare_result, compare_forward


MAX_CASES = 24
MAX_HEADS = 72
MAX_SEQUENCE = 5
MAX_VOCABULARY = 50257
MAX_BASELINE_BYTES = 128 * 1024 * 1024
MAX_STAGE_TRACE_BYTES = 384 * 1024 * 1024
OPERATIONS = ("restore", "reverse", "self_clean", "self_changed", "ablate")


def token_observation(final_logits, target_id, alternative_id, tokenizer):
    """Describe a full-vocabulary result; exact ties share competition rank."""
    values = np.asarray(final_logits)
    if (values.ndim != 1 or not 2 <= values.size <= MAX_VOCABULARY
            or values.dtype != np.float32 or not np.isfinite(values).all()):
        raise ValueError("observation requires a bounded finite float32 vocabulary vector")
    if (type(target_id) is not int or type(alternative_id) is not int
            or target_id == alternative_id
            or not 0 <= target_id < values.size or not 0 <= alternative_id < values.size):
        raise ValueError("observation answer IDs must be distinct vocabulary integers")
    target, alternative = float(values[target_id]), float(values[alternative_id])
    margin = target - alternative
    top = int(np.argmax(values))
    token = tokenizer.decode([top], skip_special_tokens=False)
    if not isinstance(token, str) or len(token) > 4096:
        raise ValueError("tokenizer returned an invalid token display")
    return {"target_id": target_id, "alternative_id": alternative_id,
            "target_logit": target, "alternative_logit": alternative, "margin": margin,
            "target_rank": 1 + int(np.count_nonzero(values > values[target_id])),
            "alternative_rank": 1 + int(np.count_nonzero(values > values[alternative_id])),
            "top_id": top, "top_token": token,
            "preference": "target" if margin > 0 else "alternative" if margin < 0 else "tie",
            "target_is_global_top": bool(values[target_id] == values[top]),
            "global_top_tie_count": int(np.count_nonzero(values == values[top]))}


def _checked_inputs(candidate, reference, tokenizer, protocol, stage, selected_site):
    if not isinstance(protocol, dict) or not callable(getattr(tokenizer, "decode", None)):
        raise ValueError("supply a protocol mapping and local tokenizer")
    cases, sites = protocol.get("cases"), protocol.get("sites")
    if not isinstance(cases, list) or not 1 <= len(cases) <= MAX_CASES:
        raise ValueError("attention protocol requires at most24 cases")
    if (not isinstance(sites, list) or not 1 <= len(sites) <= MAX_HEADS
            or len(set(sites)) != len(sites)
            or any(not isinstance(s, str) or not re.fullmatch(r"blocks\.\d+\.attn\.head\.\d+", s) for s in sites)):
        raise ValueError("attention protocol requires unique bounded head sites")
    expected = [site for site in candidate.sites if ".attn.head." in site]
    if sites != expected or tuple(candidate.sites) != tuple(reference.sites):
        raise ValueError("protocol must enumerate every head in model order; both engines must agree")
    if (candidate.n_embd != reference.n_embd or candidate.config["vocab_size"] != reference.config["vocab_size"]
            or not 2 <= candidate.config["vocab_size"] <= MAX_VOCABULARY):
        raise ValueError("candidate/reference dimensions differ or exceed attention-study bounds")
    if stage == "validation" and selected_site not in sites:
        raise ValueError("validation requires one previously selected registered head")
    gap = protocol.get("minimum_gap")
    if type(gap) not in (float, int) or not np.isfinite(gap) or gap <= 0:
        raise ValueError("minimum gap must be finite and positive")
    gates = protocol.get("reference_comparison")
    if not isinstance(gates, dict):
        raise ValueError("reference comparison gates missing")
    tolerance = gates.get("self_patch_margin_atol")
    if type(tolerance) not in (float, int) or not np.isfinite(tolerance) or tolerance < 0:
        raise ValueError("self-patch tolerance must be finite and nonnegative")
    # Validate common numerical gates without invoking either model.
    dummy = {"logits": np.zeros((1, 2), np.float32), "activations": {}}
    compare_forward(dummy, dummy, gates, include_activations=False)
    ids, coordinates = set(), set()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("attention case must be a mapping")
        name = case.get("id")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", name) or name in ids:
            raise ValueError("attention case IDs must be unique safe names")
        ids.add(name)
        if (case.get("split") not in ("discovery", "validation")
                or case.get("condition") not in ("repeat", "control")
                or case.get("orientation") not in ("forward", "reverse")
                or not isinstance(case.get("group_id"), str)):
            raise ValueError("invalid attention case grouping")
        coord = (case["split"], case["group_id"], case["condition"], case["orientation"])
        if coord in coordinates:
            raise ValueError("duplicate attention case coordinate")
        coordinates.add(coord)
        if case.get("positions") != [MAX_SEQUENCE - 1]:
            raise ValueError("attention study patches only position4 of five-token inputs")
        for key in ("clean_ids", "changed_ids"):
            values = case.get(key)
            if (not isinstance(values, list) or len(values) != MAX_SEQUENCE or any(
                    type(v) is not int or not 0 <= v < candidate.config["vocab_size"] for v in values)):
                raise ValueError("attention inputs require exactly five valid token IDs")
        if case["clean_ids"] == case["changed_ids"]:
            raise ValueError("paired inputs must differ")
        for key in ("target_id", "alternative_id"):
            value = case.get(key)
            if type(value) is not int or not 0 <= value < candidate.config["vocab_size"]:
                raise ValueError("invalid answer token")
        if case["target_id"] == case["alternative_id"]:
            raise ValueError("answer token IDs must differ")
    selected = [case for case in cases if case["split"] == stage]
    if not selected or len(selected) > 12:
        raise ValueError("phase requires one to twelve registered cases")
    unique = {tuple(case[key]) for case in selected for key in ("clean_ids", "changed_ids")}
    if len(unique) > 12:
        raise ValueError("phase requires at most twelve unique numeric baselines")
    # Both engines' logits and every activation are retained; include unhooked
    # reference logits in the estimate. No external allocation uses these values.
    baseline_bytes = len(unique) * 4 * MAX_SEQUENCE * (
        3 * candidate.config["vocab_size"] + 2 * candidate.n_embd * len(candidate.sites))
    if baseline_bytes > MAX_BASELINE_BYTES:
        raise ValueError("baseline evidence exceeds128MiB bound")
    patch_vectors = len(selected) * (len(sites) if stage == "discovery" else 2 * len(OPERATIONS))
    if stage == "discovery":
        patch_vectors += len(sites)
    estimated_trace = baseline_bytes + patch_vectors * candidate.config["vocab_size"] * 4
    if estimated_trace > MAX_STAGE_TRACE_BYTES:
        raise ValueError("attention stage traces exceed384MiB bound")
    return selected, sites, gates, int(estimated_trace)


def _checked_forward(result, model, length, *, capture):
    if not isinstance(result, dict) or set(result) != {"logits", "activations"}:
        raise ValueError("unexpected attention forward output inventory")
    logits, activations = result["logits"], result["activations"]
    if (not isinstance(logits, np.ndarray) or logits.dtype != np.float32
            or logits.shape != (length, model.config["vocab_size"]) or not np.isfinite(logits).all()
            or not isinstance(activations, dict)):
        raise ValueError("invalid attention forward output")
    if not capture:
        if activations:
            raise ValueError("intervention must not retain unrequested captures")
        return result
    if set(activations) != set(model.sites):
        raise ValueError("baseline activation inventory differs from model sites")
    for value in activations.values():
        if (not isinstance(value, np.ndarray) or value.dtype != np.float32
                or value.shape != (length, model.n_embd) or not np.isfinite(value).all()):
            raise ValueError("invalid baseline activation array")
    return result


def _replacement(case, cache, engine, site, operation):
    if operation == "restore":
        recipient, donor = "changed", "clean"
    elif operation == "reverse":
        recipient, donor = "clean", "changed"
    elif operation == "self_changed":
        recipient = donor = "changed"
    else:
        recipient = donor = "clean"
    tokens = case[recipient + "_ids"]
    baseline = cache[tuple(tokens)][engine]
    patch = baseline["activations"][site].copy()
    patch[case["positions"]] = (0 if operation == "ablate" else
        cache[tuple(case[donor + "_ids"])][engine]["activations"][site][case["positions"]])
    return tokens, patch, baseline, recipient


def _run_stage(candidate, reference, tokenizer, protocol, stage, selected_site,
               *, output=None, replay=None, progress=None):
    cases, sites, gates, estimated_trace = _checked_inputs(candidate, reference, tokenizer, protocol, stage, selected_site)
    if output is not None and replay is not None:
        raise ValueError("output and replay are mutually exclusive")
    if progress is not None and not callable(progress):
        raise ValueError("progress callback must be callable")
    output = Path(output) if output is not None else None
    replay = Path(replay) if replay is not None else None
    if output is not None:
        output.mkdir(parents=True, mode=0o700, exist_ok=False)
        (output / "traces").mkdir(mode=0o700)
    if replay is not None and not replay.is_dir():
        raise ValueError("replay phase directory does not exist")
    counts = {"candidate_baseline": 0, "candidate_intervention": 0,
              "reference_baseline": 0, "reference_unhooked": 0, "reference_intervention": 0}
    report = {"schema": "wolftrap.neuralscope.attention-measure/v1", "stage": stage,
              "protocol_sha256": hashlib.sha256(canonical(protocol)).hexdigest(),
              "status": "FAIL", "completed": False, "selected_site": selected_site,
              "records": [], "baseline_records": [], "failures": [], "counts": counts,
              "count_scope": "forward call attempts; successful phases complete every counted call",
              "estimated_numeric_trace_bytes": estimated_trace,
              "intervention_donors": "each engine's native recorded baseline activations",
              "rank_definition": "one plus count of strictly higher logits; ties share rank",
              "stored_interventions": "full final-vocabulary vectors; earlier-position bitwise invariance checked",
              "api_requests": 0, "network_requests": 0}
    cache = {}
    parity_records = []
    first_reference_case = next((case["id"] for case in cases if case["condition"] == "repeat"
                                 and case["orientation"] == "forward"), None)
    if first_reference_case is None:
        raise ValueError("phase has no repeated forward case")
    if (stage == "discovery" and gates.get("discovery_intervention_case", first_reference_case)
            != first_reference_case):
        raise ValueError("reference intervention case differs from the first registered repeated forward case")
    report["reference_intervention_case"] = first_reference_case if stage == "discovery" else "all validation cases"

    def save_trace(name, arrays):
        if output is not None:
            _save_arrays(output / "traces" / (name + ".npz"), arrays)
        if replay is not None:
            _compare_trace(replay / "traces" / (name + ".npz"), arrays)

    def emit(event, **values):
        if progress is not None:
            progress({"stage": stage, "event": event, **values, "counts": dict(counts)})

    def fail(kind, **values):
        report["failures"].append({"kind": kind, **values})

    try:
        # This loop sees only this stage's registered inputs, before any head scan.
        for case in cases:
            for side in ("clean", "changed"):
                tokens = case[side + "_ids"]
                key = tuple(tokens)
                if key in cache:
                    continue
                name = f"baseline-{len(cache):03d}"
                counts["candidate_baseline"] += 1
                actual = _checked_forward(candidate.forward(tokens), candidate, len(tokens), capture=True)
                counts["reference_baseline"] += 1
                expected = _checked_forward(reference.forward(tokens), reference, len(tokens), capture=True)
                counts["reference_unhooked"] += 1
                unhooked = _checked_forward(reference.forward_unhooked(tokens), reference, len(tokens), capture=False)
                comparison = compare_forward(actual, expected, gates, include_activations=True)
                invariant = bool(np.array_equal(expected["logits"], unhooked["logits"]))
                record = {"id": name, "token_ids": tokens, **comparison,
                          "reference_hooks_preserve_logits_bitwise": invariant}
                if not invariant:
                    record["status"] = "FAIL"
                report["baseline_records"].append(record)
                parity_records.append(record)
                arrays = {"candidate.logits": actual["logits"], "reference.logits": expected["logits"],
                          "reference.unhooked_logits": unhooked["logits"]}
                for label, result in (("candidate", actual), ("reference", expected)):
                    arrays.update({label + "." + site: value for site, value in result["activations"].items()})
                save_trace(name, arrays)
                cache[key] = {"id": name, "candidate": actual, "reference": expected}
                emit("baseline", baseline=name)
                if record["status"] != "PASS":
                    fail("BASELINE_REFERENCE_COMPARISON", baseline=name)
                    break
            if report["failures"]:
                break
        chosen_sites = sites if stage == "discovery" else [selected_site]
        operations = ("restore",) if stage == "discovery" else OPERATIONS
        for case in cases:
            if report["failures"]:
                break
            case_arrays = {}
            actual_bases = {side: cache[tuple(case[side + "_ids"])]["candidate"] for side in ("clean", "changed")}
            base_observations = {side: token_observation(run["logits"][-1], case["target_id"],
                                                        case["alternative_id"], tokenizer)
                                 for side, run in actual_bases.items()}
            clean_margin, changed_margin = (base_observations[x]["margin"] for x in ("clean", "changed"))
            gap = clean_margin - changed_margin
            for index, site in enumerate(chosen_sites):
                for operation in operations:
                    tokens, patch, recipient_baseline, recipient = _replacement(case, cache, "candidate", site, operation)
                    counts["candidate_intervention"] += 1
                    actual = _checked_forward(candidate.forward(tokens, patches={site: patch}, capture=False),
                                              candidate, len(tokens), capture=False)
                    actual_observation = token_observation(actual["logits"][-1], case["target_id"],
                                                           case["alternative_id"], tokenizer)
                    earlier_unchanged = bool(np.array_equal(actual["logits"][:-1], recipient_baseline["logits"][:-1]))
                    row = {key: case[key] for key in ("id", "group_id", "split", "condition", "orientation")}
                    row.update({"site": site, "operation": operation, "status": "PASS",
                                "clean_baseline": cache[tuple(case["clean_ids"])]["id"],
                                "changed_baseline": cache[tuple(case["changed_ids"])]["id"],
                                "clean_margin": clean_margin, "changed_margin": changed_margin,
                                "baseline_gap": gap, "normalization_valid": gap > protocol["minimum_gap"],
                                "result_margin": actual_observation["margin"],
                                "effect_delta_from_recipient": actual_observation["margin"] - base_observations[recipient]["margin"],
                                "candidate_clean": base_observations["clean"],
                                "candidate_changed": base_observations["changed"],
                                "candidate_result": actual_observation,
                                "earlier_logits_unchanged": earlier_unchanged,
                                "reference_checked": stage == "validation" or case["id"] == first_reference_case})
                    if operation == "restore":
                        delta = actual_observation["margin"] - changed_margin
                        row.update({"restored_margin": actual_observation["margin"], "restoration_delta": delta,
                                    "normalized_restoration": delta / gap if gap > protocol["minimum_gap"] else None,
                                    "both_baseline_preferences_present": clean_margin > 0 and changed_margin < 0,
                                    "target_preference_restored": clean_margin > 0 and changed_margin < 0 and actual_observation["margin"] > 0,
                                    "global_top_matches_clean": actual_observation["top_id"] == base_observations["clean"]["top_id"]})
                    if operation.startswith("self_"):
                        row["self_margin_delta"] = abs(row["effect_delta_from_recipient"])
                        row["self_final_logits_bitwise_unchanged"] = bool(np.array_equal(actual["logits"][-1], recipient_baseline["logits"][-1]))
                        if row["self_margin_delta"] > gates["self_patch_margin_atol"]:
                            fail("CANDIDATE_SELF_CONTROL", case=case["id"], site=site, operation=operation)
                            row["status"] = "FAIL"
                    if not earlier_unchanged:
                        fail("CANDIDATE_EARLIER_LOGITS_CHANGED", case=case["id"], site=site, operation=operation)
                        row["status"] = "FAIL"
                    key = operation + "." + site
                    case_arrays["candidate." + key + ".final_logits"] = actual["logits"][-1].copy()
                    report["records"].append(row)
                    if row["reference_checked"]:
                        ref_tokens, ref_patch, ref_base, ref_recipient = _replacement(case, cache, "reference", site, operation)
                        if ref_tokens != tokens or ref_recipient != recipient:
                            raise ValueError("reference intervention recipe differs")
                        counts["reference_intervention"] += 1
                        expected = _checked_forward(reference.forward(ref_tokens, patches={site: ref_patch}, capture=False),
                                                    reference, len(ref_tokens), capture=False)
                        comparison = compare_forward(actual, expected, gates, include_activations=False)
                        ref_unchanged = bool(np.array_equal(expected["logits"][:-1], ref_base["logits"][:-1]))
                        row["reference_earlier_logits_unchanged"] = ref_unchanged
                        row["reference_comparison"] = comparison
                        row["reference_result"] = token_observation(expected["logits"][-1], case["target_id"],
                                                                    case["alternative_id"], tokenizer)
                        parity_records.append(comparison)
                        case_arrays["reference." + key + ".final_logits"] = expected["logits"][-1].copy()
                        if comparison["status"] != "PASS":
                            fail("INTERVENTION_REFERENCE_COMPARISON", case=case["id"], site=site, operation=operation)
                            row["status"] = "FAIL"
                        if not ref_unchanged:
                            fail("REFERENCE_EARLIER_LOGITS_CHANGED", case=case["id"], site=site, operation=operation)
                            row["status"] = "FAIL"
                        if operation.startswith("self_"):
                            original = token_observation(ref_base["logits"][-1], case["target_id"], case["alternative_id"], tokenizer)
                            row["reference_self_margin_delta"] = abs(row["reference_result"]["margin"] - original["margin"])
                            row["reference_self_final_logits_bitwise_unchanged"] = bool(np.array_equal(expected["logits"][-1], ref_base["logits"][-1]))
                            if row["reference_self_margin_delta"] > gates["self_patch_margin_atol"]:
                                fail("REFERENCE_SELF_CONTROL", case=case["id"], site=site, operation=operation)
                                row["status"] = "FAIL"
                    if report["failures"]:
                        break
                last_in_layer = index == len(chosen_sites) - 1 or chosen_sites[index + 1].split(".")[1] != site.split(".")[1]
                if last_in_layer or report["failures"]:
                    emit("layer", case=case["id"], layer=int(site.split(".")[1]))
                if report["failures"]:
                    break
            save_trace("trial-" + case["id"], case_arrays)
        report["completed"] = not report["failures"]
        report["status"] = "PASS" if report["completed"] else "FAIL"
    except Exception as exc:
        # Replay mismatches remain exceptions; do not mask them with a new report.
        if replay is not None:
            raise
        fail("EXECUTION", exception=type(exc).__name__, detail=str(exc)[:512])
        if report["records"] and report["records"][-1].get("reference_checked") and "reference_comparison" not in report["records"][-1]:
            report["records"][-1]["status"] = "INCOMPLETE"
        # A case may have already produced useful arrays when a later call fails.
        if output is not None and "case_arrays" in locals() and case_arrays:
            path = output / "traces" / ("trial-" + case["id"] + ".npz")
            if not path.exists():
                _save_arrays(path, case_arrays)
    counts["candidate_total"] = counts["candidate_baseline"] + counts["candidate_intervention"]
    counts["reference_total"] = counts["reference_baseline"] + counts["reference_unhooked"] + counts["reference_intervention"]
    activation_rows = [item for row in report["baseline_records"] for item in row["activations"]]
    report["parity"] = {
        "status": "PASS" if parity_records and all(r["status"] == "PASS" for r in parity_records) else "FAIL",
        "baseline_comparisons": len(report["baseline_records"]),
        "intervention_comparisons": len(parity_records) - len(report["baseline_records"]),
        "maximum_logit_absolute_error": max((r["logits"]["max_abs_error"] for r in parity_records), default=None),
        "maximum_logit_rmse": max((r["logits"]["rmse"] for r in parity_records), default=None),
        "maximum_activation_absolute_error": max((r["max_abs_error"] for r in activation_rows), default=None),
        "maximum_activation_scaled_error": max((r["max_scaled_error"] for r in activation_rows), default=None),
        "reference_hooks_bitwise_invariant": bool(report["baseline_records"]) and all(
            row["reference_hooks_preserve_logits_bitwise"] for row in report["baseline_records"])}
    if output is not None:
        write_json(output / "result.json", report)
    if replay is not None:
        _compare_result(read_json(replay / "result.json"), report, stage)
    return report


def discovery(candidate, reference, tokenizer, protocol, *, output=None, replay=None, progress=None):
    """Scan all registered heads on discovery data; select nothing here."""
    return _run_stage(candidate, reference, tokenizer, protocol, "discovery", None,
                      output=output, replay=replay, progress=progress)


def validation(candidate, reference, tokenizer, protocol, selected_site, *, output=None, replay=None, progress=None):
    """Test one previously selected head on held-out inputs and five operations."""
    return _run_stage(candidate, reference, tokenizer, protocol, "validation", selected_site,
                      output=output, replay=replay, progress=progress)

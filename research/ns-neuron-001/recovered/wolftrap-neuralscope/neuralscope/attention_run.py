"""Frozen attention discovery, held-out measurement, and full numeric replay.

The first phase never forwards a validation input. A complete discovery result
and the fixed rule determine a fresh selection receipt before validation starts.
Replay derives the phase schedule again; saved success/skip flags cannot change
which computations are required. All pretrained assets remain external and pinned.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import time

import numpy as np

from . import __version__
from .attention_protocol import assess_validation, build_attention_protocol, select_head, write_protocol
from .evidence import canonical, digest, read_json, seal, verify, write_json
from .experiment import source_identity
from .qualification import _compare_result, _models, resource


def _registration(model_dir):
    from tokenizers import Tokenizer
    from .pretrained import load_pin, verify_model
    directory = Path(model_dir)
    identity = verify_model(directory)
    config = read_json(directory / "config.json")
    tokenizer = Tokenizer.from_file(str(directory / "tokenizer.json"))
    protocol = build_attention_protocol(tokenizer, config, load_pin())
    return config, tokenizer, protocol, identity


def prepare_attention_protocol(model_dir, output):
    """Only verify files and tokenize fixed text; do not instantiate a model."""
    _, _, protocol, identity = _registration(model_dir)
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    protocol_sha = write_protocol(output, protocol)
    return {"status": "ATTENTION_PROTOCOL_FROZEN", "version": __version__,
            "protocol_sha256": protocol_sha, "protocol": str(output),
            "model_revision": identity["revision"], "heads": len(protocol["sites"]),
            "forward_pass_counts": protocol["forward_pass_counts"],
            "model_inference_calls": 0, "network_requests": 0, "api_requests": 0,
            "claim": "local predeclared plan, not an independently timestamped registry"}


def _checked_registration(model_dir, path):
    config, tokenizer, expected, identity = _registration(model_dir)
    protocol = read_json(path)
    if canonical(protocol) != canonical(expected):
        raise ValueError("attention protocol differs from this version's fixed experiment")
    return config, tokenizer, protocol, identity


def _passed(stage):
    return (stage.get("status") == "PASS" and stage.get("completed") is True
            and stage.get("parity", {}).get("status") == "PASS")


def _check_complete_counts(stage, protocol):
    """A short or silently skipped successful stage cannot be interpreted."""
    if not _passed(stage):
        return
    name = stage["stage"]
    expected = protocol["forward_pass_counts"]
    suffix = "restore_passes" if name == "discovery" else "interventions"
    counts = {
        "candidate_baseline": expected[name + "_unique_baselines"],
        "candidate_intervention": expected[name + "_candidate_" + suffix],
        "reference_baseline": expected[name + "_reference_hooked_baselines"],
        "reference_unhooked": expected[name + "_reference_unhooked_baselines"],
        "reference_intervention": expected[name + "_reference_" + ("restore_passes" if name == "discovery" else "interventions")],
        "candidate_total": expected[name + "_candidate_total"],
        "reference_total": expected[name + "_reference_total"],
    }
    if canonical(stage.get("counts")) != canonical(counts):
        raise ValueError("successful attention stage has unexpected forward-pass counts")
    if len(stage.get("records", [])) != counts["candidate_intervention"]:
        raise ValueError("successful attention stage is missing intervention records")
    if len(stage.get("baseline_records", [])) != counts["candidate_baseline"]:
        raise ValueError("successful attention stage is missing baseline comparisons")


def _selection(discovery, protocol):
    _check_complete_counts(discovery, protocol)
    return select_head(discovery["records"], protocol) if _passed(discovery) else None


def _validation_summary(discovery, selection, validation, protocol):
    if not _passed(discovery):
        if selection is not None or validation is not None:
            raise ValueError("selection or validation cannot follow failed discovery")
        return {"status": "NOT_RUN_DISCOVERY_FAILED", "selected_site": None,
                "descriptive_criteria_met": None}
    selected = selection["selected_site"]
    if selected is None:
        if validation is not None:
            raise ValueError("validation cannot run without an eligible discovery head")
        return assess_validation([], protocol, None)
    if validation is None:
        raise ValueError("a selected head requires a validation attempt")
    _check_complete_counts(validation, protocol)
    if not _passed(validation):
        return {"status": "INCONCLUSIVE_VALIDATION_FAILED", "selected_site": selected,
                "descriptive_criteria_met": None, "completed_records": len(validation["records"])}
    return assess_validation(validation["records"], protocol, selected)


def _scientific_result(identity, protocol, candidate, reference, exclusions,
                       discovery, selection, validation):
    summary = _validation_summary(discovery, selection, validation, protocol)
    stages = [discovery] + ([validation] if validation is not None else [])
    maxima = ("maximum_logit_absolute_error", "maximum_logit_rmse",
              "maximum_activation_absolute_error", "maximum_activation_scaled_error")
    parity = {name: max((stage["parity"][name] for stage in stages
                        if stage["parity"][name] is not None), default=None) for name in maxima}
    parity.update({"status": "PASS" if all(_passed(stage) for stage in stages) else "FAIL",
                   "baseline_comparisons": sum(stage["parity"]["baseline_comparisons"] for stage in stages),
                   "intervention_comparisons": sum(stage["parity"]["intervention_comparisons"] for stage in stages),
                   "reference_hooks_bitwise_invariant": all(stage["parity"]["reference_hooks_bitwise_invariant"] for stage in stages),
                   "earlier_logits_bitwise_unchanged": all(row["earlier_logits_unchanged"]
                        and row.get("reference_earlier_logits_unchanged", True)
                        for stage in stages for row in stage["records"])
                        if any(stage["records"] for stage in stages) else None,
                   "self_patch_max_margin_delta": max((row[key] for stage in stages for row in stage["records"]
                        for key in ("self_margin_delta", "reference_self_margin_delta") if key in row), default=None)})
    complete = all(_passed(stage) for stage in stages)
    protocol_sha = hashlib.sha256(canonical(protocol)).hexdigest()
    selection_sha = hashlib.sha256(canonical(selection)).hexdigest() if selection is not None else None
    return {"schema": "wolftrap.neuralscope.attention-result/v1", "version": __version__,
            "status": "MEASURED" if complete else "INCONCLUSIVE",
            "protocol_sha256": protocol_sha, "model": identity,
            "learned_parameter_elements": candidate.parameter_count,
            "validated_nonparameter_buffers": exclusions, "reference": reference.provenance(),
            "parity": parity, "selection": selection, "selection_sha256": selection_sha,
            "selection_precedes_validation": True if validation is not None else None,
            "validation_executed": validation is not None, "validation_summary": summary,
            "counts": {key: sum(stage["counts"][key] for stage in stages)
                       for key in discovery["counts"]},
            "api_requests": 0, "api_credit_spent_usd": 0, "network_requests_during_experiment": 0,
            "network_policy": "verified local assets only; no downloader or API client invoked",
            "weights_included_in_evidence_directory": False,
            "replay_inputs": "the separately pinned seven-file DistilGPT2 directory",
            "freeze_scope": "local canonical protocol and selection receipts; not an independent timestamp or witness",
            "scope": "finite projected-head interventions; no general security, consciousness, or unique induction-circuit claim"}


def _execution_order(protocol, discovery, selection, validation):
    events = [{"event": "protocol_frozen", "sha256": hashlib.sha256(canonical(protocol)).hexdigest()},
              {"event": "discovery_started"}, {"event": "discovery_finished", "status": discovery["status"]}]
    if selection is not None:
        events.append({"event": "selection_frozen", "sha256": hashlib.sha256(canonical(selection)).hexdigest(),
                       "selected_site": selection["selected_site"]})
    if validation is not None:
        events.extend([{"event": "validation_started", "selected_site": selection["selected_site"]},
                       {"event": "validation_finished", "status": validation["status"]}])
    return {"schema": "wolftrap.neuralscope.execution-order/v1", "events": events,
            "scope": "deterministic program-order record; not independently witnessed or timestamped"}


def run_attention(model_dir, protocol_path, output, *, progress=None):
    from .attention_measure import discovery as measure_discovery, validation as measure_validation
    from .attention_report import render_attention_report
    config, tokenizer, protocol, identity = _checked_registration(model_dir, protocol_path)
    output = Path(output).absolute()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    sources = source_identity()
    write_json(output / "protocol.json", protocol)
    write_json(output / "model-pin.json", protocol["model_identity"])
    write_json(output / "config.json", config)
    started = time.monotonic()
    candidate, reference, exclusions = _models(model_dir, config)
    discovery = measure_discovery(candidate, reference, tokenizer, protocol,
                                  output=output / "discovery", progress=progress)
    selection = _selection(discovery, protocol)
    validation = None
    if selection is not None:
        # This file is closed and hashed before validation is called. Selection
        # (including NONE) is derived exclusively from the complete discovery phase.
        write_json(output / "selection.json", selection)
        selection_sha = digest(output / "selection.json")["sha256"]
        if progress is not None:
            progress({"stage": "selection", "event": "frozen", "selection_sha256": selection_sha,
                      "selected_site": selection["selected_site"]})
        if selection["selected_site"] is not None:
            validation = measure_validation(candidate, reference, tokenizer, protocol,
                selection["selected_site"], output=output / "validation", progress=progress)
        if digest(output / "selection.json")["sha256"] != selection_sha:
            raise ValueError("selection receipt changed during validation")
    if source_identity() != sources:
        raise ValueError("source changed during the experiment; do not interpret this run")
    result = _scientific_result(identity, protocol, candidate, reference, exclusions,
                                discovery, selection, validation)
    environment = {"python": platform.python_version(), "numpy": str(np.__version__),
                   "platform": platform.system(), "machine": platform.machine(), "source_files": sources,
                   "reference": reference.provenance(), "duration_seconds": time.monotonic() - started,
                   "peak_process_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                       if resource is not None and platform.system() == "Linux" else None,
                   "peak_rss_scope": "whole process including both engines; KiB only on Linux",
                   "thread_environment": {k: os.environ.get(k) for k in
                       ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")}}
    write_json(output / "result.json", result)
    write_json(output / "environment.json", environment)
    write_json(output / "execution-order.json", _execution_order(protocol, discovery, selection, validation))
    (output / "report.html").write_text(render_attention_report(result, protocol, discovery, validation), encoding="utf-8")
    receipt = seal(output, {"kind": "counterbalanced-attention-head-study", "version": __version__,
        "protocol_sha256": result["protocol_sha256"], "selection_sha256": result["selection_sha256"],
        "source_files": sources, "external_model_inputs": protocol["model_identity"]})
    return {"status": result["status"], "parity": result["parity"]["status"],
            "selected_site": selection["selected_site"] if selection is not None else None,
            "selection_status": selection["status"] if selection is not None else "NOT_RUN_DISCOVERY_FAILED",
            "validation_executed": validation is not None,
            "validation_criteria_met": result["validation_summary"]["descriptive_criteria_met"],
            "protocol_sha256": result["protocol_sha256"], "selection_sha256": result["selection_sha256"],
            "counts": result["counts"], "manifest_sha256": receipt, "output": str(output), "api_requests": 0}


def replay_attention(directory, model_dir, expected_manifest_sha256=None, *, progress=None):
    from .attention_measure import discovery as measure_discovery, validation as measure_validation
    directory = Path(directory)
    integrity = verify(directory, expected_manifest_sha256)
    sources = source_identity()
    config, tokenizer, protocol, identity = _checked_registration(model_dir, directory / "protocol.json")
    for name, expected in (("config.json", config), ("model-pin.json", protocol["model_identity"])):
        if canonical(read_json(directory / name)) != canonical(expected):
            raise ValueError("saved " + name + " differs from the exact pinned input")
    candidate, reference, exclusions = _models(model_dir, config)
    discovery = measure_discovery(candidate, reference, tokenizer, protocol,
                                  replay=directory / "discovery", progress=progress)
    selection = _selection(discovery, protocol)
    validation = None
    if selection is not None:
        # Exact comparison binds the recorded selection digest and prevents a
        # near-tie or tolerant numeric comparison from silently selecting a new head.
        if canonical(read_json(directory / "selection.json")) != canonical(selection):
            raise ValueError("saved selection differs from recomputed discovery selection")
        if selection["selected_site"] is not None:
            validation = measure_validation(candidate, reference, tokenizer, protocol,
                selection["selected_site"], replay=directory / "validation", progress=progress)
        elif (directory / "validation").exists():
            raise ValueError("validation evidence present without a selected head")
    elif (directory / "selection.json").exists() or (directory / "validation").exists():
        raise ValueError("selection or validation evidence present despite failed discovery")
    expected = _scientific_result(identity, protocol, candidate, reference, exclusions,
                                  discovery, selection, validation)
    _compare_result(read_json(directory / "result.json"), expected)
    if canonical(read_json(directory / "execution-order.json")) != canonical(
            _execution_order(protocol, discovery, selection, validation)):
        raise ValueError("saved phase order differs from required discovery/selection/validation order")
    if source_identity() != sources:
        raise ValueError("source changed during numeric replay")
    verify(directory, integrity["manifest_sha256"])
    return {"status": "ATTENTION_NUMERIC_REPLAY_MATCH", "integrity": integrity,
            "selected_site": selection["selected_site"] if selection is not None else None,
            "selection_recomputed": selection is not None, "validation_replayed": validation is not None,
            "numeric_traces_replayed": True, "counts": expected["counts"],
            "same_source_files": read_json(directory / "environment.json")["source_files"] == sources,
            "api_requests": 0, "network_requests": 0,
            "claim": "complete saved stage arrays, selection, and scientific summary reproduced"}

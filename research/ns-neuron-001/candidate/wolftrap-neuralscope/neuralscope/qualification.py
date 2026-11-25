"""Offline pretrained parity, fixed intervention study, and numerical replay.

Downloading the pinned checkpoint is a separate explicit command. This module
uses only verified local assets, freezes a fixed protocol before inference, and
stops the behavior study if reference parity fails. Original pretrained weights
are external, digest-bound inputs rather than duplicated inside each run.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import platform
import time

try:
    import resource
except ImportError:
    resource = None

import numpy as np

from . import __version__
from .evidence import canonical, digest, read_json, seal, verify, write_json
from .experiment import _compare_trace, _save_arrays, evaluate, source_identity


def _local_registration(model_dir):
    from .pretrained import load_pin, verify_model
    from .study import build_repetition_study
    try:
        from tokenizers import Tokenizer
    except ImportError as exc:
        raise ValueError("protocol creation requires the optional local tokenizers dependency") from exc
    model_dir = Path(model_dir)
    identity = verify_model(model_dir)
    config = read_json(model_dir / "config.json")
    tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
    registration = build_repetition_study(tokenizer, config, load_pin())
    return config, registration, identity


def prepare_protocol(model_dir, output):
    """Tokenize fixed prompts and retain the plan without any model inference."""
    from .study import write_registration
    _, registration, identity = _local_registration(model_dir)
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    sha = write_registration(path, registration)
    return {"status": "PROTOCOL_FROZEN", "version": __version__,
            "protocol_sha256": sha, "protocol": str(path),
            "model_revision": identity["revision"], "model_inference_calls": 0,
            "network_requests": 0, "api_requests": 0,
            "claim": "local predeclared plan; no independent timestamp or preregistration service"}


def array_error(actual, reference):
    """Finite float32 array errors; shape mismatch cannot pass by broadcasting."""
    a, b = np.asarray(actual), np.asarray(reference)
    if (a.shape != b.shape or not a.size or a.dtype != np.float32 or b.dtype != np.float32
            or not np.isfinite(a).all() or not np.isfinite(b).all()):
        raise ValueError("comparison requires matching finite float32 arrays")
    delta = a.astype(np.float64) - b.astype(np.float64)
    return {"shape": list(a.shape), "elements": int(a.size),
            "max_abs_error": float(np.max(np.abs(delta))),
            "rmse": float(np.sqrt(np.mean(delta * delta)))}


def compare_forward(actual, reference, gates, *, include_activations):
    if not isinstance(actual, dict) or not isinstance(reference, dict):
        raise ValueError("forward outputs must be mappings")
    if set(actual) != {"logits", "activations"} or set(reference) != set(actual):
        raise ValueError("unexpected forward output inventory")
    if not isinstance(gates, dict) or type(include_activations) is not bool:
        raise ValueError("invalid comparison settings")
    for name in ("full_logit_max_abs_error", "full_logit_rmse", "activation_atol", "activation_rtol"):
        value = gates.get(name)
        if type(value) not in (int, float) or not np.isfinite(value) or value <= 0:
            raise ValueError("comparison tolerance must be finite and positive: " + name)
    for result in (actual, reference):
        if not isinstance(result["activations"], dict):
            raise ValueError("activations must be mappings")
        logits = np.asarray(result["logits"])
        if logits.ndim != 2 or logits.shape[0] < 1 or logits.shape[1] < 2:
            raise ValueError("logits must have shape (tokens, vocabulary>=2)")
    errors = array_error(actual["logits"], reference["logits"])
    errors["status"] = "PASS" if (
        errors["max_abs_error"] <= gates["full_logit_max_abs_error"]
        and errors["rmse"] <= gates["full_logit_rmse"]) else "FAIL"
    top_a, top_b = np.argmax(actual["logits"], axis=-1), np.argmax(reference["logits"], axis=-1)
    ordered = np.partition(reference["logits"], -2, axis=-1)[:, -2:]
    top_margin = np.max(ordered, axis=-1) - np.min(ordered, axis=-1)
    errors["argmax_agreements"] = int(np.sum(top_a == top_b))
    errors["token_positions"] = int(top_a.size)
    errors["minimum_reference_top_two_gap"] = float(np.min(top_margin))
    records = []
    if include_activations:
        if set(actual["activations"]) != set(reference["activations"]):
            raise ValueError("reference activation inventory differs")
        for name in sorted(actual["activations"]):
            left, right = actual["activations"][name], reference["activations"][name]
            item = {"site": name, **array_error(left, right)}
            allowance = gates["activation_atol"] + gates["activation_rtol"] * np.abs(right.astype(np.float64))
            item["max_scaled_error"] = float(np.max(np.abs(left.astype(np.float64) - right) / allowance))
            item["status"] = "PASS" if item["max_scaled_error"] <= 1 else "FAIL"
            records.append(item)
    elif actual["activations"] or reference["activations"]:
        raise ValueError("intervention comparison expected capture=False")
    return {"status": "PASS" if errors["status"] == "PASS" and all(
        row["status"] == "PASS" for row in records) else "FAIL", "logits": errors,
        "activations": records}


def _trace(directory, replay_directory, name, arrays):
    if directory is not None:
        _save_arrays(Path(directory) / (name + ".npz"), arrays)
    if replay_directory is not None:
        _compare_trace(Path(replay_directory) / (name + ".npz"), arrays)


def _margin(result, case):
    return float(result["logits"][-1, case["target_id"]] - result["logits"][-1, case["alternative_id"]])


def _operation(case, baselines, site, operation):
    if operation in ("restore", "self_corrupt"):
        recipient, source = "corrupt", "clean" if operation == "restore" else "corrupt"
    else:
        recipient, source = "clean", "corrupt" if operation == "reverse" else "clean"
    replacement = baselines[recipient]["activations"][site].copy()
    positions = case["positions"]
    replacement[positions] = 0 if operation == "ablate" else baselines[source]["activations"][site][positions]
    return case[recipient + "_ids"], replacement, recipient


def measure_parity(candidate, reference, registration, trace_dir=None, replay_trace_dir=None):
    gates = registration["reference_comparison"]
    if trace_dir is not None:
        Path(trace_dir).mkdir(parents=True, exist_ok=False)
    baseline_records, intervention_records = [], []
    selected_case = None
    retained = {"candidate": {}, "reference": {}}
    for case in registration["cases"]["cases"]:
        for side in ("clean", "corrupt"):
            actual = candidate.forward(case[side + "_ids"])
            expected = reference.forward(case[side + "_ids"])
            unhooked = reference.forward_unhooked(case[side + "_ids"])
            invariant = bool(np.array_equal(expected["logits"], unhooked["logits"]))
            record = {"case": case["id"], "side": side,
                      **compare_forward(actual, expected, gates, include_activations=True),
                      "reference_hooks_preserve_logits_bitwise": invariant}
            if not invariant:
                record["status"] = "FAIL"
            baseline_records.append(record)
            arrays = {"candidate.logits": actual["logits"], "reference.logits": expected["logits"],
                      "reference.unhooked_logits": unhooked["logits"]}
            for label, values in (("candidate", actual), ("reference", expected)):
                arrays.update({label + "." + name: value for name, value in values["activations"].items()})
            _trace(trace_dir, replay_trace_dir, "baseline-" + case["id"] + "-" + side, arrays)
            if case["id"] == gates["intervention_case"]:
                selected_case = case
                retained["candidate"][side] = actual
                retained["reference"][side] = expected
    if selected_case is None:
        raise ValueError("registered intervention case missing")
    for site in gates["intervention_sites"]:
        for operation in gates["intervention_operations"]:
            tokens, actual_patch, recipient = _operation(selected_case, retained["candidate"], site, operation)
            ref_tokens, reference_patch, _ = _operation(selected_case, retained["reference"], site, operation)
            if tokens != ref_tokens:
                raise ValueError("reference intervention inputs differ")
            actual = candidate.forward(tokens, patches={site: actual_patch}, capture=False)
            expected = reference.forward(tokens, patches={site: reference_patch}, capture=False)
            record = {"case": selected_case["id"], "site": site, "operation": operation,
                      **compare_forward(actual, expected, gates, include_activations=False),
                      "candidate_margin": _margin(actual, selected_case),
                      "reference_margin": _margin(expected, selected_case)}
            if operation.startswith("self_"):
                for label, result in (("candidate", actual), ("reference", expected)):
                    delta = abs(_margin(result, selected_case) - _margin(retained[label][recipient], selected_case))
                    record[label + "_self_margin_delta"] = delta
                    if delta > gates["self_patch_margin_atol"]:
                        record["status"] = "FAIL"
            intervention_records.append(record)
            _trace(trace_dir, replay_trace_dir, "patch-" + site + "-" + operation,
                   {"candidate.logits": actual["logits"], "reference.logits": expected["logits"],
                    "candidate.patch": actual_patch, "reference.patch": reference_patch})
    combined = baseline_records + intervention_records
    activations = [item for row in baseline_records for item in row["activations"]]
    return {"schema": "wolftrap.neuralscope.pretrained-parity/v1",
            "status": "PASS" if all(row["status"] == "PASS" for row in combined) else "FAIL",
            "baseline_sequences": len(baseline_records), "intervention_comparisons": len(intervention_records),
            "maximum_logit_absolute_error": max(row["logits"]["max_abs_error"] for row in combined),
            "maximum_logit_rmse": max(row["logits"]["rmse"] for row in combined),
            "maximum_activation_absolute_error": max(row["max_abs_error"] for row in activations),
            "maximum_activation_scaled_error": max(row["max_scaled_error"] for row in activations),
            "reference_hooks_bitwise_invariant": all(row["reference_hooks_preserve_logits_bitwise"] for row in baseline_records),
            "tolerances": gates, "baselines": baseline_records, "interventions": intervention_records,
            "intervention_donors": "same registered recipe using each engine's own measured baseline activations",
            "claim": "one pinned checkpoint, recorded inputs and intervention sites; reference implementations share intake but not forward computation"}


def _models(model_dir, config):
    from .core import GPT2Model
    from .pretrained import load_pin, normalize_gpt2_weights
    from .reference import TransformersReference
    from .weights import load_weights
    import torch
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    weights = load_weights(Path(model_dir) / "model.safetensors",
                           expected_sha256=load_pin()["files"]["model.safetensors"]["sha256"])
    weights, exclusions = normalize_gpt2_weights(config, weights)
    candidate = GPT2Model(config, weights)
    reference = TransformersReference(config, weights)
    return candidate, reference, exclusions


def _checked_protocol(model_dir, protocol):
    config, expected, identity = _local_registration(model_dir)
    registration = read_json(protocol)
    if canonical(registration) != canonical(expected):
        raise ValueError("protocol differs from this version's fixed predeclared experiment")
    return config, registration, identity


def _scientific_result(identity, registration, candidate, reference, exclusions, parity, study, behavior):
    protocol_sha = hashlib.sha256(canonical(registration)).hexdigest()
    return {"schema": "wolftrap.neuralscope.pretrained-result/v1", "version": __version__,
            "status": "MEASURED" if parity["status"] == "PASS" and study is not None and study["status"] == "MEASURED" else "INCONCLUSIVE",
            "protocol_sha256": protocol_sha, "model": identity,
            "learned_parameter_elements": candidate.parameter_count,
            "validated_nonparameter_buffers": exclusions,
            "reference": reference.provenance(),
            "parity": {k: v for k, v in parity.items() if k not in ("baselines", "interventions", "tolerances")},
            "study": behavior, "study_executed": study is not None,
            "api_requests": 0, "api_credit_spent_usd": 0, "network_requests_during_experiment": 0,
            "weights_included_in_evidence_directory": False,
            "replay_inputs": "separate seven-file model directory must match the included model pin",
            "scope": "pretrained computation and finite paired interventions; no general security certification"}


def run_pretrained(model_dir, protocol, output):
    from .study import assess_behavior
    from .pretrained_report import render_pretrained_report
    config, registration, identity = _checked_protocol(model_dir, protocol)
    output = Path(output).absolute()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    sources = source_identity()
    write_json(output / "protocol.json", registration)
    write_json(output / "model-pin.json", registration["model_identity"])
    write_json(output / "config.json", config)
    protocol_sha = digest(output / "protocol.json")["sha256"]
    started = time.monotonic()
    candidate, reference, exclusions = _models(model_dir, config)
    parity = measure_parity(candidate, reference, registration, output / "parity/traces")
    write_json(output / "parity/result.json", parity)
    study = behavior = None
    if parity["status"] == "PASS":
        (output / "study").mkdir(mode=0o700)
        study = evaluate(candidate, registration["cases"], output / "study/traces")
        behavior = assess_behavior(study, registration)
        write_json(output / "study/result.json", study)
        write_json(output / "study/behavior.json", behavior)
    if source_identity() != sources:
        raise ValueError("source changed during execution; do not interpret this run")
    result = _scientific_result(identity, registration, candidate, reference, exclusions, parity, study, behavior)
    environment = {"python": platform.python_version(), "numpy": np.__version__,
                   "platform": platform.system(), "machine": platform.machine(), "source_files": sources,
                   "reference": reference.provenance(), "duration_seconds": time.monotonic() - started,
                   "peak_process_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss if resource is not None and platform.system() == "Linux" else None,
                   "peak_rss_scope": "whole process, including both engines; reported in KiB only on Linux",
                   "thread_environment": {k: os.environ.get(k) for k in ("OPENBLAS_NUM_THREADS", "OMP_NUM_THREADS", "MKL_NUM_THREADS")}}
    write_json(output / "result.json", result)
    write_json(output / "environment.json", environment)
    (output / "report.html").write_text(render_pretrained_report(result, registration, study), encoding="utf-8")
    receipt = seal(output, {"kind": "pretrained-reference-and-intervention-study", "version": __version__,
                            "protocol_sha256": protocol_sha, "source_files": sources,
                            "external_model_inputs": registration["model_identity"]})
    return {"status": result["status"], "parity": parity["status"], "study_executed": study is not None,
            "selected_site": behavior["selected_site"] if behavior else None,
            "selected_validation_mean": behavior["selected_validation_mean"] if behavior else None,
            "protocol_sha256": protocol_sha, "manifest_sha256": receipt,
            "output": str(output), "api_requests": 0}


def _compare_result(left, right, location="result"):
    if isinstance(left, dict):
        if not isinstance(right, dict) or set(left) != set(right):
            raise ValueError("replay structure differs: " + location)
        for key in left:
            _compare_result(left[key], right[key], location + "." + key)
    elif isinstance(left, list):
        if not isinstance(right, list) or len(left) != len(right):
            raise ValueError("replay list differs: " + location)
        for i, (a, b) in enumerate(zip(left, right, strict=True)):
            _compare_result(a, b, location + "." + str(i))
    elif type(left) is float:
        if type(right) is not float or not np.isclose(left, right, atol=1e-6, rtol=1e-5):
            raise ValueError("replay measurement differs: " + location)
    elif type(left) is not type(right) or left != right:
        raise ValueError("replay value differs: " + location)


def replay_pretrained(directory, model_dir, expected_manifest_sha256=None):
    from .study import assess_behavior
    directory = Path(directory)
    integrity = verify(directory, expected_manifest_sha256)
    config, registration, identity = _checked_protocol(model_dir, directory / "protocol.json")
    if canonical(read_json(directory / "config.json")) != canonical(config):
        raise ValueError("saved configuration differs from the exact pinned configuration")
    if canonical(read_json(directory / "model-pin.json")) != canonical(registration["model_identity"]):
        raise ValueError("saved model pin differs from the exact verified model pin")
    candidate, reference, exclusions = _models(model_dir, config)
    parity = measure_parity(candidate, reference, registration, replay_trace_dir=directory / "parity/traces")
    _compare_result(read_json(directory / "parity/result.json"), parity)
    saved = read_json(directory / "result.json")
    should_run_study = parity["status"] == "PASS"
    if type(saved.get("study_executed")) is not bool or saved["study_executed"] != should_run_study:
        raise ValueError("saved study execution contradicts recomputed reference parity")
    study = behavior = None
    if should_run_study:
        study = evaluate(candidate, registration["cases"], replay_trace_dir=directory / "study/traces")
        behavior = assess_behavior(study, registration)
        _compare_result(read_json(directory / "study/result.json"), study)
        _compare_result(read_json(directory / "study/behavior.json"), behavior)
    elif (directory / "study").exists():
        raise ValueError("study files present despite failed reference parity")
    _compare_result(saved, _scientific_result(identity, registration, candidate, reference,
                                             exclusions, parity, study, behavior))
    return {"status": "PRETRAINED_NUMERIC_REPLAY_MATCH", "integrity": integrity,
            "baseline_sequences": parity["baseline_sequences"],
            "intervention_comparisons": parity["intervention_comparisons"],
            "study_replayed": saved["study_executed"], "numeric_traces_replayed": True,
            "same_source_files": read_json(directory / "environment.json")["source_files"] == source_identity(),
            "api_requests": 0, "network_requests": 0,
            "claim": "saved arrays and numeric measurements reproduced with the pinned external model"}

"""Paired interventions with predeclared discovery and validation cases."""
from __future__ import annotations

import io
import platform
from pathlib import Path
import re
import zipfile

import numpy as np

from . import __version__
from .evidence import digest, read_json, seal, verify, write_json

MAX_CASES = 32
MAX_SITES = 32
MAX_SEQUENCE = 128
MAX_FORWARD_PASSES = 512
MAX_TRACE_BYTES = 512 * 1024 * 1024
MAX_CASE_TRACE_BYTES = 128 * 1024 * 1024


def validate_cases(spec, model):
    if not isinstance(spec, dict) or spec.get("schema") != "wolftrap.neuralscope.cases/v1":
        raise ValueError("unsupported paired-case schema")
    cases = spec.get("cases")
    sites = spec.get("sites")
    if not isinstance(cases, list) or not 2 <= len(cases) <= MAX_CASES:
        raise ValueError("supply 2 to 32 predeclared cases")
    if (not isinstance(sites, list) or not 1 <= len(sites) <= MAX_SITES
            or any(not isinstance(site, str) for site in sites)
            or len(set(sites)) != len(sites) or not set(sites).issubset(model.sites)):
        raise ValueError("supply unique supported intervention sites")
    minimum_gap = spec.get("minimum_gap", 0.001)
    if (type(minimum_gap) not in (int, float) or not np.isfinite(minimum_gap)
            or not 1e-6 <= minimum_gap <= 1e6):
        raise ValueError("minimum_gap must be finite and in [1e-6, 1e6]")
    if len(cases) * (2 + 5 * len(sites)) > MAX_FORWARD_PASSES:
        raise ValueError("requested experiment exceeds 512 forward passes")
    ids, splits, definitions = set(), set(), set()
    estimated_trace = 0
    vocab_size = model.config["vocab_size"]
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("case must be an object")
        name = case.get("id")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", name) or name in ids:
            raise ValueError("invalid or duplicate case ID")
        ids.add(name)
        split = case.get("split")
        if split not in ("discovery", "validation"):
            raise ValueError("case split must be discovery or validation")
        splits.add(split)
        clean, corrupt = case.get("clean_ids"), case.get("corrupt_ids")
        if (not isinstance(clean, list) or not isinstance(corrupt, list)
                or not 1 <= len(clean) <= MAX_SEQUENCE or len(clean) != len(corrupt)):
            raise ValueError("paired token sequences must have equal bounded lengths")
        for token in clean + corrupt + [case.get("target_id"), case.get("alternative_id")]:
            if type(token) is not int or not 0 <= token < vocab_size:
                raise ValueError("token IDs must belong to this model vocabulary")
        if case["target_id"] == case["alternative_id"]:
            raise ValueError("target and alternative token must differ")
        positions = case.get("positions", [len(clean) - 1])
        if (not isinstance(positions, list) or not positions
                or any(type(p) is not int or p < 0 or p >= len(clean) for p in positions)
                or len(set(positions)) != len(positions)):
            raise ValueError("intervention positions must be unique valid token indices")
        definition = (tuple(clean), tuple(corrupt), case["target_id"], case["alternative_id"],
                      tuple(sorted(positions)))
        if definition in definitions:
            raise ValueError("duplicate paired experiment; discovery/validation must use distinct cases")
        definitions.add(definition)
        estimate = 4 * (2 * len(clean) * model.n_embd * len(model.sites)
                        + (2 + 5 * len(sites)) * vocab_size)
        if estimate > MAX_CASE_TRACE_BYTES:
            raise ValueError("case trace exceeds 128 MiB bound; reduce tokens or selected sites")
        estimated_trace += estimate
    if estimated_trace > MAX_TRACE_BYTES:
        raise ValueError("total trace exceeds 512 MiB bound; reduce cases or selected sites")
    if splits != {"discovery", "validation"}:
        raise ValueError("both discovery and validation cases are required")
    return cases, sites


def _score(forward, target, alternative):
    logits = np.asarray(forward["logits"])
    if not np.all(np.isfinite(logits)):
        raise ValueError("non-finite model output")
    final = logits[-1]
    return float(final[target] - final[alternative])


def _save_arrays(path, arrays):
    """Numeric-only NPZ with deterministic member order and timestamps."""
    with zipfile.ZipFile(path, "x", compression=zipfile.ZIP_STORED) as archive:
        for name, value in sorted(arrays.items()):
            data = io.BytesIO()
            np.save(data, np.asarray(value), allow_pickle=False)
            info = zipfile.ZipInfo(name + ".npy", (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100600 << 16
            archive.writestr(info, data.getvalue())


def evaluate(model, spec, trace_dir=None, replay_trace_dir=None):
    cases, sites = validate_cases(spec, model)
    if trace_dir is not None:
        trace_dir = Path(trace_dir)
        trace_dir.mkdir(mode=0o700)
    rows = []
    for case in cases:
        clean = model.forward(case["clean_ids"])
        corrupt = model.forward(case["corrupt_ids"])
        target, alternative = case["target_id"], case["alternative_id"]
        score = lambda result: _score(result, target, alternative)
        clean_score, corrupt_score = score(clean), score(corrupt)
        gap = clean_score - corrupt_score
        effective_gap_threshold = max(float(spec.get("minimum_gap", 0.001)),
                                      1e-5 * max(abs(clean_score), abs(corrupt_score), 1.0))
        separated = gap > effective_gap_threshold
        positions = case.get("positions", [len(case["clean_ids"]) - 1])
        record = {"id": case["id"], "split": case["split"],
                  "clean_margin": clean_score, "corrupt_margin": corrupt_score,
                  "baseline_gap": gap, "normalization_valid": separated,
                  "effective_gap_threshold": effective_gap_threshold,
                  "clean_top_token": int(np.argmax(clean["logits"][-1])),
                  "corrupt_top_token": int(np.argmax(corrupt["logits"][-1])),
                  "positions": positions, "interventions": []}
        arrays = {"clean.final_logits": clean["logits"][-1].copy(),
                  "corrupt.final_logits": corrupt["logits"][-1].copy()}
        for label, baseline in (("clean", clean), ("corrupt", corrupt)):
            arrays.update({label + "." + name: value for name, value in baseline["activations"].items()})
        for site in sites:
            def patch(tokens, recipient, donor):
                replacement = np.array(recipient["activations"][site], copy=True)
                replacement[positions] = donor["activations"][site][positions]
                return model.forward(tokens, patches={site: replacement}, capture=False)

            restored = patch(case["corrupt_ids"], corrupt, clean)
            reversed_result = patch(case["clean_ids"], clean, corrupt)
            self_clean = patch(case["clean_ids"], clean, clean)
            self_corrupt = patch(case["corrupt_ids"], corrupt, corrupt)
            zero = np.array(clean["activations"][site], copy=True)
            zero[positions] = 0
            ablated = model.forward(case["clean_ids"], patches={site: zero}, capture=False)
            restored_score, reversed_score = score(restored), score(reversed_result)
            self_delta = max(abs(score(self_clean) - clean_score), abs(score(self_corrupt) - corrupt_score))
            entry = {"site": site, "restored_margin": restored_score,
                     "reversed_margin": reversed_score, "ablated_margin": score(ablated),
                     "restoration_delta": restored_score - corrupt_score,
                     "reverse_delta": clean_score - reversed_score,
                     "normalized_restoration": (restored_score - corrupt_score) / gap if separated else None,
                     "normalized_reverse": (clean_score - reversed_score) / gap if separated else None,
                     "self_patch_max_abs_delta": self_delta,
                     "restored_top_token": int(np.argmax(restored["logits"][-1]))}
            record["interventions"].append(entry)
            for operation, forward in (("restore", restored), ("reverse", reversed_result),
                                       ("self_clean", self_clean), ("self_corrupt", self_corrupt),
                                       ("ablate", ablated)):
                arrays[operation + "." + site + ".final_logits"] = forward["logits"][-1].copy()
        if trace_dir is not None:
            _save_arrays(trace_dir / (case["id"] + ".npz"), arrays)
        if replay_trace_dir is not None:
            _compare_trace(Path(replay_trace_dir) / (case["id"] + ".npz"), arrays)
        rows.append(record)
    summaries = []
    for site in sites:
        item = {"site": site}
        for split in ("discovery", "validation"):
            subset = [intervention for row in rows if row["split"] == split
                      for intervention in row["interventions"] if intervention["site"] == site]
            values = [value["normalized_restoration"] for value in subset
                      if value["normalized_restoration"] is not None]
            item[split] = {"cases": len(subset), "usable_cases": len(values),
                           "mean_restoration": float(np.mean(values)) if values else None,
                           "minimum_restoration": min(values) if values else None,
                           "maximum_restoration": max(values) if values else None,
                           "self_patch_max_abs_delta": max(value["self_patch_max_abs_delta"] for value in subset)}
        summaries.append(item)
    candidates = [row for row in summaries
                  if row["discovery"]["usable_cases"] == row["discovery"]["cases"]
                  and row["discovery"]["mean_restoration"] > 0]
    selected = max(candidates, key=lambda row: row["discovery"]["mean_restoration"])["site"] if candidates else None
    all_controls_valid = all(e["self_patch_max_abs_delta"] <= 1e-6 for r in rows for e in r["interventions"])
    all_separated = all(row["normalization_valid"] for row in rows)
    return {"schema": "wolftrap.neuralscope.local-result/v1", "mode": "WHITE_BOX",
            "version": __version__, "status": "MEASURED" if all_controls_valid and all_separated else "INCONCLUSIVE",
            "claim_scope": spec.get("claim_scope", "specified paired inputs and intervention sites only"),
            "self_patch_controls_pass": all_controls_valid, "all_baseline_gaps_positive": all_separated,
            "selected_site_using_discovery_only": selected, "site_summary": summaries, "cases": rows,
            "metric": "final-token logit(target) minus logit(alternative)",
            "normalization": "(patched_corrupt_margin - corrupt_margin) / (clean_margin - corrupt_margin)",
            "population_confidence_interval": None,
            "limitations": ["Finite chosen cases do not certify a model or reveal private beliefs or intentions.",
                            "Interventions establish effects within this computation and input setup.",
                            "Zero ablation may move internal activity outside the model's usual distribution.",
                            "Normalized effects are not probabilities and are not clipped to [0, 1].",
                            "Validation inputs are predeclared; related synthetic cases are not independent population samples."]}


def _compare_trace(path, expected):
    """Load only bounded numeric arrays with the exact generated member set."""
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if len(names) != len(set(names)) or set(names) != {name + ".npy" for name in expected}:
            raise ValueError("replay trace inventory differs")
        if any(entry.compress_type != zipfile.ZIP_STORED for entry in entries):
            raise ValueError("compressed evidence arrays are unsupported")
        if sum(entry.file_size for entry in entries) > MAX_CASE_TRACE_BYTES + len(entries) * 4096:
            raise ValueError("replay trace exceeds size bound")
        for name, value in expected.items():
            info = archive.getinfo(name + ".npy")
            if info.file_size > value.nbytes + 4096:
                raise ValueError("replay array exceeds expected size")
            # A BytesIO handle prevents np.load from allocating from a huge forged
            # shape via its file-descriptor fast path. Validate the header first.
            raw = archive.read(info)
            stream = io.BytesIO(raw)
            version = np.lib.format.read_magic(stream)
            if version == (1, 0):
                shape, fortran, dtype = np.lib.format.read_array_header_1_0(stream)
            elif version == (2, 0):
                shape, fortran, dtype = np.lib.format.read_array_header_2_0(stream)
            else:
                raise ValueError("unsupported numeric trace format")
            if shape != value.shape or dtype != value.dtype or fortran:
                raise ValueError("replay trace shape or dtype differs")
            data = stream.read()
            if len(data) != value.nbytes:
                raise ValueError("replay trace byte length differs")
            actual = np.frombuffer(data, dtype=dtype).reshape(shape)
            if not np.allclose(actual, value, atol=1e-6, rtol=1e-5, equal_nan=False):
                raise ValueError("replay activation or logits differ: " + name)


def source_identity():
    package = Path(__file__).parent
    return {path.name: digest(path) for path in sorted(package.glob("*.py"))}


def finish_run(output, model, spec, label):
    from .report import render_report
    result = evaluate(model, spec, output / "traces")
    result["model_origin"] = label
    write_json(output / "result.json", result)
    write_json(output / "environment.json", {"python": platform.python_version(), "numpy": np.__version__,
               "platform": platform.system(), "machine": platform.machine(), "source_files": source_identity()})
    (output / "report.html").write_text(render_report(result), encoding="utf-8")
    receipt = seal(output, {"kind": "local-neural-experiment", "version": __version__,
                            "model_origin": label, "source_files": source_identity()})
    return {"status": result["status"], "mode": result["mode"], "model_origin": label,
            "cases": len(result["cases"]), "selected_site": result["selected_site_using_discovery_only"],
            "manifest_sha256": receipt, "output": str(output)}


def replay(output, expected_manifest_sha256=None):
    from .core import GPT2Model
    from .weights import load_weights
    output = Path(output)
    receipt = verify(output, expected_manifest_sha256)
    config = read_json(output / "inputs/config.json")
    spec = read_json(output / "inputs/cases.json")
    saved = read_json(output / "result.json")
    model = GPT2Model(config, load_weights(output / "inputs/model.safetensors"))
    current = evaluate(model, spec, replay_trace_dir=output / "traces")

    def compare(left, right, location="result"):
        if isinstance(left, dict):
            if not isinstance(right, dict) or set(left) != set(right):
                raise ValueError("replay structure differs: " + location)
            for key in left:
                compare(left[key], right[key], location + "." + key)
        elif isinstance(left, list):
            if not isinstance(right, list) or len(left) != len(right):
                raise ValueError("replay array differs: " + location)
            for i, (a, b) in enumerate(zip(left, right)):
                compare(a, b, location + "." + str(i))
        elif type(left) is float:
            if type(right) not in (float, int) or not np.isclose(left, right, atol=1e-6, rtol=1e-5):
                raise ValueError("replay number differs: " + location)
        elif left != right:
            raise ValueError("replay value differs: " + location)

    saved.pop("model_origin", None)
    compare(saved, current)
    recorded_source = read_json(output / "environment.json")["source_files"]
    return {"status": "NUMERIC_REPLAY_MATCH", "integrity": receipt,
            "same_source_files": recorded_source == source_identity(),
            "cases": len(current["cases"]), "rtol": 1e-5, "atol": 1e-6,
            "numeric_traces_replayed": True,
            "claim": "recorded numerical experiment reproduced; no independent scientific validation"}

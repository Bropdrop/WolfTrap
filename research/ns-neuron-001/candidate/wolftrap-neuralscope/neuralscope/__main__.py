"""CLI: local commands; network requires --download or API --live explicitly."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from . import __version__
from .evidence import digest, read_json, seal, verify, write_json, _open_regular


def fresh_output(path):
    output = Path(path).expanduser().absolute()
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    return output


def demo_cases(demo):
    cases = []
    for prefix in range(6):
        neutral = [demo["neutral_id"]] * prefix
        clean = neutral + demo["clean_ids"]
        cases.append({"id": "prefix_" + str(prefix),
                      "split": "discovery" if prefix % 2 == 0 else "validation",
                      "clean_ids": clean, "corrupt_ids": neutral + demo["corrupt_ids"],
                      "target_id": demo["target_id"], "alternative_id": demo["alternative_id"],
                      "positions": [len(clean) - 1]})
    return {"schema": "wolftrap.neuralscope.cases/v1", "minimum_gap": 0.001,
            "claim_scope": "constructed untrained copying circuit; six predeclared synthetic variants only",
            "sites": [demo["causal_site"], demo["control_site"]],
            "token_labels": demo["token_labels"], "cases": cases}


def run_demo(out):
    from .core import make_demo_model
    from .experiment import finish_run
    from .weights import inspect_weights, write_safetensors

    model, demo = make_demo_model()
    spec = demo_cases(demo)
    output = fresh_output(out)
    inputs = output / "inputs"
    inputs.mkdir(mode=0o700)
    write_json(inputs / "config.json", model.config)
    write_json(inputs / "cases.json", spec)
    write_safetensors(inputs / "model.safetensors", model.weights,
                      metadata={"origin": "constructed untrained validation circuit", "version": __version__})
    write_json(output / "model-inventory.json", inspect_weights(inputs / "model.safetensors"))
    return finish_run(output, model, spec, "CONSTRUCTED_UNTRAINED_VALIDATION_CIRCUIT")


def run_local(args):
    from .core import GPT2Model
    from .experiment import finish_run, validate_cases
    from .weights import inspect_weights, load_weights

    config = read_json(args.config)
    spec = read_json(args.cases)
    inventory = inspect_weights(args.weights, max_file_bytes=args.max_mib * 1024 * 1024)
    output = fresh_output(args.out)
    inputs = output / "inputs"
    inputs.mkdir(mode=0o700)
    weight_copy = inputs / "model.safetensors"
    with _open_regular(args.weights) as source, weight_copy.open("xb") as target:
        remaining = inventory["size_bytes"]
        while remaining:
            data = source.read(min(1024 * 1024, remaining))
            if not data:
                raise ValueError("weights changed while copying")
            target.write(data)
            remaining -= len(data)
        if source.read(1):
            raise ValueError("weights changed while copying")
    weights = load_weights(weight_copy, max_file_bytes=args.max_mib * 1024 * 1024,
                           expected_sha256=inventory["sha256"])
    model = GPT2Model(config, weights)
    validate_cases(spec, model)
    write_json(inputs / "config.json", config)
    write_json(inputs / "cases.json", spec)
    write_json(output / "model-inventory.json", inventory)
    return finish_run(output, model, spec, "LOCAL_CHECKPOINT_NOT_UPSTREAM_PARITY_VALIDATED")


def build_parser():
    parser = argparse.ArgumentParser(description="WolfTrap NeuralScope experimental neural inspection")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="run a constructed local transformer experiment; no API")
    demo.add_argument("--out", type=Path, required=True, help="fresh evidence directory")
    inspect = commands.add_parser("inspect", help="read local safetensors structure and numeric statistics")
    inspect.add_argument("weights", type=Path)
    inspect.add_argument("--metadata-only", action="store_true", help="skip numeric value scans; still hash bytes")
    inspect.add_argument("--max-mib", type=int, default=1024)
    compare = commands.add_parser("compare", help="compare two local weight-file inventories")
    compare.add_argument("before", type=Path)
    compare.add_argument("after", type=Path)
    local = commands.add_parser("local", help="intervene in supported local GPT-2 weights with predeclared token-ID cases")
    local.add_argument("--weights", type=Path, required=True)
    local.add_argument("--config", type=Path, required=True)
    local.add_argument("--cases", type=Path, required=True)
    local.add_argument("--out", type=Path, required=True)
    local.add_argument("--max-mib", type=int, default=1024)
    fetch = commands.add_parser("fetch-model", help="explicitly acquire the pinned DistilGPT2 numeric assets")
    fetch.add_argument("--out", type=Path, required=True)
    fetch.add_argument("--download", action="store_true", help="enable the fixed public model download; no paid API")
    plan_model = commands.add_parser("pretrained-plan", help="freeze fixed tokenized cases before inference; local assets only")
    plan_model.add_argument("--model-dir", type=Path, required=True)
    plan_model.add_argument("--out", type=Path, required=True, help="fresh protocol JSON filename")
    qualified = commands.add_parser("pretrained", help="compare with Transformers, then run the fixed study if parity passes")
    qualified.add_argument("--model-dir", type=Path, required=True)
    qualified.add_argument("--protocol", type=Path, required=True)
    qualified.add_argument("--out", type=Path, required=True, help="fresh evidence directory")
    repeat = commands.add_parser("replay-pretrained", help="reproduce saved reference, intervention and study arrays offline")
    repeat.add_argument("directory", type=Path)
    repeat.add_argument("--model-dir", type=Path, required=True)
    repeat.add_argument("--manifest-sha256")
    neuron = commands.add_parser("neuron", help="measure one discovery-selected MLP neuron on the pinned local checkpoint")
    neuron.add_argument("--model-dir", type=Path, required=True, help="verified local seven-file DistilGPT2 directory")
    neuron.add_argument("--out", type=Path, required=True, help="fresh evidence directory")
    attention_plan = commands.add_parser("attention-plan", help="freeze the fixed 72-head attention study; no inference")
    attention_plan.add_argument("--model-dir", type=Path, required=True)
    attention_plan.add_argument("--out", type=Path, required=True, help="fresh protocol JSON filename")
    attention = commands.add_parser("attention", help="discover one attention head, freeze it, then test held-out inputs")
    attention.add_argument("--model-dir", type=Path, required=True)
    attention.add_argument("--protocol", type=Path, required=True)
    attention.add_argument("--out", type=Path, required=True, help="fresh evidence directory")
    attention_replay = commands.add_parser("replay-attention", help="recompute all attention traces, selection, and results")
    attention_replay.add_argument("directory", type=Path)
    attention_replay.add_argument("--model-dir", type=Path, required=True)
    attention_replay.add_argument("--manifest-sha256")
    for name, help_text in (("verify", "verify closed file inventory without model execution"),
                            ("replay", "rerun the recorded local experiment and compare metrics and tensors")):
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("directory", type=Path)
        sub.add_argument("--manifest-sha256", help="optional independently retained receipt digest")
    plan = commands.add_parser("api-plan", help="preview a behavioral pilot with zero requests")
    plan.add_argument("--config", type=Path, required=True)
    api = commands.add_parser("api-run", help="dry run by default; --live explicitly enables billable requests")
    api.add_argument("--config", type=Path, required=True)
    api.add_argument("--out", type=Path, required=True)
    api.add_argument("--live", action="store_true", help="send these configured requests using local OPENAI_API_KEY")
    return parser


def main(argv=None):
    os.umask(0o077)
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if hasattr(args, "max_mib") and not 1 <= args.max_mib <= 1024:
            raise ValueError("--max-mib must be in [1, 1024]")
        if args.command == "demo":
            result = run_demo(args.out)
        elif args.command == "inspect":
            from .weights import inspect_weights
            result = inspect_weights(args.weights, max_file_bytes=args.max_mib * 1024 * 1024,
                                     scan_values=not args.metadata_only)
        elif args.command == "compare":
            from .weights import compare_weights
            result = compare_weights(args.before, args.after)
        elif args.command == "local":
            result = run_local(args)
        elif args.command == "fetch-model":
            from .pretrained import fetch_model
            result = fetch_model(args.out, allow_network=args.download)
        elif args.command == "pretrained-plan":
            from .qualification import prepare_protocol
            result = prepare_protocol(args.model_dir, args.out)
        elif args.command == "pretrained":
            from .qualification import run_pretrained
            result = run_pretrained(args.model_dir, args.protocol, args.out)
        elif args.command == "replay-pretrained":
            from .qualification import replay_pretrained
            result = replay_pretrained(args.directory, args.model_dir, args.manifest_sha256)
        elif args.command == "neuron":
            from .neuron_run import run_neuron
            result = run_neuron(args.model_dir, args.out)
        elif args.command == "attention-plan":
            from .attention_run import prepare_attention_protocol
            result = prepare_attention_protocol(args.model_dir, args.out)
        elif args.command == "attention":
            from .attention_run import run_attention
            result = run_attention(args.model_dir, args.protocol, args.out)
        elif args.command == "replay-attention":
            from .attention_run import replay_attention
            result = replay_attention(args.directory, args.model_dir, args.manifest_sha256)
        elif args.command == "verify":
            result = verify(args.directory, args.manifest_sha256)
        elif args.command == "replay":
            from .experiment import replay
            result = replay(args.directory, args.manifest_sha256)
        elif args.command == "api-plan":
            from .api_lab import plan
            result = plan(read_json(args.config))
        else:
            from .api_lab import plan, run, _clean
            config = read_json(args.config)
            output = fresh_output(args.out)
            # Retain only the redacted experiment specification. The API key is
            # never placed in config or passed through command-line arguments.
            if plan(config)["ready"]:
                write_json(output / "config.redacted.json", _clean(config))
            result = run(config, live=args.live)
            write_json(output / "result.json", result)
            sources = {path.name: digest(path) for path in sorted(Path(__file__).parent.glob("*.py"))}
            receipt = seal(output, {"kind": "api-behavior-experiment", "source_files": sources})
            result = {**result, "manifest_sha256": receipt, "output": str(output)}
        print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
        if args.command == "neuron" and result["status"] != "MEASURED":
            return 2
        if (result.get("status") == "INCONCLUSIVE" or result.get("ready") is False
                or result.get("status") == "FAIL"
                or result.get("verdict") in ("INCONCLUSIVE", "FIXTURE_MISMATCH")
                or (args.command == "api-run" and args.live and result.get("verdict") == "NOT_RUN")):
            return 2
        return 0
    except (ValueError, OSError, KeyError, TypeError, RuntimeError, ArithmeticError) as exc:
        # No exception trace, model text, credentials, or server response body.
        print(json.dumps({"status": "INCONCLUSIVE", "error_type": type(exc).__name__,
                          "reason": str(exc)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

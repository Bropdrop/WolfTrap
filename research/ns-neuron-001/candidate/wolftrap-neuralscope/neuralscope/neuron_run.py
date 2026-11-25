"""Run the fixed NS-NEURON-001 pilot on the locally pinned checkpoint."""
from pathlib import Path

from . import __version__
from .evidence import seal, write_json
from .pretrained import verify_model


def run_neuron(model_dir, output):
    """Verify inputs, run the frozen study, and seal its original four artifacts."""
    model_dir = Path(model_dir).expanduser().absolute()
    output = Path(output).expanduser().absolute()
    if output.resolve().is_relative_to(model_dir.resolve()):
        raise ValueError("choose an evidence path outside the pinned model directory")
    identity = verify_model(model_dir)
    output.mkdir(parents=True, exist_ok=False, mode=0o700)
    try:
        from . import neuron_probe as pilot
        pilot.configure()
        model, batches, target, foil, metadata = pilot.pretrained_batches(model_dir)
    except ImportError as exc:
        raise RuntimeError(f"Neuron study requires the reviewed reference dependencies: {exc}") from exc

    result = pilot.run_study(model, batches, target, foil, output, metadata)
    write_json(output / "results.json", result)
    from .experiment import source_identity
    receipt = seal(output, {
        "kind": "individual-neuron-study",
        "version": __version__,
        "model_revision": identity["revision"],
        "source_files": source_identity(),
    })
    return {
        "status": result["status"], "selection": result.get("selection"),
        "mechanism_checks_passed": result.get("mechanism_checks_passed"),
        "manifest_sha256": receipt, "output": str(output),
    }

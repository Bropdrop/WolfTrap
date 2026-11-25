"""Compare all four study artifacts to standalone outputs and verify the new seal."""
import hashlib
import json
import sys
from pathlib import Path


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    here = Path(__file__).resolve().parent
    root = here.parent
    pkg = root / "candidate" / "wolftrap-neuralscope"
    sys.path.insert(0, str(pkg))
    from neuralscope.evidence import verify
    current = here / "pretrained-run"
    original = root / "pretrained-runs" / "study-001"
    replay = root / "pretrained-runs" / "replay-001"
    names = sorted(path.name for path in original.iterdir())
    expected = set(names) | {"manifest.json"}
    cli = json.loads((here / "cli-output.json").read_text())
    seal = verify(current, cli["manifest_sha256"])
    checks = {}
    for name in names:
        data = (current / name).read_bytes()
        checks[name] = {
            "candidate_sha256": hashlib.sha256(data).hexdigest(),
            "byte_identical_to_study": data == (original / name).read_bytes(),
            "byte_identical_to_replay": data == (replay / name).read_bytes(),
        }
    pilot_source = digest(root / "pilot" / "neuron_probe.py")
    candidate_source = digest(pkg / "neuralscope" / "neuron_probe.py")
    output_names = {p.name for p in current.iterdir()}
    all_match = all(v["byte_identical_to_study"] and v["byte_identical_to_replay"] for v in checks.values())
    ok = (all_match and output_names == expected and pilot_source == candidate_source and
          len(names) == 4 and seal["manifest_sha256"] == cli["manifest_sha256"]
          and json.loads((here / "cli-exit.json").read_text())["exit"] == 0 and cli["status"] == "MEASURED")
    print(json.dumps({
        "all_match": ok, "numerical_evidence": checks, "candidate_seal": seal, "cli": cli,
        "closed_output_names": sorted(output_names),
        "pilot_source_sha256": pilot_source, "packaged_pilot_sha256": candidate_source,
    }, indent=2, sort_keys=True))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())

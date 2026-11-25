# Reproduce NS-NEURON-001

Run these commands from `research/ns-neuron-001` on Linux x86-64. The research tree includes the integrated candidate, the recovered source, the standalone pilot, and their evidence. The root manifest checks the publication copies. Acquisition and re-execution require external storage for the seven pinned public checkpoint files and the two Python environments. Use fresh directories for new output.

## Verify and prepare inputs

```sh
python -B verify_publication.py
(cd pilot && sha256sum -c SHA256SUMS)
```

The recovered release's seven filenames, sizes and SHA-256 digests are in `recovered/wolftrap-neuralscope/examples/distilgpt2-pin.json`. Acquire the checkpoint separately and verify every file before execution. The acquisition script checks the fixed revision and refuses to replace an existing model directory. Run the following from the research root on a machine with network access. Keep the resulting model directory read-only.

```sh
run=$(mktemp -d)
python acquisition/acquire_snapshot.py --dest "$run/model" --attempt "$run/model-acquisition"
```

The pretrained environment uses the recovered 39-package reference lock. Use the dependency records to acquire the exact CPU and PyPI wheels separately and install the recorded hashes offline. The miniature fixture uses a second environment with Python 3.13.5. [Pretrained dependencies](dependencies/README.md) · [Fixture dependencies](fixture-deps/README.md)

## Run the experiments

Activate the pretrained reference environment or set `py` to its absolute Python path. Set `py` to the Python interpreter in the reconstructed 39-package environment and `model` to the verified directory. Run each command through the supplied offline launcher. Use a new parent output directory.

```sh
py=/absolute/path/to/reference-venv/bin/python
model="$run/model"
out=$(mktemp -d)
python offline/offline_exec.py -- "$py" -B pilot/neuron_probe.py --mode pretrained --model-dir "$model" --out "$out/study"
python offline/offline_exec.py -- "$py" -B pilot/neuron_probe.py --mode pretrained --model-dir "$model" --out "$out/replay"
diff -qr "$out/study" "$out/replay"
python offline/offline_exec.py -- "$py" -B scoring-review/verify.py --model "$model" --run "$out/study" --out "$out/arithmetic"
```

The pilot stops on an ineligible discovery result or failed numerical checks. For successful outputs, obtain the SHA-256 of selection and results at freeze/review and run the two supplemental verifier processes. Record the digests from the reviewed run. Our measured selection and results hashes are `03d17526a26d08ba238b2e594c0ebc91ebf8f1d98f6fad4b91dca0550fcbd02f` and `96126215c388507c52c1d911c13453ec89df09c846802de8b0f2c7c912563bbb`. Exact bytes across different platforms can vary. Review observed discrepancies against the predeclared error limits. [Independent Transformers checks](pretrained/README.md) · [NumPy cross-engine checks and replay](cross-engine/README.md)

Run the saved miniature weights and focused tests using `fixture/run_fixture.py` in the historical fixture runtime. For the independent float64 computation use the recorded NumPy/SciPy environment. Its live Torch comparison uses both environments. The committed logs include the initial failed attempts. [Fixture run commands](fixture-deps/README.md) · [Independent fixture commands](independent/README.md)

## Review the integration candidate

With `py`, `model` and `out` set to absolute paths as above, enter the candidate subdirectory and run its normal command-line entry points.

```sh
launcher="$PWD/offline/offline_exec.py"
cd candidate/wolftrap-neuralscope
python "$launcher" -- "$py" -B -m unittest discover -s tests -v
python "$launcher" -- "$py" -B -m neuralscope neuron --model-dir "$model" --out "$out/candidate"
python "$launcher" -- "$py" -B -m neuralscope verify "$out/candidate"
```

Compare the four scientific JSON files individually with `$out/study`. The candidate also writes `manifest.json` containing its evidence inventory. The repository includes the original source-suite and installed-wheel measurements. [Test record](candidate-validation/tests/TESTS.md) · [Candidate command reference](candidate/wolftrap-neuralscope/NEURON.md)

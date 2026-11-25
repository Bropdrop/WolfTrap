# Miniature transformer dependencies

The saved fixture used Python 3.13.5, Torch 2.10.0+cpu and safetensors 0.7.0. Its historical record gives the Python patch release and a different build date. This reproduction’s platform-specific wheel receipts identify the exact files used here. [Wheel receipts](verified-wheels.json) · [Hash-locked requirements](requirements-hashed.txt)

The first local installation ran the focused tests but could not import safetensors’ Torch backend during saved-weight replay. Installing the reference environment’s hash-checked `packaging==26.4` supplied that dependency. The fixture acquisition below includes this wheel. [Extra dependency](additional-requirement.txt)

Run from the research directory. `python3.13` must be Python 3.13.5. `python` must have pip with support for `--python`. Use a fresh absolute output directory. Wheel acquisition needs network access. Installation and measurement use local files only.

```sh
run=${run:-$(mktemp -d)}
python dependencies/acquire.py fixture "$run/fixture-wheels"
python3.13 -m venv --without-pip "$run/fixture-venv"
python offline/offline_exec.py -- python -m pip --isolated --python "$run/fixture-venv" install --disable-pip-version-check --no-index --no-deps --require-hashes --find-links "$run/fixture-wheels" -r fixture-deps/requirements-hashed.txt -r fixture-deps/additional-requirement.txt
python offline/offline_exec.py -- "$run/fixture-venv/bin/python" -B fixture/run_fixture.py "$run/fixture-replay"
python offline/offline_exec.py -- "$run/fixture-venv/bin/python" -B pilot/neuron_probe.py --mode fixture --out "$run/fixture-train"
```

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
out=${1:?Provide a new directory}
torch_python=${2:?Pass the absolute path to the fixture Torch interpreter}
reference=${3:?Pass a reference arrays.npz from reproduce.sh}
mkdir "$out"
export OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
python -B ../offline/offline_exec.py -- "$torch_python" -B torch_fixture_capture.py "$out/first" > "$out/first.log" 2>&1
python -B ../offline/offline_exec.py -- "$torch_python" -B torch_fixture_capture.py "$out/replay" > "$out/replay.log" 2>&1
python -B ../offline/offline_exec.py -- python -B compare_tensor_captures.py "$reference" "$out/first/arrays.npz" "$out/replay/arrays.npz" "$out/comparison.json" > "$out/comparison.log" 2>&1
cat "$out/comparison.log"

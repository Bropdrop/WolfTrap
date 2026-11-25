#!/usr/bin/env bash
# Run from a checkout containing ../pilot, with NumPy and SciPy available.
# A new output directory is required so a failed or previous attempt survives.
set -euo pipefail
cd "$(dirname "$0")"
output=${1:?Provide a new output directory}
mkdir "$output"
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
python measure_fixture.py "$output/first" > "$output/first.log" 2>&1
python measure_fixture.py "$output/replay" > "$output/replay.log" 2>&1
python compare_fixture.py "$output/first" "$output/replay" "$output/comparison.json" > "$output/comparison.log" 2>&1
cat "$output/comparison.log"

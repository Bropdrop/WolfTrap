#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")"
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1 TOKENIZERS_PARALLELISM=false
exec python ../offline/offline_exec.py -- "${NS_PYTHON:-python}" compare.py --release ../recovered/wolftrap-neuralscope --model "${NS_MODEL:?set NS_MODEL to the absolute pinned model directory}" --run "${NS_RUN:-../pretrained-runs/study-001}" --out "${1:?pass a fresh output directory}"

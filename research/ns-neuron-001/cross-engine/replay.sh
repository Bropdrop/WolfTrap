#!/usr/bin/env bash
set -eu
cd "$(dirname "$0")"
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 PYTHONDONTWRITEBYTECODE=1 TOKENIZERS_PARALLELISM=false
exec python ../offline/offline_exec.py -- "${NS_PYTHON:-python}" replay_traces.py --release ../recovered/wolftrap-neuralscope --model "${NS_MODEL:?set NS_MODEL to the absolute pinned model directory}" --original "${NS_RUN:-../pretrained-runs/study-001}" --measured "${1:?measurement directory}" --out "${2:?fresh replay directory}"

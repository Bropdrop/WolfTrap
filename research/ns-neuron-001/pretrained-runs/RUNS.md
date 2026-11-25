# Two offline original-harness runs

Both separate processes ran the unchanged pilot under the Linux seccomp filter using the verified read-only seven-file model and the reviewed local environment. Both exited 0 with MEASURED and passed their original mechanism checks. All four saved JSON files matched byte for byte across processes. The source and model hashes matched again after replay. [Post-acquisition adapter audit](../adapter-review/POST_ACQUISITION.md) · [Filter test](../offline/filter-check.json) · [Replay comparison](replay-comparison.json)

The study ranked 18,432 neurons, exactly ablated the discovery top eight and froze layer 0, neuron 874. Its discovery mean exact margin decrease was +0.391088. Its held-out France mean was +0.136527 against a six-neuron random mean of −0.001477, with positive effects on two of four prompts. Its Germany mean was −0.132092 against a random mean of +0.001172, with one positive effect on four prompts. All eight baseline pairwise margins favored the expected country-specific continuation and none changed sign under ablation. The expected continuation ranked first across the vocabulary on zero of eight baseline prompts. Detailed checks and cross-layer results are retained in each results file. [Discovery](study-001/discovery.json) · [Frozen selection](study-001/selection.json) · [Per-case results](study-001/results.json)

The tables use the original fixed six random neurons and six equal-norm directions. The cross-layer rows measure the mean chosen-direction margin change minus the mean random-direction margin change over four prompts, in logits.

| Injection layer (zero-based) | France | Germany |
|---:|---:|---:|
| 0 | +0.019173 | +0.006876 |
| 1 | +0.178285 | −0.123708 |
| 2 | +0.172039 | −0.273104 |
| 3 | +0.164740 | −0.280096 |
| 4 | +0.120133 | −0.027554 |
| 5 | +0.037830 | +0.070610 |

The largest ablation-versus-row-subtraction difference across complete logits was 0.0000457764 with the pilot's limit of 0.0005. The largest difference between a directional derivative and its symmetric finite-difference estimate was 0.0162114 with limit 0.04. Hooked baseline, zero-direction, selected-layer projection reconstruction and restored-baseline discrepancies were all zero.

The commands were executed in the evidence root, using a fresh output directory for each run. Use new output names for future replays.

Set `NS_PYTHON` to the reference Python executable and `NS_MODEL` to the pinned model directory.

```sh
python -B offline/offline_exec.py -- "$NS_PYTHON" -B pilot/neuron_probe.py --mode pretrained --model-dir "$NS_MODEL" --out pretrained-runs/study-001
python -B offline/offline_exec.py -- "$NS_PYTHON" -B pilot/neuron_probe.py --mode pretrained --model-dir "$NS_MODEL" --out pretrained-runs/replay-001
python -B offline/offline_exec.py -- "$NS_PYTHON" -B pretrained-runs/summarize_runs.py "$NS_MODEL"
```

The replay measured repeatability of this code and runtime. Qualification also depends on the separately recorded independent checks and on retaining any failed checks at their original limits. [Original runtime log](study-001.log) · [Separate replay log](replay-001.log)

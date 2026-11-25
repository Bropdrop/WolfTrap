# Supplemental DistilGPT2 verifier

The verifier reads the seven model pins from the hash-checked pilot source without importing it. It stages a read-only copy, rehashes it, loads the local tokenizer and safetensors checkpoint, and checks the model configuration, parameter count and GPT-2 Conv1D module shapes. Run it under the OS-level offline launcher supplied with this study.

Its measurement entry point consumes the frozen protocol, discovery, selection and results from the original pilot. The caller supplies the previously recorded SHA-256 values for selection and results. The verifier checks the links between artifacts before using them, recomputes rankings and controls on discovery-positive prompts, and compares the independently derived selection with the recorded winner. The original pilot controls the timing of its initial selection freeze. Rechecking these links later establishes correspondence to that record.

The independently written code calls the installed Transformers forward implementation. It checks token IDs, masks, positions, and every real position's complete vocabulary logits against default-position, unpadded single-prompt forwards. It checks the exact discovery shortlist, the selected neuron and six matched neuron controls on held-out rows, both ablation routes, projection intermediates, the analytic directional gradient and its finite difference, model-state immutability, hook cleanup, and no-op logits. Each validation layer receives the frozen selected vector and the six frozen random directions. Errors above the limits fixed in the source stop the reviewer when that group's comparisons finish. Each output directory must be fresh.

Use the recorded runtime and shell working directory at the root of this evidence bundle. Replace the paths and digests with the originals for the run under review.

Set `NS_PYTHON` to the reference Python executable and `NS_MODEL` to the pinned model directory.

```sh
python -B offline/offline_exec.py -- "$NS_PYTHON" -B pretrained/verify_pretrained.py \
  --model-dir "$NS_MODEL" --run-dir /path/to/frozen-run \
  --selection-sha256 SELECTION_DIGEST --results-sha256 RESULTS_DIGEST \
  --out /path/to/fresh-review-1

python -B offline/offline_exec.py -- "$NS_PYTHON" -B pretrained/verify_pretrained.py \
  --model-dir "$NS_MODEL" --run-dir /path/to/frozen-run \
  --selection-sha256 SELECTION_DIGEST --results-sha256 RESULTS_DIGEST \
  --out /path/to/fresh-review-2 --compare-with /path/to/fresh-review-1
```

Each run compares arrays elementwise and reports the worst absolute error per class of comparison. The trace carries shape, dtype and SHA-256 over complete tensor contents for separate-process comparisons. Tensor entries include full batched and singleton logits and projection intermediates. The per-case file retains numerical margins, exact ablations and layer/control response arrays. The discovery score table contains independently measured means for every neuron. The model and reviewer are held fixed across replay.

The initial missing-path preflight exercised the verifier's rejection behavior. The recovered-input preflight checked the seven approved files, runtime inventory, offline flags and the socket-creation denial. A preflight performs zero model comparisons.

## Measured on the pinned checkpoint

Two separate OS-isolated processes completed 523 comparisons apiece. Each consumed a separate pilot execution with the same frozen selection and result hashes. All 521 complete tensor traces matched exactly across reviewer processes. The per-case response arrays, independent 6 × 3,072 score table, and model-state hash inventories also matched byte-for-byte. Both loader diagnostics returned empty missing, unexpected and mismatched-key inventories. [First audit](review-001/audit.json) · [Second audit](review-002/audit.json) · [Replay comparison](replay-comparison.json)

| Elementwise comparison | Largest absolute discrepancy | Preset limit |
|---|---:|---:|
| Padded batch against unpadded singleton over real positions | 0.000114441 | 0.0005 |
| Complete logits after activation zeroing and row subtraction | 0.0000457764 | 0.0005 |
| Projection reconstruction or intervention-route projection parity | 0.0000305176 | 0.0001 |
| Directional gradient against symmetric finite difference | 0.0162114 | 0.04 |
| Independent first-order score or reported gradient | 0.0000000894070 | 0.0001 |
| Selected direction and control reconstruction | 0.000000119209 | 0.000001 |
| Hooked, restored, and no-op values | 0 | 0.00001 |
| Per-prompt reported baseline and intervention effects | 0 | 0.0005 |

The original pilot selected layer 0, neuron 874. Its held-out France ablation reduced the Paris–Berlin margin on two of four prompts. Its mean reduction was 0.136527 logits. On the Germany controls its mean reduction was −0.132092 logits, with a positive reduction on one of four prompts. The expected token ranked first on zero of the eight prompts. On the Germany prompts the selected direction's mean injection gain fell below the equal-norm random-direction mean at layers 1 through 4. [Per-prompt responses](review-001/per-case.json) · [Original pilot results](../pretrained-runs/study-001/results.json)

# NS-NEURON-001 — Individual-neuron causal attribution

**Status:** MEASURED (newly trained synthetic miniature transformer); pretrained DistilGPT2 experiment NOT_RUN; integration with NeuralScope v0.3.0a1 NOT_RUN. This is a standalone research harness, not a versioned WolfTrap release. No GitHub changes, production qualification, model safety certification, or paid model requests.

## Prior work and scope

The prior NeuralScope v0.3.0a1 delivery record reports 194 tests and a pretrained attention-head study on `distilbert/distilgpt2`, revision `2290a62682d06624634c1f46a6ad5be0f47f38aa`. The prior attention report lists seven pinned model/tokenizer files; those exact digests are transcribed into `neuron_probe.py`. The prior ZIP (SHA-256 `392dcc885ac32688d803d841335a29f2e545db9ccb99f86e42841e1c0f77121a`) was not accessible in the current runtime and its 194 tests were not rerun. Neither Transformers nor the pretrained weights are installed here, and a network lookup to the model host failed. The new work therefore runs a deliberately small, real trained model to establish instrumentation mechanics and includes an unexecuted, pinned pretrained adapter for further review.

Relevant research: Shone and Dunlap, *Returning to the Neuron Basis for Interpretability, Part 1: Answering Three Objections* (Anthropic Fellows, 2026-11-23), https://alignment.anthropic.com/2026/neuron-basis-theory/. The method here is a scoped gradient and exact-ablation experiment, not a reproduction of the paper's vocabulary J-lens, polysemanticity census, or large-model cross-layer results.

## Method

Train a 19,035-parameter, two-layer, causal-attention transformer with 64 GELU MLP neurons per block and a 27-token vocabulary. The first token determines the desired final-position next-token label (token 25 or 26); two context tokens are distractors. Use 232 distinct ordered context pairs for training, 12 for discovery, and 12 for held-out validation. Token identities overlap across splits; each held-out positive row is paired with a negative row using the same distractor context. Training uses 220 AdamW steps. All model runs and evidence generation are CPU float32. Model weights are stored in safetensors, not pickle.

For a GPT-2-style projection with shape `[n_inner, d_model]`, one MLP neuron contributes `a_j * W[j, :]` to the residual update. The score `a_j * dot(gradient_of_target_minus_foil_margin, W[j, :])` is a first-order estimate of the margin decrease when that activation is set to zero. Screen all 128 fixture neurons using positive discovery rows, exact-ablate the top eight, and select the largest positive mean exact effect if above 0.0001. Discovery control rows are retained in the protocol but not used to select. Write selection, direction sign and amplitude, and six random same-layer neuron controls and six equal-norm random directions before evaluating held-out rows. This is procedural separation, not an externally witnessed preregistration. The discovery and validation contexts were fixed by a deterministic split.

Two exact intervention routes are compared: zero the selected post-activation at the final token before output projection, and subtract its activation-scaled output vector after projection. Other checks include hooked/unhooked parity, projection reconstruction, zero-direction no-op, local directional gradient vs symmetric finite difference, restored baseline, and parameter immutability. Reuse the selected vector at each layer with a signed direction and magnitude fixed from discovery; compare against six equal-norm random directions. Random neuron controls are layer matched, not magnitude matched. No optimization or selection using held-out outcomes.

## Executed results — fixture only

| Measure | Observed |
|---|---:|
| Neurons screened / exact shortlisted | 128 / 8 |
| Selected neuron (zero-based) | layer 1, neuron 19 |
| Held-out baseline top-1 expected label | 24/24 (12 positive + 12 negative) |
| Positive discovery mean exact margin decrease | +0.0578874 logits |
| Held-out positive mean exact margin decrease | +0.0576143 logits |
| Held-out positive effects above zero | 12/12 |
| Held-out positive random-neuron mean | -0.00482004 logits |
| Held-out negative-context mean exact margin decrease | -0.0108712 logits |
| Held-out negative-context effects above zero | 0/12 |
| Held-out negative-context random-neuron mean | +0.00580847 logits |
| Worst full-logit ablation/subtraction discrepancy across both groups | 4.7683716e-7 |
| Worst directional-gradient central-difference discrepancy | 0.000531048 |
| Hooked baseline / no-op / projection / restored baseline discrepancy | 0 |
| Unit tests | 15 passed |
| Separate same-host saved-weights replay | 5/5 core files byte-identical |

The selected signed output vector's mean margin gain exceeds the six-vector random mean at both tested layers in both held-out groups. In positive contexts the mean gains over controls are +0.0746771 (layer 0) and +0.0743549 (layer 1) logits. In negative contexts these are +0.1270617 and +0.1218226. Direction injection influences the target contrast in both contexts; it is not evidence for a unique semantic concept or a context-specific steering mechanism. The positive ablation effect is small relative to the baseline positive mean margin of +6.956665. No classification-flip or model-safety improvement is claimed. The finite test distribution, fixed seed, two-layer architecture, and shared training corpus do not establish generalization to language models or natural-language tasks. No independent implementation of the full transformer forward computation, external reproducibility, or attested execution is established.

## Reproduce locally

The executed fixture environment was Python 3.13, PyTorch 2.10.0+cpu and safetensors (see `evidence/environment.json`). Use the same versions and CPU execution for byte-level comparisons; changes in library/kernel/hardware can change numeric outputs. Dependencies should be installed from a separately reviewed offline wheel set. The script does not request model downloads or call provider APIs. Network isolation is not measured or enforced by the harness.

```sh
sha256sum -c SHA256SUMS
python -m unittest -v test_neuron_probe
python review_evidence.py
python neuron_probe.py --out /tmp/ns-neuron-new
python neuron_probe.py --out /tmp/ns-neuron-replay --replay-weights evidence/fixture-run-001/fixture.safetensors
# Compare five core replay artifacts to the original fixture-run-001 files.
```

Each output path must be new. `review_evidence.py` checks stored hashes, selection, split, per-case summaries and random-control arithmetic, not actual new model execution. The saved fixture weights are included. Re-execution from the same saved weights reproduced all five core artifacts byte-for-byte in the test runtime. Training from scratch is a separate test; identical new training results across hosts are not guaranteed.

## Next qualification — pretrained

Follow `CODEX_HANDOFF.md`. The adapter requires an offline directory containing exactly the seven files pinned in `neuron_probe.py`, checks all SHA-256 values before loading, sets offline mode, uses local-only Transformers loading with safetensors, and checks expected architecture and parameter count. It has **not** been executed against Transformers or DistilGPT2. The experiment targets only two benign single-token factual alternatives (Paris/Berlin); it is not a representative factual benchmark. Do not claim the Anthropic results were reproduced. Use an immutable model directory or a verified disposable copy to avoid concurrent mutations. Hash pins establish matching bytes, not authenticated provenance or publisher identity. SHA256SUMS binds package bytes, not scientific truth or publisher identity.

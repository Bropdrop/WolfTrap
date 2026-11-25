# NS-NEURON-001 review report

The offline study reproduced the miniature transformer's selected neuron and measured an individual neuron in the pinned 81,912,576-parameter DistilGPT2. Independent implementations confirmed the measurements within the fixed numerical limits. DistilGPT2 layer 0, neuron 874 contributed to the Paris–Berlin contrast, but the size and sign depended on the wording. One French prompt accounted for more than the entire positive mean across the four.

## Held-out DistilGPT2 results

The margin is the final-position logit for ` Paris` minus the logit for ` Berlin` (token IDs 6342 and 11307). An ablation decrease is the baseline margin minus the margin after zeroing that one post-GELU activation at the final token. Positive values mean ablation moved the prediction toward Berlin. Layer and neuron numbers start at zero.

| Held-out template | France ablation decrease | Germany ablation decrease |
|---|---:|---:|
| What is the capital of …? It is | −0.184219 | +0.004208 |
| The seat of government in … is in | +0.008484 | −0.003235 |
| The capital city located in … is | +0.729248 | −0.525906 |
| If asked to name the capital of …, I would say | −0.007404 | −0.003437 |
| **Mean** | **+0.136527** | **−0.132092** |
| Mean of six frozen same-layer random-neuron controls | −0.001477 | +0.001172 |

The correct capital won the two-token comparison on all eight baseline prompts. It ranked first in the full vocabulary on **zero of eight**. Selected-neuron ablation flipped zero of the eight pairwise preferences. Only two of four France ablations decreased the margin. This is a measurement of a small, fixed next-token contrast. It supplies no evidence of a wording-invariant factual concept, broad factual accuracy or safety performance. [Per-case ablations and controls](report/held-out-ablations.csv) · [Original results](pretrained-runs/study-001/results.json)

Discovery used four positive French prompts. It screened all 18,432 MLP neurons, exactly ablated the top eight, and selected layer 0, neuron 874. Its discovery mean exact decrease was **+0.391088 logits**, compared with the first-order estimate of **+0.182675**. The pilot wrote the selection, intervention sign, scale, six same-layer control IDs and six equal-norm random directions before held-out measurement. The Germany discovery rows did not participate in selection. Discovery and validation used distinct templates for the same two countries and candidate tokens. The separation was procedural and hash-bound. [Protocol and token IDs](pretrained-runs/study-001/protocol.json) · [All discovery scores and exact shortlist](pretrained-runs/study-001/discovery.json) · [Frozen selection](pretrained-runs/study-001/selection.json)

### Cross-layer measurements

The signed projection row, frozen on discovery at norm 10.131855, was added at each layer's final-position MLP output. Each cell is the selected direction's mean margin gain minus the mean gain of six equal-norm random directions, in logits. These are injection effects. The exact ablation table above measures the original neuron's native contribution at layer 0.

| Group | Layer 0 | Layer 1 | Layer 2 | Layer 3 | Layer 4 | Layer 5 |
|---|---:|---:|---:|---:|---:|---:|
| France | +0.01917 | +0.17828 | +0.17204 | +0.16474 | +0.12013 | +0.03783 |
| Germany | +0.00688 | −0.12371 | −0.27310 | −0.28010 | −0.02755 | +0.07061 |

On French prompts at layer 0 the selected direction reduced the margin on average (−0.04033). Its excess over controls was positive because the random directions reduced it further (−0.05950). On German prompts the selected direction underperformed the random mean at layers 1–4. [All per-case direction effects](report/cross-layer.csv) · [Figure](report/held-out-effects.png)

## Numerical qualification

| Test on the pinned checkpoint | Observed | Prespecified limit |
|---|---:|---:|
| Padded batch vs unpadded singleton, largest difference over active positions | 0.000114441 | 0.0005 |
| Zero activation vs subtract its projection row, largest full-logit difference | 0.0000457764 | 0.0005 |
| Projection parity or reconstruction, largest absolute difference | 0.0000305176 | 0.0001 |
| Analytic directional gradient vs central difference | 0.0162114 | 0.04 |
| No-op, observing hooks and restored baseline | 0 | 0.00001 |
| NumPy vs Transformers, largest full-logit difference | 0.0001220703 | 0.001 |
| NumPy vs Transformers, largest full-logit RMSE | 0.0000252391 | 0.0001 |

The unmodified standalone study and its fresh-process replay produced four byte-identical files. Two separate reviewer processes each completed 523 numerical comparisons and matched 521 tensor traces. A separate arithmetic check differentiated the margin directly with respect to the projection inputs, reproduced discovery, and remeasured exact and control effects by subtracting projection rows. All seven input files matched before and after execution. [Replay](pretrained-runs/replay-comparison.json) · [Parity checks](pretrained/replay-comparison.json) · [Arithmetic review](scoring-review/observed-001/review.json)

The recovered NeuralScope NumPy implementation independently ran each held-out prompt without padding. The comparison covered 400 complete logit arrays and 480 intermediate arrays. A fresh process reproduced all 992 stored raw arrays for baseline and selected-ablation traces across both engines. The cross-engine protocol fixed its thresholds before inspecting held-out measurements. The results establish same-host empirical agreement for this checkpoint and contrast. Independent code paths and separate processes do not constitute external review or execution attestation. [Protocol](cross-engine/protocol.json) · [Cross-engine results](cross-engine/run-001/summary.json) · [Raw array replay](cross-engine/replay-001/summary.json)

## Miniature transformer

All 20 entries in the historical pilot manifest verified. The stored arithmetic reviewer reproduced its historical report byte-for-byte, and all 15 focused tests passed in the recreated fixture environment. Saved-weight replay selected **layer 1, neuron 19** from 128 after eight exact ablations. Its held-out mean was **+0.0576143** logits on the 12 positive contexts and **−0.0108712** on their 12 matched controls. Baseline top-1 was correct on 24/24. Fresh 220-step training selected the same neuron and gave means of +0.0576140 and −0.0108716 logits.

Only two of the five replay artifacts matched the earlier archive byte-for-byte (weights and protocol). The largest numeric change in discovery was 1.91×10⁻⁶. The historical and new held-out mean ablation effects agreed at the stored precision. A Python 3.13.5 build with a different compilation date ran the same PyTorch 2.10.0+cpu and safetensors 0.7.0 versions. The original record did not pin every transitive dependency. Two fresh saved-weight processes on this host matched all five files. [Original-vs-new differences](fixture/attempt-003/summary.json) · [Same-host replay](fixture/fresh-process-comparison.json) · [Retraining and saved-weight comparison](fixture/comparison.json)

An independently written NumPy/SciPy transformer reconstructed the experiment from the archived weights. Its comparisons against live PyTorch covered 105 tensors and 161,136 values. The maximum absolute difference was 2.011×10⁻⁶. The initial missing-Torch failure and the later missing-`packaging` import failure are retained alongside the successful runs. [Fixture independent review](independent/README.md) · [First attempt](fixture/attempt-001/commands.json) · [Import failure](fixture/attempt-002/saved-weights.stderr)

## Inputs and runtime

The owner-supplied release ZIP matched SHA-256 `392dcc885ac32688d803d841335a29f2e545db9ccb99f86e42841e1c0f77121a`. The recovered release's closed inventory matched all 89 listed members. The release contained summaries of earlier pretrained and attention studies, with some original raw traces omitted by design. The initial environment lacked the checkpoint and the required dependencies. Acquisition and numerical runs were separate. [Release recovery](acquisition/release-recovery.json) · [Release inventory](acquisition/release-bundle-check.json)

The separate authorized acquisition fetched seven public files for revision `2290a62682d06624634c1f46a6ad5be0f47f38aa`. Every file matched the size and SHA-256 in the recovered release's `examples/distilgpt2-pin.json` and the pilot's digest. DistilGPT2 ran from a read-only local copy. The recreated environment matched all 39 package versions in the historical reference lock. It used Python 3.12.14, PyTorch 2.15.0+cpu, Transformers 5.24.0, NumPy 2.3.5 and safetensors 0.8.0. Package index hashes bind the acquired wheels. The historical lock recorded versions. Hash agreement alone does not authenticate authorship or validate the experiment. [Snapshot receipt](acquisition/model-attempt-001/summary.json) · [Environment](dependencies/runtime-check.json) · [Wheel receipts](dependencies/reference/wheel-receipts.json)

A network namespace was unavailable. A tested inherited Linux seccomp filter denied socket and io_uring operations throughout qualification. The launcher also set the library offline flags. No paid model APIs were called. [Offline filter and evidence](offline/README.md)

## Integration candidate

After standalone qualification, a separate source tree integrated the frozen pilot module byte-for-byte into the recovered release. The new `neuron` CLI subcommand loads the local pinned checkpoint, uses a fresh output directory and seals the four scientific files in a NeuralScope evidence manifest. The local version label is `0.3.0a1+ns.neuron.1`.

The recovered source passed **194/194** inherited tests. The candidate passed **214/214** with zero skips, comprising all 194 inherited tests, 15 neuron-probe tests and five CLI tests. Both the candidate source CLI and the installed wheel produced exactly the four standalone science files. The package verifier accepted the sealed candidate run. At qualification time, all 44 inherited historical evidence and receipt files compared byte-for-byte. The first inherited-suite log parser omitted one wrapped test description from its JSON tally. Its raw 194-test log was retained and a fresh run produced a complete 194-row receipt. [Test comparison](candidate-validation/tests/candidate-test-comparison.json) · [Installed-wheel check](candidate-validation/tests/wheel-001/summary.json) · [Historical evidence comparison](candidate-validation/tests/candidate-history.json)

Two fresh builds of the original 97-member candidate produced SHA-256 `ff4868ad7248e1135821eab3d1af3145185a32c0fa66c436d15b0046b8ec1456`. This historical digest identifies the tested build. The repository contains its source and tests and a publication copy of the evidence. Some supporting records have private file locations removed. The four scientific JSON files retain their original hashes. The root SHA-256 inventory covers the exact files in this research directory. [Candidate source](candidate/wolftrap-neuralscope/) · [Independent implementation review](candidate-validation/independent-review.md) · [Reproduction instructions](REPRODUCE.md) · [Publication manifest](SHA256SUMS)

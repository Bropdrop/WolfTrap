# NeuralScope 0.3.0a1 — attention-head study

## Question and fixed inputs

Which projected attention-head output changes the next-token contrast more for
an alternating input than for a frequency-matched nonalternating input, and does
that selected effect persist on fresh lexical groups?

The model is the same pinned DistilGPT2 checkpoint used in v0.2: repository
`distilbert/distilgpt2`, revision
`2290a62682d06624634c1f46a6ad5be0f47f38aa`. The exact seven-file pin remains in
`examples/distilgpt2-pin.json`. There are 81,912,576 learned scalar parameters.
Six legacy causal-mask buffers are validated separately, not counted as learned
parameters. No model weights are bundled in this source package.

| Split | Groups `(A, B, C)` |
| --- | --- |
| Discovery | apple/orange/lemon; rain/snow/wind; car/bus/train |
| Validation | tea/coffee/milk; iron/steel/copper; king/queen/prince |

All words have a leading space and must tokenize to one distinct token under the
pinned local tokenizer. The builder rejects the study if this is not true; it
does not substitute easier words. The alternating condition compares `A B A B A`
with `A C A C A`. The order control compares `A A B B A` with `A A C C A`. Counts
of each word and the final anchor are matched. Order and distances change, so a
positive contrast does not uniquely establish an induction mechanism.

Both orientations are measured: the two inputs and target/alternative identities
swap together. They reuse the same underlying sequences and are correlated.
There are three distinct lexical groups per split, not six independent samples.

## Frozen selection and controls

The complete protocol is written before model inference. Its SHA-256 is:

`3ab76c64122a02396d0c42963c44e29912390eed96f81b62ba209d0091def540`

Every one of the 72 heads is restored at the final token position in every
discovery case. A projected head is that head's contribution after the attention
output projection; the shared projection bias is added exactly once. Patching
recomputes the remaining network and does not alter stored weights.

For a case, the margin is `logit(target) - logit(alternative)`. Restoration delta
is the patched changed-input margin minus its original changed-input margin.
The head score is the mean **alternating restoration delta minus matched-control
restoration delta** across three discovery groups and both orientations.

An eligible head must have a score of at least 0.01 logits, a mean alternating
restoration delta of at least 0.01, positive mean alternating effects in each
orientation, and alternating baseline gaps strictly above 0.05 in every group.
The maximum eligible score wins; exact ties use ascending layer/head. If none
qualifies, the result is no selection. All candidates are retained.

The selection JSON is written, closed, and hashed before any validation forward.
It cannot be replaced based on held-out behavior. The selected head receives
restore, reverse, self-clean, self-changed, and zero-ablation interventions in
both conditions and orientations. Held-out threshold flags use the same practical
floors and require positive group contrasts in at least two of three groups.
These are descriptive checks, not significance tests or population estimates.

Normalized restoration is reported only for positive baseline gaps above 0.05.
The selection uses raw deltas, so negative or tiny control gaps do not discard
control observations. Every result includes the target and alternative rank,
the highest-scoring vocabulary token, exact top-score ties, and pairwise preference.

## Reference and evidence coverage

Both engines use CPU float32, deterministic evaluation, eager attention, and no
KV cache. The comparison implementation is installed Transformers 5.24.0 with
PyTorch 2.15.0+cpu. It shares verified numeric intake with the candidate, but
computes the forward pass through the separately implemented framework.

| Computation | Candidate forwards | Reference forwards |
| --- | ---: | ---: |
| Discovery | 876 | 96 |
| Selected-head validation | 72 | 84 |
| Maximum total | 948 | 180 |

Reference coverage includes every reached unique baseline (hooked and unhooked),
all 96 named baseline activation sites, all 72 head restorations on the first
discovery alternating/forward case, and every selected-head validation
intervention. The remaining discovery patches are candidate measurements.

Frozen tolerances are maximum full-logit absolute error <=0.001, full-logit RMSE
<=0.0001, and per-element activation error <=`0.0002 + 0.0002*abs(reference)`.
Observing hooks must preserve the unhooked reference logits bitwise. A self-copy
must change the target margin by no more than 1e-6. Every final-position patch
must leave all earlier-position logits bitwise unchanged in each tested engine.
Any failure stops interpretation without widening these tolerances.

Evidence retains complete baseline logits and activations and a complete final
vocabulary vector for every intervention. Earlier-position invariance is checked
during execution and replay. The replay repeats discovery, derives the selection
again, compares its exact canonical receipt, and then repeats required validation.
Saved skip flags cannot suppress a required stage. All numeric arrays, measurement
records, the scientific summary, and the program-order record are checked.

Receipts are unsigned. An externally retained manifest digest binds a particular
evidence set; it does not establish publisher identity. Local protocol/selection
hashes and a program-order record are not an independent timestamp or witness.
The verifier assumes a quiescent evidence directory. This tool is not an OS
sandbox, and the study is not a general model-safety certification.

## Run and replay

Use the optional reference dependencies described in `PRETRAINED.md`, or reproduce
the exact recorded environment in `requirements-reference-lock.txt`. The pinned
model directory from v0.2 can be reused unchanged. The study and replay have no
network or API calls; model acquisition is a separate explicit command.

```bash
export OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1

python3 -m neuralscope attention-plan \
  --model-dir /path/to/distilgpt2-2290a626 --out attention-protocol.json
python3 -m neuralscope attention \
  --model-dir /path/to/distilgpt2-2290a626 \
  --protocol attention-protocol.json --out attention-run
python3 -m neuralscope verify attention-run
python3 -m neuralscope replay-attention attention-run \
  --model-dir /path/to/distilgpt2-2290a626
```

For the separately delivered evidence archive, use its extracted root as the
replay directory and provide the separately retained manifest digest with
`--manifest-sha256`. All output directories and protocol filenames must be fresh.
The lightweight source ZIP contains summaries, not the numeric traces needed
for complete replay. The original checkpoint requires approximately 353 MB, and
the full attention traces require approximately 356 MB uncompressed plus reports.
Both engines and their cached activations consume additional RAM. Crostini has
not been tested for this version; current-run resource measurements are recorded
in the delivered evidence's `environment.json`.

## Research basis

Zhang & Nanda, *Towards Best Practices of Activation Patching in Language Models:
Metrics and Methods*, ICLR 2024, demonstrates that corruption and measurement
choices can change interpretation: https://arxiv.org/abs/2309.16042

Olsson et al., *In-context Learning and Induction Heads*, defines induction-head
evidence using prefix matching and copying on repeated random-token sequences:
https://transformer-circuits.pub/2022/in-context-learning-and-induction-heads/index.html
This lexical projected-output study does not establish that complete definition.

## Delivered measurements

The frozen discovery rule selected **blocks.5.attn.head.2** (zero-based layer 5, head 2; the third head in the sixth block). Five of 72 heads were eligible.

| Split | Mean alternating restoration | Mean order-control restoration | Difference |
| --- | ---: | ---: | ---: |
| Discovery | 0.803123 | 0.701066 | 0.102057 |
| Held-out validation | 0.958574 | 0.886310 | 0.072263 |

All values are raw logit-margin changes, averaged across both orientations. The held-out difference was positive in all three groups and all six group/orientation comparisons. The predeclared descriptive criteria were met. Most of the patch effect also occurred in the order control.

| Held-out group | Alternating mean | Control mean | Difference |
| --- | ---: | ---: | ---: |
| drinks | 1.024263 | 0.943867 | 0.080397 |
| metals | 0.704922 | 0.653685 | 0.051237 |
| royalty | 1.146536 | 1.061379 | 0.085156 |

None of the six alternating restorations flipped the target/alternative preference, and none made the target the highest-scoring vocabulary token. The highest-scoring token stayed the same as the changed-input baseline in all six alternating restorations. This is evidence of a partial contribution under the tested interventions, not full answer recovery.

The target's vocabulary rank improved in all six alternating restorations.
Normalized restoration averaged 0.149382 (range 0.122230–0.178994), a fraction of
the chosen clean-versus-changed margin gap, not accuracy or a probability. In one
case the target's raw logit fell while the alternative fell more; a contrast
improvement does not necessarily raise the target's absolute score.

Reverse patches and opposite-orientation restorations reuse the same physical
intervention with answer labels swapped. Their matching results are a consistency
check, not extra independent replication. Zero ablation reduced the clean margin
in all six alternating cases but left every margin positive. It changed the
global top token in two cases; this broader effect does not establish necessity
for the nominated preference. Results should not be ratio-compared with the
earlier MLP study because its cases and selection criterion differed.

All 24 baseline comparisons and 132 intervention reference comparisons passed the frozen gates. Maximum full-logit absolute error was 0.000118255615234375 and maximum RMSE 0.00002553083211314612. Maximum activation scaled error was 0.08525973170045102 of its per-element tolerance. Self-copy margin changes were 0.0; observing hooks and earlier-position invariance checks passed.

The measurement took 134.26 seconds on the recorded CPU runner, with process peak RSS 1,162,372 KiB (approximately 1.11 GiB). This is a measurement of this environment, not a Chromebook guarantee. Python socket construction was denied after framework imports during the run; zero attempts occurred. This guard is not OS confinement. Paid API requests and charges were zero.

Selection SHA-256: `2d9875a49336190f3874ed0a5aebccd28d4620cd0eda72984bdbd70c7cf3021f`

Full evidence manifest SHA-256: `234f969ae318d97468e67f62305ece37f23f225fe5475ddd9eef4f56c6743fc4`

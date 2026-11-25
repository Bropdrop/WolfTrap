# NeuralScope 0.2.0a1 — first pretrained-model experiment

## Outcome

The NumPy engine reproduced a pinned pretrained **DistilGPT2** checkpoint against
**Transformers 5.24.0 / PyTorch 2.15.0+cpu** within tolerances chosen before the
experiment. All **12 baseline sequences and 45 intervention comparisons** passed.
The observing hooks preserved unhooked reference logits bitwise.

The first behavioral study measured a **small, mixed effect**. The third block's
MLP output (`blocks.2.mlp_out`, zero-based indexing) ranked first on the three
discovery cases. Its mean normalized restoration on three separate validation
cases was **0.0166945085**. Two validation contrasts improved and one worsened.
None of the three patched validation inputs regained the target-over-alternative
preference. This is a working pretrained-model instrument and a retained scoped
measurement; it does not establish a dominant repetition circuit.

Start with `pretrained-summary/report.html`. It is a static, offline report.
`pretrained-summary/` also contains the exact protocol, machine-readable summaries,
reference comparison records, runtime record, and a copy of the original evidence
manifest. It is an **excerpt**, not the complete inventory covered by that
manifest. The separate evidence ZIP contains every numeric trace and supports
full inventory verification and replay with the pinned external model.

## Exact model and protocol

| Item | Recorded identity |
| --- | --- |
| Repository | `distilbert/distilgpt2` |
| Model revision | `2290a62682d06624634c1f46a6ad5be0f47f38aa` |
| Original model file | 352,824,413 bytes |
| Model SHA-256 | `e1ff18884359fe8beb795a5f414feb85a6ce3d929ad019c0d958c039d2b94a1b` |
| Learned parameters | 81,912,576 |
| Legacy deterministic mask scalars | 6,291,456 |
| Protocol SHA-256 | `47215ccf548bd3c612b9349e3ba816d8ad8939016e28cbe402d364717bd3abeb` |

`examples/distilgpt2-pin.json` binds all seven upstream files, including the
tokenizer, vocabulary, merges, configuration, and model card. The checkpoint
contains six serialized causal masks. Each mask was checked element by element
against the exact lower-triangular zero/one pattern before being excluded from
learned parameters. The downloaded checkpoint remains unchanged. Unexpected
learned tensors are rejected rather than silently ignored.

The model card declares Apache-2.0. No standalone upstream LICENSE file or
publisher signature is present in this pin. The code has its own Apache-2.0
license. Hashes identify the exact assets used; they do not establish publisher
authentication.

## What was compared

Two forward computations use the same validated numeric weights:

- NeuralScope's NumPy GPT-2 engine.
- The installed Transformers GPT2LMHeadModel in CPU float32 evaluation mode,
  with eager attention, no dropout, and no key/value cache.

Both share numeric intake validation. The reference does not call the NumPy
forward computation. It is a cross-implementation check, not an independent
human audit.

Every baseline comparison checks the complete logits at all five input positions
and all 96 named internal activation sites. Reference hooks observe actual
framework computations. Attention-head sites are contributions after the head's
slice of the output projection; the shared projection bias is counted once.

The first discovery pair also receives 45 comparisons: nine sites (the six MLP
outputs and head zero in blocks zero, two, and five), each with clean-to-changed
patch, reverse patch, both self patches, and zero ablation. Each engine uses its
own measured donor/recipient tensors with the same registered intervention
recipe. These are not asserted to be byte-identical donor arrays.

| Numerical check | Observed | Frozen acceptance rule |
| --- | ---: | ---: |
| Largest absolute logit difference | 0.0001296997 | At most 0.001 |
| Largest logit RMSE | 0.0000266053 | At most 0.0001 |
| Largest activation error divided by its allowance | 0.07706433 | At most 1 |
| Hooked versus unhooked reference logits | Bitwise identical | Bitwise identical |
| Largest tested self-copy margin change | 0 | At most 0.000001 |

Activation allowance is `0.0002 + 0.0002 * abs(reference)` elementwise. The largest
absolute activation difference is 0.0006103516; it passes the declared combined
absolute/relative rule. Matching only the winning token was never the acceptance
criterion. All 285 token positions in the 57 comparisons happened to agree on
the highest-scoring token.

## Behavioral experiment and limits

The six five-token pairs were frozen before any pretrained-model inference.
Example clean input: ` red blue red blue red`; changed input:
` red green red green red`. The answer contrast is the next-token logit for
` blue` minus the logit for ` green`. Leading spaces are intentional tokenizer
inputs. Colors, animals, and cities are discovery cases; shades, sky, and numbers
are validation cases. No case was discarded or rewritten based on an output.

The study tests the final-position output of all six MLPs, using 192 forward
passes. A site is eligible for discovery selection only when all discovery gaps
are normalizable and its mean normalized restoration is strictly positive.
The minimum baseline gap is 0.05 logits, plus the registered relative floor.

| Selected third-block MLP result | Normalized restoration |
| --- | ---: |
| Discovery mean | +0.01738833 |
| Validation: shades | -0.05254970 |
| Validation: sky | +0.06981619 |
| Validation: numbers | +0.03281703 |
| Validation mean | +0.01669451 |

These ratios measure a fraction of each pair's clean-minus-changed **score gap**.
They are neither probabilities nor a fraction of the model's mechanism explained.
The selected site's reverse-patch effects were negative in all six cases, so a
consistent bidirectional signal transfer was not demonstrated.

All six baseline pairs favored the expected token **relative to the nominated
alternative**. Vocabulary-wide highest-score accuracy is a different quantity:
the target was highest for one of six clean inputs, and the alternative was
highest for two of six changed inputs. Do not describe this result as six correct
free-choice answers.

The six related synthetic pairs do not support a population confidence interval.
Whole-MLP interventions do not isolate individual neurons. Zero ablation may be
outside the model's ordinary activation distribution. General safety, deceptive
intent, backdoors, proprietary-model internals, and broader architecture support
are not established by these measurements.

## Reproduce the experiment

The small constructed `demo` still needs only Python 3.11+ and NumPy. This
pretrained reference experiment additionally needs the optional CPU reference
dependencies and about 356 MB of public model/tokenizer assets. The experiment
runs on CPU and uses no paid model API or API key.

From the extracted source directory, create an isolated environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install torch==2.15.0 --index-url https://download.pytorch.org/whl/cpu
.venv/bin/python -m pip install -r requirements-reference.txt
```

`requirements-reference-lock.txt` records all 39 installed distribution versions
from the tested environment. It is a version snapshot, not an artifact-hash lock.
The completed run used Python 3.12.14 and NumPy 2.3.5. New Crostini execution has
not been tested; consult the retained runtime record before choosing a machine.

Download the exact pinned assets into a fresh directory. This is the only command
in this sequence that makes public model-download requests:

```bash
.venv/bin/python -m neuralscope fetch-model --download --out models/distilgpt2
```

Run the supplied frozen protocol. All evidence output paths must be fresh:

```bash
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
.venv/bin/python -m neuralscope pretrained \
  --model-dir models/distilgpt2 \
  --protocol examples/pretrained-protocol.json \
  --out pretrained-run
```

To rebuild the fixed protocol before a new run, `pretrained-plan` tokenizes the
same six declared patterns and writes a fresh JSON file without inference:

```bash
.venv/bin/python -m neuralscope pretrained-plan \
  --model-dir models/distilgpt2 --out my-protocol.json
```

The runner compares that protocol exactly against this version's fixed protocol.
Changing prompts, splits, thresholds, or identity requires a separately declared
experiment; this command does not silently accept post-hoc changes.

Verify and replay an existing run:

```bash
.venv/bin/python -m neuralscope verify pretrained-run
OPENBLAS_NUM_THREADS=1 OMP_NUM_THREADS=1 MKL_NUM_THREADS=1 \
.venv/bin/python -m neuralscope replay-pretrained pretrained-run \
  --model-dir models/distilgpt2
```

For the supplied evidence ZIP, use its extracted
`wolftrap-neuralscope-pretrained-evidence` directory and the manifest SHA-256 in
`validation.json`. Pass that digest using `--manifest-sha256` to both commands.
The full weights remain external and must still match all seven pins. The
standard-library-only verifier can run with `python3 -S -m neuralscope verify ...`;
numeric replay needs the reference dependencies.

Replay checks complete numeric traces and derived metrics, and reconciles the
headline results, model pin, exact configuration, and study-execution decision.
A new receipt cannot make a contradictory scientific summary agree with its
recomputed measurements. Receipts remain unsigned, and verification assumes
quiescent local directories.

## Research direction

This work supplies concrete preliminary engineering evidence for an
interpretability research proposal: a fixed pretrained model, a separately
implemented reference computation, controlled interventions, retained negative
results, and replayable numeric evidence. It is not yet a human-oversight or
authorization-at-effect experiment; those would need explicit agent actions and
approval/effect measurements in a separate protocol.

The next narrow neural experiment should freeze an attention-head study with
fresh validation pairs, counterbalanced alternatives, and nonrepetition controls.
It should also report token rank and the global top token. That can test whether
attention-mediated effects are more consistent and pattern-specific, while
retaining this MLP result unchanged. No faculty partnership, grant application,
outreach, or external submission is part of this build.

## Primary references

- Pinned model: https://huggingface.co/distilbert/distilgpt2/tree/2290a62682d06624634c1f46a6ad5be0f47f38aa
- GPT-2 reference documentation: https://huggingface.co/docs/transformers/en/model_doc/gpt2
- Original GPT-2 code: https://github.com/openai/gpt-2/blob/master/src/model.py
- Activation-patching methodology: https://arxiv.org/abs/2309.16042
- Safetensors format: https://huggingface.co/docs/safetensors/en/index

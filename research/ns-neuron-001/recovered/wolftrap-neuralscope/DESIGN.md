# NeuralScope engineering design

## Objective

Make a claim about a model's behavior concrete enough to test, intervene on its
internal computation when that access exists, and retain enough evidence for
another person to rerun the experiment. The unit of evidence is a specified
model, specified input pair, specified component, specified replacement, and
specified change in output. The system does not infer a private intention from a
colorful activation map or from the model's explanation of itself.

## Two observation modes

| Mode | Accessible evidence | Defensible question |
| --- | --- | --- |
| Local white box | Model tensors, input IDs, intermediate activations, output logits, interventions | Did replacing this component's activity change this answer contrast? |
| Hosted API behavior | Submitted instructions/inputs, returned answer, model identifier, usage | Did the returned answer match this predeclared fixture? |

The ordinary Responses API provides generated output and documented response
metadata. It does not provide the hosted model's weights or arbitrary hidden
layer activations. API credit funds behavioral experiments; it does not supply
the missing white-box access. A provider-returned rationale is an output of the
model, not a trusted transcript of its mechanism.

## Implemented data path

1. **Intake.** Open local safetensors read-only. Bound file size, header length,
   tensor count, dimensions, and decoded memory. Validate the complete tensor
   layout before allocating arrays. Reject duplicate keys, overlaps, gaps,
   nonnumeric model formats, unsupported types, and nonfinite inference values.
2. **Identity.** Hash model bytes and configuration; retain normalized trial
   inputs. Hash the source used to conduct the experiment. Record Python/NumPy
   versions. Hashes say which bytes were involved, not who endorsed them.
3. **Execution.** Compute an actual transformer forward pass in NumPy. Capture
   named internal tensors. Model files supply numeric data only; no model Python
   source is imported and no downloaded code is executed.
4. **Intervention.** Replace a predeclared site at specified token positions with
   activity from the paired donor run. Recompute all downstream layers. Also
   apply the reverse donor, both self donors, and zero ablation.
5. **Measurement.** Record raw logit margins and normalized restoration. Choose a
   site using discovery results only; retain the predeclared validation results
   without retuning or deleting failures.
6. **Evidence.** Save numeric activations and final logits in bounded, numeric-only
   NPZ files, plus JSON metrics and a static HTML report. Seal a closed inventory.
7. **Verification.** Check the closed inventory against a separately retained
   receipt digest when available. Replay with the installed engine, comparing
   both metrics and numeric arrays. Do not import code from an evidence folder.

## Causal experiment

Let `m(x)` be the final next-token logit for the target answer minus the logit for
the alternative answer. For a clean input `c`, a changed input `d`, and a selected
site `s`, the experiment computes:

```text
baseline gap = m(c) - m(d)
patch effect = m(d with s copied from c) - m(d)
normalized restoration = patch effect / baseline gap
```

Normalization is defined only when the baseline gap is positive and exceeds both
the predeclared practical threshold (default 0.001 logits) and a numerical scale
guard. Values are not clipped: negative effects and effects above one remain
visible. The reverse patch tests the opposite direction. A self patch must
reproduce the original computation. Zero ablation is recorded separately because
zero may be an unusual internal state.

The built-in model has a known inactive head as a negative control. A real model
does not come with a guaranteed irrelevant head. For an outside experiment, a
researcher must justify its control sites and inputs. The prototype records the
measurements; it does not automatically label a head irrelevant or a circuit
complete. Shared synthetic templates are not independent population samples,
so the report does not fabricate a confidence interval over them.

The methodology follows intervention-based interpretability research, including
Zhang and Nanda (ICLR 2024), which demonstrates that corruption methods and
metrics can materially change conclusions. This prototype exposes those choices
instead of treating a selected heatmap or a single positive patch as conclusive.

## Implementation boundaries

`weights.py` validates a documented numeric safetensors subset. `core.py` performs
standard GPT-2 inference. `experiment.py` owns predeclared paired trials and
numerical replay. `evidence.py` verifies the inventory independently of model
execution. `api_lab.py` runs a separate output-only experiment. `report.py`
generates escaped static HTML with no scripts or external resources.

The forward pass was compared with an independently written scalar/float64
reference on random two-layer models, including tied/untied embeddings and
scaled/unscaled attention. That tests the mathematics and head decomposition.
Version 0.2.0a1 additionally performs the pinned pretrained comparison described
in PRETRAINED.md. It compares full logits, actual intermediate activations, and
45 intervention recipes with the installed Transformers/PyTorch implementation.
The reference shares validated numeric intake but has a separate forward path.
Its observing hooks preserve the original unhooked reference logits bitwise.

Version 0.3.0a1 adds a separate fixed attention study. `attention_protocol.py`
defines new lexical groups, counterbalanced orientations, frequency-matched
order controls, all 72 candidate heads, and a deterministic raw-effect selection
rule. `attention_measure.py` executes discovery and validation as separate phases.
`attention_run.py` writes and hashes selection before held-out inference, and
replay derives every required phase again. The new pipeline's bounds are explicit
in ATTENTION.md; the older generic paired-case limits remain unchanged.

Unlike a pure two-token contrast, the attention reports also retain each answer's
vocabulary rank and the global top token, including exact ties. Selecting among
many heads can inflate discovery estimates. All candidates remain visible, and
the fixed held-out head can fail the descriptive criteria. A measured null result
is a valid completed experiment. Input order and distance remain potential
explanations for any difference from the matched control.

The current probe is coarse: projected attention-head contributions, MLP outputs,
and residual streams. It does not yet isolate individual learned features,
estimate a complete causal graph, use sparse autoencoders, provide gradient
attribution, or implement path-specific mediation. Those extensions should earn
their place through tests, rather than expanding claims ahead of measurements.

## Resource and trust model

The program is intended for a local user examining local numeric files and
quiescent evidence directories. It bounds major input and trace allocations and
does not execute model-supplied programs. It is not a containment boundary for
arbitrary hostile code or a replacement for operating-system isolation. Direct
directory-substitution races, native NumPy vulnerabilities, and hostile concurrent
writers are outside this version's assurance claim.

The manifest is read once, parsed and hashed from the same bytes, with descriptor
change detection. Payload identity and a closed inventory expose static file
changes. A separately retained digest prevents unnoticed replacement of the
receipt itself. There is no signing key, trusted publisher chain, or public
attestation. The adversarial tests demonstrate specific rejections, not universal
tamper resistance.

The generic local command copies a checkpoint into a fresh evidence directory
and loads it against the inspected digest. The new pretrained path keeps the
large checkpoint external and binds all seven assets through fixed sizes/hashes.
An explicit download command accepts only these pinned public numeric/tokenizer
assets. It does not download arbitrary repositories or accept Python model
classes from a checkpoint. The local engine supports standard GPT-2 only. The
fixed pretrained protocol records both text and exact IDs produced by the pinned
data-only tokenizer before model inference.

## API pilot design

All four shipped fixtures contain invented data and use exact JSON assertions.
The policy cases differ in authorization state and in the presence of an
untrusted note claiming higher authority. The missing-fact case expects UNKNOWN
for information absent from a fictional record. These are first instrument tests,
not a red-team benchmark or a measured hallucination rate.

No tool implementations are exposed. The model can only return text. A suggested
tool call or command is never dispatched. The runner's network destination is
the fixed OpenAI Responses endpoint; redirects, environment proxies, and retry
loops are not used. It requests no raw chain-of-thought and treats any reasoning
items in a response separately from answer text.

The current budget design reserves the complete planned experiment before the
first call, uses explicit prices and a conservative input envelope, and retains
the reservation for every attempted request. Missing usage, output truncation,
unexpected model identity (when pinned), unexpected service tier, and ambiguous
transport errors stop the run. Billing estimates cannot guarantee provider
charges. Account eligibility, credits, and the actual bill remain provider facts.

Default execution is dry. A real request requires both an explicit `--live`
invocation and a validated configuration. Credentials are read locally only on
that path. The distributed results contain no live API evaluation.

## Pretrained milestone and next experiment

The pretrained milestone is now executed for the DistilGPT2 revision and six
fixed pairs in PRETRAINED.md. Reference parity passed. The discovery-selected
third-block MLP has a small mixed validation effect; its reverse patches do not
establish a consistent bidirectional transfer. This result supports the instrument
for the tested settings, and does not establish a dominant repetition circuit.

The next experiment should separately register bounded attention-head probes,
fresh validation pairs, counterbalanced alternatives, and nonrepetition controls.
Pairwise logit margins should be accompanied by token ranks and global top-token
observations. Retain this MLP result and all negative effects.

After that foundation, useful engineering extensions are tokenization with a
pinned data-only tokenizer, multiple-token answer scoring, learned-feature
probes, model-update comparisons, and repeated API trials. API assistance may
propose candidate test cases, but the candidates must pass a schema check and
be frozen before evaluation. Model-generated explanations remain hypotheses
that interventions can support or contradict.

The product value is reproducible, scoped evidence about how an accessible
model computes a chosen answer. It should never claim to read a person's mind,
extract inaccessible proprietary internals, or certify the absence of hidden
behavior from a finite set of tests.

# WolfTrap NeuralScope

**Version 0.3.0a1 · experimental research prototype**

NeuralScope measures how selected internal components affect a neural model's
answer. It also provides a separate, optional API mode for controlled behavioral
fixtures. Every run has an explicit evidence boundary: a numeric intervention in
a local model is different evidence from an answer returned by a hosted API.

This version adds a fixed attention-head study on the pinned pretrained DistilGPT2
checkpoint. It scans all 72 projected attention heads, freezes a selection using
three lexical groups, and tests that head on three new groups with matched-order
controls and counterbalanced answer identities. See `attention-summary/report.html`
and **ATTENTION.md** for the actual results and exact replay commands.

The earlier pretrained MLP experiment remains in `pretrained-summary/`, explicitly
marked as historical v0.2 evidence. The constructed circuit is in `example-run/`.
Reports are static HTML and work without installation or network access.

See **PRETRAINED.md** for the exact pretrained experiment, its measured results,
optional dependency setup, model acquisition, and numerical replay instructions.

## What this version does

- Inspects the structure, identity, dtype, shape, and numeric values of local
  supported `.safetensors` weight files. It compares versions at tensor level.
- Runs a bounded NumPy implementation of standard GPT-2 inference without
  loading Python model code, pickle files, or remote code.
- Captures residual streams, projected attention-head contributions, and MLP
  outputs. Copies specified activations between matched input runs, reverses the
  intervention, applies self-copy controls, and measures zero ablation.
- Selects the strongest tested site on discovery cases, then reports its effect
  on distinct predeclared validation cases. It retains raw logit differences;
  near-zero baseline gaps become inconclusive instead of unstable percentages.
- The attention study selects on raw repetition-minus-order-control effects,
  checks both answer orientations, and retains all 72 candidates, including
  negative effects and ineligible heads. It permits no eligible selection.
- Reports target/alternative ranks and the globally highest-scoring token, so
  a pairwise margin improvement is not misreported as next-token accuracy.
- Saves the exact inputs, configuration, activations, final logits, metrics,
  environment, code hashes, and a closed inventory receipt. Constructed fixture
  weights are included; pretrained weights remain a separately pinned input.
- Verifies byte integrity and replays the numeric computation, comparing both
  results and saved arrays. Hashes establish consistency relative to a retained
  receipt, not publisher authenticity.
- Prepares four synthetic API fixtures covering an allowed decision, revocation,
  an injected authority claim, and a missing fact. No model-selected action is
  executed. Live requests require the explicit `--live` flag.

This package is a standalone experiment. It does not modify or install the
WolfTrap skills plugin or the separate Linux MCP adapter.

## The constructed validation fixture

The fixture is an **untrained, hand-constructed transformer**: one layer, two
heads, eight residual dimensions, and 1,080 stored parameters. A known attention
head copies a synthetic RED/BLUE signal; the other head is deliberately inactive.
Six input variants use different neutral-prefix lengths. Three are predeclared
discovery cases and three are validation cases.

On the delivered run, the active-head patch restored the clean answer in all six
cases. Its normalized restoration was 1.0. The inactive-head patch restored 0.0,
all self-copy controls changed the measured margin by 0.0, and active-head zero
ablation removed the target-versus-alternative signal. These findings validate
the instrument on known wiring. They are not evidence that an outside language
model, backdoor detector, or general model-safety system has been qualified.

`validation.json` records the checks actually executed when this ZIP was built.
`DESIGN.md` explains the scientific method, boundaries, and next engineering step.

## Run the local experiment

The runtime needs Python 3.11+ and NumPy. The packaged run used Python 3.12.14 and
NumPy 2.3.5. No GPU, API key, model download, sudo, or Bubblewrap is required for
the constructed fixture. Crostini execution of this new prototype has not been
performed in this session.

From the extracted directory, if NumPy is already available:

```bash
python3 -m neuralscope demo --out my-neural-run
python3 -m neuralscope verify my-neural-run
python3 -m neuralscope replay my-neural-run
```

Open `my-neural-run/report.html` for the report. Output directories must be fresh;
the program does not overwrite earlier evidence.

If you need an isolated Python environment first:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m neuralscope demo --out my-neural-run
```

Dependency installation accesses the package index; the `demo`, `inspect`,
`compare`, `verify`, `replay`, and `local` commands have no networking code.
The verifier itself uses only the Python standard library:

```bash
python3 -S -m neuralscope verify example-run
```

For stronger custody, retain the printed `manifest_sha256` separately and supply
it to both verification and replay:

```bash
python3 -m neuralscope verify my-neural-run --manifest-sha256 YOUR_RETAINED_DIGEST
```

The receipt has no digital signature. An attacker able to replace both the
evidence and an unpinned receipt can replace their hashes together. Verification
assumes a quiescent local directory; it is not a concurrent hostile filesystem
sandbox.

## Inspect another model's weights

```bash
python3 -m neuralscope inspect /path/to/model.safetensors
python3 -m neuralscope compare /path/to/before.safetensors /path/to/after.safetensors
```

Inspection supports documented common numeric safetensors dtypes. Inference
supports finite F32, F16, and BF16, decoded to float32. Pickle, `.bin`, float8,
sub-byte quantization, shards, arbitrary model code, and remote downloads are
not supported. An unusual weight value or a changed tensor is an observation,
not a finding of malicious behavior.

The experimental local adapter accepts standard GPT-2 configurations and Hugging
Face-style tensor names, with tied or explicitly untied output embeddings. It
rejects unsupported architecture options, quantized and pruned models, and
unexpected tensors. **This release compares one pinned DistilGPT2 checkpoint against Transformers
5.24.0 / PyTorch 2.15.0+cpu on a predeclared finite set of inputs and interventions.**
The dedicated `pretrained` command uses the checked compatibility path for that
checkpoint, including validation of six legacy causal-mask buffers. The generic
`local` command retains its strict learned-weight inventory and does not claim
that other models or configurations have been qualified.

```bash
python3 -m neuralscope local \
  --weights /path/to/model.safetensors \
  --config /path/to/config.json \
  --cases /path/to/paired-token-cases.json \
  --out outside-model-run
```

For the paired-case schema, see `example-run/inputs/cases.json`. Supply token IDs
produced by the exact tokenizer for your model. This version does not include a
general tokenizer. A run requires distinct discovery and validation cases,
equal-length clean/changed sequences, two distinct answer token IDs, and explicit
intervention sites. This version measures next-token answer contrasts; it does
not score complete multi-token answers.

Choose small models and short sequences on a Chromebook. Limits include a 1 GiB
input file, 150 million stored float32 parameters, at most 128 tokens in paired
experiments, 32 selected sites, 512 forward passes, and a 512 MiB projected trace
budget. Those are admission checks, not a guarantee that maximum settings fit in
RAM or finish quickly. Intermediate arrays and the model require additional
memory. No operating-system confinement is implemented here.

## Preview the API pilot

```bash
python3 -m neuralscope api-plan --config examples/api-pilot.json
python3 -m neuralscope api-run --config examples/api-pilot.json --out api-dry-run
```

Both commands above send **zero API requests** and do not read credentials.
`example-api-dry-run/` contains the delivered dry-run evidence.

The configured pilot uses `gpt-6-luna`, reasoning effort `none`, four requests,
and at most 256 generated tokens per request. The model page was checked on
2026-11-23. Its listed standard text prices were $0.10 input and $0.50 output per
million tokens, with $0.125 cache writes. The supplied planning rate uses $0.125
for all input tokens to cover that higher tier. The current dry plan reserves
6,960 total tokens and **$0.001254** inside a **$1 local planning budget**.

Prices and account model access can change. The model name is an alias, and
service availability and use of the user's particular API credit are not tested.
The reservation uses UTF-8 byte lengths plus a 1,024-token envelope per input;
it is a conservative local estimate, not a tokenizer proof or provider-enforced
billing ceiling. The runner stops if returned usage exceeds reservations and
does not retry ambiguous failures. It records estimates separately from actual
provider charges, which it cannot independently determine.

When you choose to send the pilot, place an API key in your local environment,
then explicitly run:

```bash
python3 -m neuralscope api-run --config examples/api-pilot.json --out live-api-pilot --live
```

The runner reads `OPENAI_API_KEY` locally. Do not put the key in chat, the JSON
fixture, or a command-line argument. A local `--live` invocation sends the
configured instructions and inputs to OpenAI and may incur charges. The shipped
fixtures contain invented data. This package has made no such request.

Calls use the fixed OpenAI Responses HTTPS endpoint, `tools: []`,
`tool_choice: "none"`, `store: false`, standard service tier, disabled input
truncation, and no automatic retries. `store: false` does not establish zero
provider retention; the provider's data controls still apply. API outputs are
inert strings or parsed JSON. Refusals and malformed/incomplete responses are
inconclusive, and a matching fixture is not a safety certification.

API evidence is created with a private umask. The configuration export redacts
recognizable API-key patterns; it does not promise comprehensive removal of
arbitrary sensitive text. Invalid configurations are not exported. Raw model
reasoning is not requested or saved as an interpretation of hidden computation.

## Check the source

```bash
python3 -m unittest discover -s tests -v
python3 build_bundle.py --output /a/fresh/path/WolfTrap-NeuralScope-0.3.0a1.zip
```

The source build uses sorted ZIP members, fixed timestamps and permissions, and
stored compression. It includes source, tests, documentation, API configurations,
the constructed local evidence, and the pretrained/attention summaries. Complete
numeric evidence is supplied in a separate ZIP for each study, with the original
model kept as a pinned external input. `bundle-inventory.json` covers every packaged
file except itself. The same source and evidence produce identical ZIP bytes.

Exit 0 means the selected operation completed within its stated scope. Exit 2
means invalid input, an inconclusive experiment, or an observed fixture mismatch.
An offline API dry run can complete successfully while reporting `NOT_RUN` for
live evaluation.

Use the matching version's source ZIP to replay historical evidence: retained
v0.2 summaries are not relabeled as v0.3 executions. New `demo`, `pretrained`, or
`attention` runs use fresh directories and record the installed source/version.

## Research and format references

1. OpenAI, original GPT-2 implementation:
   https://github.com/openai/gpt-2/blob/master/src/model.py
2. Zhang and Nanda, *Towards Best Practices of Activation Patching in Language
   Models: Metrics and Methods*, ICLR 2024:
   https://arxiv.org/abs/2309.16042
3. Safetensors format:
   https://github.com/safetensors/safetensors#format
4. OpenAI Responses API:
   https://developers.openai.com/api/reference/resources/responses/methods/create
5. OpenAI token counting:
   https://developers.openai.com/api/docs/guides/token-counting
6. OpenAI data controls:
   https://developers.openai.com/api/docs/guides/your-data
7. GPT-6 Luna model and pricing:
   https://developers.openai.com/api/docs/models/gpt-6-luna

License: Apache-2.0. This is experimental research software with no general
security or model-safety certification.

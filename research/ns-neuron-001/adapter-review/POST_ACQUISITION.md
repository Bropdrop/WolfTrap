# Installed DistilGPT2 adapter audit

The preflight verified all seven pinned files. The CPU reference environment used Python 3.12.14, Torch 2.15.0+cpu, Transformers 5.24.0, safetensors 0.8.0 and tokenizers 0.23.3. [Pinned-input check](acquired-preflight.json) · [Adapter design review](REVIEW.md)

The installed GPT2LMHeadModel passes attention masks and position IDs to GPT2Model, which uses the supplied position IDs for its embedding lookup and passes the attention mask into causal masking. GPT2LMHeadModel returns the language head's vocabulary logits. GPT2Block applies the MLP after its second layer normalization and adds its result to the residual stream. GPT2MLP applies c_fc, activation, c_proj and dropout in that order. Dropout is inactive in eval mode. The installed Conv1D stores a weight of shape (input, output) and calls addmm on flattened input, weight and bias. The audit records the precise source file digest and method digest for each of the five inspected methods. [Installed methods and shapes](installed-001/loaded.json)

The pinned loader yielded GPT2LMHeadModel in float32 on CPU with eager attention, 81,912,576 parameters and six Conv1D MLP projections. Each weight had 3,072 input rows and 768 output columns. All 76 distinct named parameter tensors were elementwise identical to their serialized counterparts. For each layer, the maximum absolute discrepancy across all discovery-positive projection outputs was zero when reconstructed from the recorded inputs, weight and bias. The check used the original 0.0001 projection tolerance. [Parameter binding](installed-001/parameter-bindings.json) · [Projection reconstruction](installed-001/discovery-projections.json)

Re-encoding each of the 16 individual prompts using the pinned tokenizer produced the real-token suffix of its batched IDs. All masks and positions agreed token by token, including left EOS padding with ID 50256 and each real sequence starting at position 0. The single-token continuations were 6342 for space-prefixed Paris and 11307 for space-prefixed Berlin. This check verified token inputs. Numerical comparisons of batched and single-prompt model outputs belong to the independent measurement evidence. [Per-prompt alignment](installed-001/tokenization.json)

The audit performed model forward passes on the discovery-positive prompts. Run these commands from the research directory after preparing the model and reference environment. Use a fresh output path.

```sh
python -B offline/offline_exec.py -- "$run/venv/bin/python" -B adapter-review/preflight.py --model-dir "$run/model"
python -B offline/offline_exec.py -- "$run/venv/bin/python" -B adapter-review/audit_installed.py --model-dir "$run/model" --out "$run/adapter-audit"
```

The original audit exited 0 and verified the seven model files again after running. [Audit output](installed-001.log)

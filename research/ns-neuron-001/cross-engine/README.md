# Cross-engine comparison of the frozen DistilGPT2 neuron

The recovered v0.3.0a1 NumPy engine took each of the eight held-out prompts as a single, unpadded sequence. Each prompt was freshly tokenized from the pinned tokenizer JSON and checked against the original token IDs, position IDs and mask. Hugging Face GPT2LMHeadModel ran the same singleton unpadded sequences on CPU. Both engines used the same seven pinned checkpoint files. The selection hash binds the neuron, same-layer controls, and all signed and random directions before validation.

The NumPy engine exposes the MLP output as a replacement site. This verifier reconstructed the pre-projection post-GELU activations from the engine’s residual and attention arrays and computed the selected neuron’s final-position contribution as its activation times its projection row. It subtracted that contribution at the MLP output. On Hugging Face it zeroed that coordinate directly before the projection. Both models also received the frozen direction additions at each layer. The original source tree was read only.

Each of the eight cases produced fifty complete logit-array comparisons and sixty intermediate-array comparisons. The NumPy and Hugging Face maximum absolute logit difference was 0.0001220703125 against the registered 0.001 limit. The largest logit RMSE was 0.0000252391 against 0.0001. The largest componentwise intermediate error used 8.42% of the registered allowance. The largest discrepancy between any singleton effect and its original batched value was 0.0001831055. Within NumPy, direct zeroing and projection-row subtraction differed by at most 0.0000009537 at the MLP output. Both engines reproduced their baselines exactly after interventions. Ablating the frozen neuron lowered the target-minus-foil margin for two of four positive prompts and raised it for two.

The protocol, scripts, case records, and compressed paired tensors support local review. Each case JSON records the complete-array hashes and error maxima for all fifty logit arrays. Its NPZ stores full baseline and selected-ablation logits plus every compared intermediate for both engines. Hashes over numerical arrays use the raw C-contiguous float32 bytes. Numerical comparisons use float64 differences. The perturbed layer’s `hidden_before_edit` array records its incoming activation before the intervention. A separate process regenerated all 992 stored arrays from both engines with identical float32 bytes. This comparison supplies finite-case execution evidence from one workspace. An external reviewer has yet to assess the result.

Run from this directory with the prepared dependency environment active. Set `NS_MODEL` to the absolute path of the verified seven-file model and choose fresh output directory names.

```sh
bash run.sh new-measurement
bash replay.sh new-measurement new-trace-replay
```

The wrappers use the offline syscall filter and the recovered source tree in the surrounding evidence bundle. `NS_PYTHON` and `NS_RUN` override the interpreter and standalone run directory. The commands regenerate evidence from the original standalone result and its bound selection.

# Independent miniature-transformer measurement

The float64 reference reconstructed the two-block fixture from its 19,035 saved F32 parameters. It reran the causal forward pass in NumPy and SciPy, using componentwise finite differences of final-position MLP projection outputs to estimate the gradient of the target-minus-foil margin. It generated all context pairs, controls and directions from the discovery protocol seeds. It wrote the 128 scores, eight exact ablations and selected intervention before running held-out cases. No validation effects or historical score arrays were inputs to selection.

On both fresh processes the selected neuron was layer 1, index 19 (zero-based). The mean exact ablation decrease was 0.05761415 on the 12 positive contexts and −0.01087164 on the 12 matched controls. The signed cross-layer intervention increased the margin relative to the six equal-norm random directions on **both** groups. The positive-group means at layers 0 and 1 were 0.07467701 and 0.07435476. The control-group means were 0.12706158 and 0.12182283. These are logit-margin units for this synthetic contrast.

The reference reproduced the full historical discovery ranking and shortlist order. Across discovery and validation, the largest absolute non-finite-difference discrepancy with exported historical measurements was 2.855e−6. The historical float32 central-difference estimates differed from the float64 estimates by up to 5.311e−4. At the archived control scale, all six sampled neuron IDs matched and 82 of 192 direction components differed at the bit level, with maximum absolute error 2.981e−8. Per-field errors, fixed limits, shapes, both control groups and all six direction comparisons at both layers are in the comparison JSON.

For the float64 implementation, complete logits from final-token activation zeroing and direct output subtraction agreed within 8.882e−16. Per-prompt and batched logits and traced layer arrays agreed exactly. All 105 named arrays matched bitwise across independent process executions. The validated arrays cover both layers’ projection inputs, outputs and residuals for the baseline and selected intervention, the discovery gradients and shortlist, and complete logits for every validation intervention. The independent numerical replay provides empirical evidence for the finite synthetic task. Scientific external review requires a separate reviewer.

## Files and reproduction

Run from this directory, alongside the original `../pilot` and the offline launcher. Choose a fresh output directory for each invocation.

```bash
python -B ../offline/offline_exec.py -- ./reproduce.sh my-reference-run
./reproduce_live_comparison.sh my-torch-run /absolute/path/to/fixture-venv/bin/python my-reference-run/first/arrays.npz
```

The independent reference used Python 3.12.14, NumPy 2.3.5 and SciPy 1.17.0. The first invocation executes discovery, freezes the selection, measures validation, repeats the steps in a second process and compares both against the shipped artifacts. The second invokes the original Torch fixture in two more processes, attaches native PyTorch hooks to export the same tensors, verifies pre-existing hook survival after normal and deliberately exceptional exits, and compares every tensor element with the independent implementation.

* `run-001` contains the initial local reference run and separate-process replay.
* `run-002-offline` repeats both reference runs under the process-level socket-denying launcher. Its measurements and comparisons are in `first`, `replay` and `comparison.json`.
* `torch-run-001/first.log` records the original runtime capture failure at the missing transitive Python dependency `packaging`.
* `control-draws` records the comparison of the independent seeded draw implementation with the archived discovery controls.
* `torch-run-002` contains two successful CPU Torch 2.10.0+cpu captures after installation of the verified packaging 26.4 wheel. Forty numeric checks passed per run. Pre-existing hooks survived the deliberate exception and the unhooked baseline returned exactly. All 105 arrays (161,136 elements) matched the independent float64 engine within 2.011e−6; the predeclared limit was 2e−5. Torch replay was bitwise identical. Torch’s maximum selected-ablation versus row-subtraction logit error was 4.769e−7. The per-array comparison is in `torch-run-002/comparison.json`.

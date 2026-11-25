# NS-NEURON-001 individual-neuron study

This private review candidate adds the fixed neuron study to the recovered NeuralScope v0.3.0a1 release. It measures the logit difference between the single-token continuations “ Paris” and “ Berlin” in four discovery and four held-out templates, each paired across France and Germany.

## Run and verify

Use the reviewed CPU reference environment and the immutable seven-file DistilGPT2 snapshot. The neuron command verifies the closed local inventory. It uses the fixed revision `2290a62682d06624634c1f46a6ad5be0f47f38aa`, local Transformers, safetensors, eager attention and float32 evaluation. The command reads its inputs locally. It starts no acquisition or paid API work. Qualified runs used the separate evidence bundle's Linux offline launcher.

```sh
python -m neuralscope neuron --model-dir /path/to/pinned-model --out /path/to/new-neuron-run
python -m neuralscope verify /path/to/new-neuron-run --manifest-sha256 <digest-printed-by-neuron>
```

Each study needs a fresh output directory. To replay, repeat the first command with a new directory and compare the four JSON study files. Each output also includes a NeuralScope manifest sealing those files and the candidate source identities. The verify command checks the sealed inventory. Empirical replay and independent measurement evidence are supplied separately for this candidate.

The procedure scores all 18,432 neurons on the four discovery-positive prompts, exactly ablates the top eight, and selects the greatest positive mean decrease above 0.0001, breaking ties by layer and neuron. It writes the frozen neuron, signed direction, magnitude and six random neurons and directions before held-out forwards. The protocol includes all 16 token sequences, masks and position IDs. The selected neuron is zeroed only at the final position. The signed projection row and six equal-norm directions are separately injected at each layer. A no-selection result and a failed mechanism check are sealed and exit with code 2. [Executed protocol](examples/neuron-protocol.json)

## Measured findings

Discovery selected layer 0, neuron 874. The exact mean drop in the Paris-minus-Berlin margin was +0.391088 logits on discovery-positive prompts. On held-out France prompts it was +0.136527 versus −0.001477 for the six same-layer random neurons, with positive effects on two of four prompts. On Germany prompts it was −0.132092 versus +0.001172, with positive effects on one of four prompts. The expected city ranked first across the full vocabulary on zero of eight baseline prompts. At layers 1–4 on the Germany prompts the chosen direction's mean effect fell below the random directions' mean. These measurements describe this fixed contrast on these eight held-out prompts.

The private evidence package contains two original-harness runs, independent full-logit, projection and single-prompt comparisons and a separate fixture replay. The original-harness JSON files matched byte for byte across processes. The largest absolute full-logit difference between activation zeroing and direct row subtraction was 0.0000457764. The largest padded-versus-unpadded full-logit difference was 0.000114441.

## Provenance

| Input | SHA-256 |
|---|---|
| Recovered owner source ZIP, v0.3.0a1 | `392dcc885ac32688d803d841335a29f2e545db9ccb99f86e42841e1c0f77121a` |
| Supplied pilot ZIP | `f291462a6a9bf8d161c9585ffca2c9be7ed3f196e07a6e8cd12398a4757c3c0a` |
| Qualified module copied byte for byte to neuralscope/neuron_probe.py | `6372d218768d98f487bf89e41230da111bcb16532a8d95818796043f962ef8ce` |
| Fixed executed DistilGPT2 protocol | `45d7425959432611354b4bcebde7a08625a5e7d2d992912e8089989ba57fd561` |

The added CLI uses the package's local model verification and evidence sealing. Method and thresholds are those of the supplied pilot. The inherited source inventory is retained under historical/. The prior example runs, summaries and validation.json describe the historical release. [Original source inventory](historical/v0.3.0a1-bundle-inventory.json) · [Pinned model inventory](examples/distilgpt2-pin.json)

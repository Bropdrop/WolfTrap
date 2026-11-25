# NS-NEURON-001 individual-neuron attribution

This research candidate adds the `neuron` command to NeuralScope `0.3.0a1+ns.neuron.1`. It measures how removing one final-token MLP activation changes the Paris-minus-Berlin logit margin on the pinned 81,912,576-parameter DistilGPT2. The experiment has fixed discovery and validation prompts, exact ablations, six same-layer control neurons, and six equal-norm direction controls at each layer.

Discovery selected layer 0, neuron 874 after screening 18,432 neurons and exactly ablating eight. On four held-out France prompts, the mean decrease was +0.136527 logits and two effects were negative. On four matched Germany prompts, the mean was −0.132092 logits. The expected capital was top-1 on zero of eight prompts. The experiment measures this finite contrast and supports no general claim about factual recall or model safety. [Qualification report](REPORT.md) · [Held-out cases](report/held-out-ablations.csv) · [Cross-layer results](report/cross-layer.csv)

| Review material | Location |
|---|---|
| Integrated source, CLI and 214 tests | [Candidate](candidate/wolftrap-neuralscope/) · [Publication rerun](candidate-validation/publication-verification.json) |
| Original standalone harness and fixture evidence | [Pilot](pilot/) |
| Verified model pins and 39-package reference environment | [Model inventory](recovered/wolftrap-neuralscope/examples/distilgpt2-pin.json) · [Runtime](dependencies/runtime-check.json) |
| Frozen selection and independent-process replay | [Study files](pretrained-runs/study-001/) · [Replay comparison](pretrained-runs/replay-comparison.json) |
| Independent model checks and raw tensors | [Cross-engine experiment](cross-engine/) · [Transformers measurement review](pretrained/) · [Miniature fixture review](independent/) |
| Per-test outcomes, installed CLI parity and reviewer findings | [Test record](candidate-validation/tests/TESTS.md) · [Review](candidate-validation/independent-review.md) |
| Reproduction commands and SHA-256 integrity | [Reproduce](REPRODUCE.md) · [File manifest](SHA256SUMS) · [Integrity checker](verify_publication.py) |

The external DistilGPT2 weights and dependency wheels are identified by public sources and SHA-256 pins. The publication inventory covers the repository copies of the candidate, tests, evidence and documentation. Historical receipts preserve their original digests. Publication notes identify any records with private locations removed.

[Source-tree publication notes](candidate/PUBLICATION.md) · [Input and dependency records](publication-notes-inputs.json) · [Study records](publication-notes-study.json) · [Test records](publication-notes-tests.json)

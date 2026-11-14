# Research lifecycle status

This file records conservative repository-level claims. The generated qualification report is authoritative for the exact commit/tree, dirty state, test counts, experiment counts, bounds, coverage, findings, and control results. A later milestone may advance a status only with the evidence described below.

## Current v0.1 construction status

| Status | Current claim | Evidence required to advance |
|---|---|---|
| DESIGNED | Yes | Tracked threat model, scenario schema, state-machine phases, independent-oracle contract, evidence contract, and bounded workflow design. |
| IMPLEMENTED | Yes | Source, versioned scenarios, CLI, reporting, and tests are present; qualification evidence remains revision-specific. |
| CHECKPOINTED | No claim in this document | A local Git commit containing the complete source and tests, with exact commit and tree SHA recorded in the handoff/report. |
| TESTED | No claim in this document | Actual standard-library test summary and bounded qualification results against the exact checkpoint. |
| LIVE VERIFIED | No | Synthetic tests do not validate a live service, product, tenant, network, or real-world vulnerability. |
| REVIEWED | No | Independent human/security review has not been claimed. Automated oracle reproduction is not a substitute for review. |
| MERGED | No | No merge is authorized or claimed. |
| DEPLOYED | No | No deployment is authorized or claimed. |

The final v0.1 handoff may accurately report `IMPLEMENTED`, `CHECKPOINTED`, and `TESTED` after those actions occur. This tracked page deliberately does not embed its own commit SHA, which would create a source-revision self-reference.

## Meaning of each term

- **DESIGNED**: the intended behavior and safety boundary are documented.
- **IMPLEMENTED**: the described source paths and behavior exist. It does not imply they passed tests.
- **CHECKPOINTED**: the recoverable local Git commit and tree are known. It does not imply a remote push.
- **TESTED**: named commands ran against the exact revision with actual counts and outcomes recorded.
- **LIVE VERIFIED**: the behavior was validated against a real affected implementation. WolfTrap v0.1 explicitly does not perform this.
- **REVIEWED**: an identified independent reviewer completed a review. Oracle independence is a technical control, not this organizational status.
- **MERGED**: an authorized remote branch integration completed.
- **DEPLOYED**: an authorized release was placed into an operating environment.

## Qualification claims and limits

A successful bounded qualification means all mandatory positive controls executed, negative controls produced no forbidden synthetic ledger delta, and the independent oracle found no reproducible invariant violation within the recorded bounds. It is not an exhaustive proof and must report any truncated exploration frontier.

A synthetic finding is classified independently of any model judgment:

- `CONFIRMED`: the minimized case reproduced on fresh fixtures in every required independent attempt;
- `UNVERIFIED`: evidence is incomplete and cannot support confirmation;
- `NOT_REPRODUCED`: the candidate did not reproduce;
- `DUPLICATE`: the evidence fingerprint matches a canonical finding; or
- `FALSE_POSITIVE`: independent expectation correction shows that no invariant was violated.

The deliberately defective SUT is a qualification sentinel. Detecting its synthetic defect demonstrates harness sensitivity, not a vulnerability in third-party software. The correct SUT must pass the identical input corpus, and a deny-all SUT must fail the positive-control gate.

## Model-hypothesis status

GPT-5.6 Sol with Daybreak Blue was requested only when legitimately available. It was unavailable in the v0.1 environment, so:

- provider available: `false`;
- provider used: `false`;
- substituted model: none; and
- findings classified by a model: none.

WolfTrap remains independently useful without a model. Future model proposals must remain in a separate hypothesis record until a deterministic case is generated, run, minimized, and independently reproduced through the normal qualification path.

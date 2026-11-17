# Qualification baseline and priorities

The public `main` baseline is commit `892b822d842456ddfb1ea33db338d4ffe85c0491`,
tree `ce7c1ebc7e336efb1e5f9085bf2b77152d09988b`. PR #5 merged at that commit and
PR #6 at `bd07307931a465d119df3c02045645a9e4d68ed1`. All three hosted push workflows
for the baseline succeeded. The clean baseline passed 274 unit tests with Linux
network isolation. Replayed reports matched all 1,920 cloud-authority checks
across 160 traces and all 20 funnel cases covering 3,019 inert proposals. Their
counts describe synthetic inputs and assertions. [PR #5][pr5] · [PR #6][pr6] ·
[Hosted baseline qualification][baseline-ci]

| Rank | Existing verified behavior | Gap and scope |
| --- | --- | --- |
| 1 | The authority funnel applies a host-owned grant register, checks exact bindings, and exercises three 1,000-proposal controls. A separate synthetic state machine already tests effect phases, replay and revocation. | Observe effects through a separate ledger in the funnel and qualify the shared lifecycle controls against independent expectations and deliberately defective sentinels. |
| 2 | The offline GitDoor-inspired challenge has cloud correlation, benign lookalikes and known misses. Its cloud advisory and synthetic authority are independent. | Add a separate finite identity-audit vocabulary for fictional app-only and cross-tenant activity, OAuth changes, volume and operation chains. |
| 3 | Stage 5.3 implements bounded prompt-document signals. The funnel discards untrusted tool authority claims. | Test advisory and host decisions together, with synthetic Unicode and format variants, benign and unsupported controls, and an independent effect oracle. |
| 4 | The FBI table inventory classifies 29 modeled abstractions and 14 unmodeled entries. | Correct a source citation and bind individual run assertions and oracle verdicts to the matrix. An inventory mapping alone establishes `NOT TESTED` for operational behavior. |
| 5 | Existing hosted workflows pin Actions. Stage 4 assesses static artifact-path signals. | Screen tracked paths and content, reviewed dependencies and explicit evidence paths. Validate the exact PR source under a network namespace before publishing qualification evidence. |
| 6 | The project documents its offline scanners and provides a security reporting policy. | Provide reviewer-oriented architecture, evidence and replay instructions, an agency brief, and original project art. |
| Blocked | Synthetic fixtures can define a conformance contract. | The authoritative private Ground Truth runtime pin and technical ownership are `UNKNOWN / BLOCKED`. Genuine runtime conformance remains `NOT TESTED`. |

The inventory audit used the pinned [FBI FLASH][fbi] and compared context against
Microsoft's primary publications. The qualification labels describe what the
public harness measured. Cloud or model advisories carry no effect authority.

[pr5]: https://github.com/GovernableIntelligence/WolfTrap/pull/5
[pr6]: https://github.com/GovernableIntelligence/WolfTrap/pull/6
[baseline-ci]: https://github.com/GovernableIntelligence/WolfTrap/actions/runs/44142899339
[fbi]: https://www.ic3.gov/CSA/2026/261113.pdf

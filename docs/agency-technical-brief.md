# WolfTrap technical brief for defender evaluation

WolfTrap is public defensive research from Governable Intelligence. It offers offline static inspection of selected CI, container build and agent trust boundaries, and synthetic experiments on host-owned authority. ARTEX public advisories motivate the threat model. WolfTrap is an independent project with no FBI affiliation or endorsement.

## What an evaluator can exercise

- Review bounded GitHub Actions, Dockerfile, agent source, protected-effect and prompt-document patterns. Findings are `STATIC REVIEW SIGNAL`.
- Replay deterministic synthetic cloud-advisory and authority-funnel suites. Observe how a single current host grant, verified at the effect boundary, interacts with untrusted requests, revocation, replay and unknown state.
- Examine synthetic app identity and privileged-operation audit events, including benign lookalikes and known misses. [Offline identity telemetry](identity-telemetry.md).
- Exercise tool-output authority claims and inspect mandatory negative controls in the effect oracle. [Prompt and tool trust challenge](prompt-trust-challenge.md) · [Authority qualification](authority-funnel-challenge.md#qualify-independently-recorded-effects).
- Inspect documented benign lookalikes and deliberately exercised misses. Review a fixture, the expected outcome, recorded synthetic effects, oracle result and completion manifest.
- Reproduce two authority suites from a clean checkout using Python and Git without accounts, paid models or external requests. [Offline evaluation demo](evaluation-demo.md).

## Qualification snapshot

The baseline revision `892b822d842456ddfb1ea33db338d4ffe85c0491` includes 1,920 cloud-authority checks and 3,019 authority-funnel proposals. Each suite exercises a finite set of authored cases. The cloud-authority suite checks that authority is independent of an advisory. The funnel suite includes three logical 1,000-proposal scenarios. These inputs and checks do not measure real incidents or attacker effectiveness. [Public baseline qualification](qualification-baseline.md).

Live ARTEX detection, compromise attribution, control effectiveness on a production tenant, and genuine Ground Truth runtime conformance are `NOT TESTED`. An evaluator can use the [evidence guide](evidence-guide.md) to assess exact revisions, oracle controls and known limits, and the [public conformance contract](private-runtime-conformance.md) to see what a future separately authorized runtime evaluation would require.

For security concerns involving WolfTrap itself, follow the [responsible-disclosure process](../SECURITY.md).

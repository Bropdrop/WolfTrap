# Offline synthetic identity telemetry

WolfTrap replays six defensive identity-audit rules over 27 independently
authored cases. The experiment draws on the identity and privilege boundaries
described in FBI FLASH-20261113-001 and Microsoft’s Storm-0940 report. The cases
use fictional values and fixed audit categories. Coverage and source
qualification apply to the specific finite experiment.
[FBI FLASH](https://www.ic3.gov/CSA/2026/261113.pdf) ·
[Microsoft Storm-0940 analysis](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/) ·
[WolfTrap threat mapping](threat-mapping.md)

## Run and verify

Use Python 3.11+ from a clean checkout at a reviewed commit. The commands use
the local standard library and Git metadata with an empty output directory
outside the checkout.

```bash
export PYTHONPATH=src
python -m wolftrap.identity_telemetry_challenge run --output-dir /tmp/wolftrap-identity
python -m wolftrap.identity_telemetry_challenge verify --evidence-dir /tmp/wolftrap-identity
```

The JSON and Markdown evidence record the checkout commit and tree, input and
report schemas, interpreter and platform, and configured limits. The JSON
lists expected and observed rule IDs and zero-based event rows. It also hashes
each canonical input and the raw fixture corpus. The completion manifest
hashes both report files. Verification recomputes all three files locally
against the current checkout and runtime. A different Python patch version,
operating system, or architecture requires a fresh run for comparison.
The verifier checks content and reproducibility, and supplies no authorship or
publication attestation. [Authored cases](../src/wolftrap/data/identity-telemetry-controls.v1.json)

Exit code 0 means **SYNTHETICALLY VERIFIED**. Exit code 1 means observed
results disagreed with the fixture expectations. Exit code 2 means
**INCONCLUSIVE**, including source instability, an uncommitted checkout,
incomplete coverage, or inconsistent evidence. Every report records live
qualification as **NOT TESTED**.

## Input contract

The Python function `wolftrap.identity_telemetry.inspect_identity_trace`
accepts UTF-8 JSON bytes in `wolftrap.synthetic-identity-telemetry/v1`.
The schema uses local numeric application and tenant aliases and relative
logical ticks. There are no fields for provider identifiers, addresses,
principal names, timestamps, credential material, URLs or free text. Fixed
enum fields distinguish app-only and delegated sessions, sign-in outcomes,
change context, elevated actions, and source and tenant relationship
categories. Semantically inconsistent values, unknown fields, duplicate JSON
keys, and inputs outside 64 KiB or 1–256 records yield **INCONCLUSIVE**. The
runtime also checks event order and cross-field tenant and baseline consistency.
Use fictional data created for the test.
[Machine-readable input schema](../src/wolftrap/schemas/identity-telemetry-v1.schema.json)

The public runner reads only the bundled corpus. It makes no network calls,
invokes no model and collects no tenant records. In a separate future
conformance exercise, an upstream source would need to establish provenance
and retention rules for each normalized field before anyone could interpret
them as production telemetry.

| Rule | Requires | False-positive control and blind spots |
| --- | --- | --- |
| WT-IDENTITY-001 | Successful app-only sign-in with a new source class | Known source classes and delegated sessions are outside the rule. Newly deployed legitimate workloads can still match. |
| WT-IDENTITY-002 | Successful app-only sign-in with a different credential tenant and an unexpected tenant relationship | Known partner relationships are exempt. Missing relationship context is inconclusive. Misclassified context or an ordinary-looking session can evade this rule. |
| WT-IDENTITY-003 | Application credential addition marked unplanned | Positive change-window context suppresses this signal. Legitimate rotation without a corresponding record still matches. |
| WT-IDENTITY-004 | Unplanned elevated consent or role assignment | Limited scope and recorded change windows suppress the signal. A low-scope operation may still carry risk outside the modeled summary. |
| WT-IDENTITY-005 | At least 20 app-only attempts in a 15-minute aggregate and at least three times the greater of 1 and the typical count, using at least 12 comparable baseline windows | Busy steady-state workloads and small counts are excluded. Legitimate scaling can match and unusable baselines are inconclusive. Thresholds are fixture choices. |
| WT-IDENTITY-006 | Unplanned credential addition, privilege change and protected operation for the same app and tenant within five logical ticks, in strict order | Different tenant or app aliases, recorded windows, longer intervals and tied timestamps do not establish the chain. The preceding actions can still raise individual signals. |

The expected results are literal fixture labels. Seven cases collectively
exercise all six rules, seven cover routine negatives, and two isolate
cross-scope chain negatives. Two benign lookalikes are deliberately flagged,
three cases capture known misses in the analysis, and six exercise incomplete
input or context. The results do not establish operational technique
reproduction, production accuracy, or live ARTEX detection.

Individual findings are conditional, advisory `REVIEW_REQUIRED` signals.
`NO_PATTERN_MATCH` indicates that these rules found no supported match.
An incomplete trace can retain supported signals and still be
`INCONCLUSIVE` overall. The detector returns rule IDs and row references.
Effect authorization requires a current independent host grant. No detection
result, change label, or clean report can convey authority.

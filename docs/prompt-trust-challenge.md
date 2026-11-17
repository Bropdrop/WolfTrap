# Synthetic prompt and tool-output trust challenge

WolfTrap crosses 13 authored advisory fixtures with five independent host
authority cases. The Stage 5.3 scanner records the lexical outcome for each
fixture. The existing synthetic authority engine receives a typed host fixture,
and the executor-owned effect ledger and independent reference oracle check
the result over 65 checks.

## Run and replay

From a clean Git checkout with Python 3.11 or later, choose a fresh local output
directory outside the checkout.

```bash
PYTHONPATH=src python -m wolftrap.prompt_trust run --output-dir /tmp/wolftrap-prompt-trust
PYTHONPATH=src python -m wolftrap.prompt_trust verify --evidence-dir /tmp/wolftrap-prompt-trust
```

`prompt-trust-challenge.json` contains the exact source commit and tree, dirty
state and diff hash, report schema, Python implementation and version, OS
family and architecture, fixture hashes, complete typed authority case inputs,
expected and recorded effects, denial reasons and oracle fingerprints.
`prompt-trust-challenge.manifest.json` binds the report by byte count and SHA-256.
The verifier repeats the corpus from the same source revision and recorded
environment and compares both evidence files byte for byte. Fixture text is
available in the pinned [challenge source](../src/wolftrap/prompt_trust.py).

Exit `0` means all bounded controls agree. Exit `1` means at least one authored
control disagreed with the run. Exit `2` means input, execution, or evidence
verification was inconclusive. The challenge uses standard-library Python and
local Git. It requires no model, API key, network, payload or external target.

## Interpreting the two outcomes

| Fixture or condition | Expected result |
| --- | --- |
| Fictional priority claim in plain text, Unicode compatibility characters or an escaped JSON value | `STATIC REVIEW SIGNAL` |
| Benign narration containing the same claim | `STATIC REVIEW SIGNAL` and an explicit benign lookalike |
| Benign summary and labelled instructional example | `NO_PATTERN_MATCH` |
| Quoted priority claim, copied role or sender label, and claimed approval or success | `NO_PATTERN_MATCH` and an explicit known lexical miss |
| Unsupported document type, invalid UTF-8 or malformed JSON | `INCONCLUSIVE` for text inspection |
| Independently provisioned, current synthetic host grant | Exactly one recorded effect for each advisory fixture |
| Expired host grant, foreign origin, foreign principal or unknown host state | Zero recorded effects for each advisory fixture |

Static text dispositions apply only to the scanner's declared scope. The host
engine receives no detector output, claimed author, priority, approval or success
field. Unknown **host** authority fails closed. Inconclusive **text** inspection
and a current, independently supplied synthetic host grant can coexist. A
legitimate control must still record a single effect and a deny-all sentinel
fails qualification.

`SYNTHETICALLY VERIFIED` covers these authored controls and the independent
effect comparison. Live prompt-injection resistance, transport authentication,
real model behavior, real authorization and prevalence estimates are `NOT TESTED`.
Review static findings in context before making any incident claim.

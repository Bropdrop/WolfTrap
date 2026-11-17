# FBI ARTEX source-to-experiment mapping

## Source pin and interpretation

The corpus is pinned to FBI `FLASH-20261113-001`, “Threat Overview of ARTEX Autonomous Penetration Testing Framework,” dated November 13, 2026:

- source: <https://www.ic3.gov/CSA/2026/261113.pdf>
- PDF SHA-256: `3dd86a94d33b29c65f56b4307919b74358e63cfde33a600b61adce5794d169e2`
- marking: TLP:CLEAR

Page references below use PDF page numbers. Each versioned scenario also carries the source identifier, digest, page set, observed-behavior excerpt or paraphrase, ATT&CK identifier/name/URL, and a relationship label. `DIRECT` means the advisory directly associates the behavior with that ATT&CK technique. `UNDERLYING_OPERATION` means the technique describes the protected operation or credential context, not the experiment’s lifecycle property. `DEFENSIVE_STRESSOR` means the experiment is an engineering test motivated by the advisory but has no one-to-one ATT&CK technique.

The experiments reproduce no exploit, web shell, credential theft, command execution, network traffic, external destination, or victim data. They model only authorization and effect-state properties inside local fixtures.

The original PDF matches the pinned SHA-256. Its ATT&CK table on PDF pages 3–6
has 46 printed identifier occurrences across 43 distinct normalized entries.
`T1190`, `T1606.002`, and `T1059` each appear on two pages. The machine-validated
inventory assigns 29 entries to synthetic authority or effect abstractions and
records 14 containment decisions as `NOT_MODELED_V0.1`. The loader validates the
normalized identifier set, exact PDF page references and links to scenario IDs.
[FBI FLASH](https://www.ic3.gov/CSA/2026/261113.pdf)
· [Versioned inventory](../src/wolftrap/data/advisory-techniques-v1.json)

Microsoft describes app-only authentication across customer tenants and
subsequent cloud application credential changes in its October 21
investigation. It recommends correlating app sign-ins and audit records with
authorized administration, including review of volume anomalies, consent and
role assignments. The November 5 and November 6 investigations provide
additional context for compromised application credentials and accelerated
intrusion activity. These publications motivate defensive controls and provide
no qualification of WolfTrap's scenarios or detectors.
[October 21 Microsoft investigation](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/)
· [November 5 Microsoft investigation](https://www.microsoft.com/en-us/security/blog/2026/11/05/threat-actors-use-agentic-AI-tooling-to-find-and-abuse-exposed-secrets/)
· [November 6 Microsoft investigation](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/)

## Machine-readable evidence

The `run` and `sweep` commands generate a manifest-bound `wolftrap-report.json`
with the source commit and tree, report schema and runtime environment. The
`corpus.advisory_technique_inventory` records the pinned table. The
`corpus.advisory_technique_evidence` matrix links each technique to its
authored baseline tests, scenario versions and definition digests, the
relationship category, asserted invariants and independent
oracle verdict. A link with no explicit ATT&CK pairing in the scenario uses
`DEFENSIVE_STRESSOR`. `evidence_case_id` joins a completed baseline to
`cases[].case.case_id`, where the full saved case, case digest, expected and
observed effects, and oracle evidence are included.

`authority_property_status` can be `SYNTHETICALLY VERIFIED` only after the
complete campaign qualifies and every linked baseline passes its independent
oracle. A planned baseline in an incomplete or failed campaign is
`INCONCLUSIVE` for that qualification claim. The case-level oracle verdict
still records a failure when the case ran and failed. Unselected and unmodeled
authority properties are `NOT TESTED`. Every row's
`operational_technique_status` is `NOT TESTED`. This matrix measures bounded
authorization and protected-effect behavior in synthetic fixtures.

To check a completed matrix entry, use the reported `evidence_case_id` and the
exact source revision from the report. This example validates the saved report
pair, reconstructs the named synthetic case, and compares independent oracle
output from a fresh run.

```bash
PYTHONPATH=src python - /path/to/wolftrap-report.json WT-C-REPLACE-WITH-CASE-ID <<'PY'
import sys
from wolftrap.execution import execute_case
from wolftrap.model import ExperimentCase
from wolftrap.report import validate_report_pair
from wolftrap.system import SYSTEMS

report = validate_report_pair(sys.argv[1])
record = next(entry for entry in report["cases"] if entry["case"]["case_id"] == sys.argv[2])
case = ExperimentCase.from_dict(record["case"])
evidence = record["execution"]
replayed = execute_case(case, SYSTEMS[evidence["system_id"]])
if case.digest != evidence["case_digest"] or replayed.assessment.to_dict() != evidence["assessment"]:
    raise SystemExit("Case or oracle output differs")
print("Saved case digest and oracle output match")
PY
```

## Traceability matrix

| Synthetic experiment family | FBI basis | ATT&CK taxonomy used | Synthetic property under test |
|---|---|---|---|
| Legitimate authorized operation (positive control) | FBI recommendations on least privilege and server-side authorization, pp. 9–10 | The matching corpus operation’s underlying technique | A current, correctly bound authorization can append exactly one synthetic effect; this prevents deny-all from qualifying. |
| Identity impersonation and credential substitution | Unsigned SAML assertions, compromised vendor credentials, leaked credentials, forged administrator tokens, and alternate authentication material, pp. 3–5 | `T1078` Valid Accounts; `T1606.002` Forge Web Credentials: SAML Tokens; where applicable, `T1550.002` Pass the Hash and `T1550.003` Pass the Ticket | Substitute subject, presented credential, or principal while retaining a syntactically verified credential. The oracle requires an exact current subject/grant binding. |
| Privilege escalation attempt | High-value IAM roles, `is_admin=true`, additional cloud roles, forged administrator tokens, and Kerberoasting, pp. 4–5 | `T1098.003` Account Manipulation: Additional Cloud Roles; `T1134.001` Access Token Manipulation: Token Impersonation/Theft; `T1606.002`; `T1558.003` Steal or Forge Kerberos Tickets: Kerberoasting | Present a valid read-scoped authorization for a protected synthetic role-assignment operation. Scope and digest must reject the escalation. |
| Trusted relationship and supplier-origin substitution | Cross-account cloud trust, compromised third-party vendor credentials, trusted B2B federation, and systematic supplier trust mapping, pp. 2–3 | `T1195` Supply Chain Compromise; `T1199` Trusted Relationship | Change the synthetic supplier origin while retaining the credential. Final commit requires the configured origin binding. |
| Unauthorized protected-resource access | Missing Web API authentication, IDOR, authentication bypass, and the recommendation for server-side authorization of customer records, pp. 3–4 and 10 | `T1190` Exploit Public-Facing Application; `T1078` Valid Accounts | Use an authorization bound to one synthetic resource against another resource or operation digest. No protected effect may appear. |
| Simulated credential persistence | Added OAuth application credentials, SSH keys, account takeover, and unexpected application credential modifications, pp. 4 and 9 | `T1098.001` Account Manipulation: Additional Cloud Credentials; `T1078.004` Valid Accounts: Cloud Accounts | Present a syntactically verified but unregistered, stale, or substituted synthetic credential. Verification alone does not establish current authority. |
| Revoked and expired authorization | Recommendations to revoke unnecessary permissions, rotate credentials, and remove unauthorized credentials/grants, pp. 10–11 | `T1098.001` and `T1078` as `UNDERLYING_OPERATION`; expiry/revocation is a `DEFENSIVE_STRESSOR` | Advance logical time past expiry or revoke before commit. The system must re-read current authority and produce no new effect. |
| Concurrent multi-agent execution | Concurrent campaigns at scale, p. 2; multiple sub-agents overwriting each other or producing duplicate requests, p. 9 | The protected operation’s ATT&CK reference as `UNDERLYING_OPERATION`; concurrency itself is a `DEFENSIVE_STRESSOR` | Explore selected, recorded interleavings at security-relevant yield points within explicit bounds. Shared replay authority may commit at most one effect; independent valid operations remain possible. |
| Replay and duplicate operation | Duplicate requests and iterative high-volume attempts, p. 9; alternate authentication material, p. 5 | `T1550.002` / `T1550.003` only when the modeled credential context warrants them; otherwise the operation’s mapping is `UNDERLYING_OPERATION` and replay is a `DEFENSIVE_STRESSOR` | Reuse a consumed authorization or retry after a lost response. The durable replay journal and effect ledger must show no duplicate effect. |
| Unauthorized synthetic data transfer | Mass blob reads, command output to rotating webhook endpoints, local/remote staging, and structured-data transfers to unauthorized destinations, pp. 5–8 | `T1530` Data from Cloud Storage; `T1005` Data from Local System; `T1074.001` Data Staged: Local Data Staging; `T1074.002` Data Staged: Remote Data Staging | Attempt a `transfer` only between in-memory `synthetic://` resources and `synthetic-sink://` destinations. Unauthorized scope/origin/digest combinations cannot change the ledger. |
| Delayed execution and recovery races | Compressed detection window, p. 3; containment, revocation, credential removal, and evidence preservation, pp. 10–11 | `T1078` or `T1098.001` as `UNDERLYING_OPERATION`; delay/recovery is a `DEFENSIVE_STRESSOR` | Interleave authorization, revocation, crash-before/after-commit, restart, and retry. Unknown recovery state freezes effects; post-commit recovery never repeats an effect. |

## Advisory identifier correction

The advisory’s privilege-escalation table prints `T11558.003` for Kerberoasting
on PDF page 5. WolfTrap normalizes the identifier to MITRE ATT&CK's
`T1558.003`. The inventory expands the display label for `T1134.001` to its
MITRE ATT&CK sub-technique title, Token Impersonation/Theft.
[MITRE ATT&CK T1558.003](https://attack.mitre.org/techniques/T1558/003/)
· [MITRE ATT&CK T1134.001](https://attack.mitre.org/techniques/T1134/001/)

## What this mapping does not establish

An ATT&CK reference classifies source behavior; it does not make a synthetic case an implementation of that technique, and it does not establish exploitability. Concurrency, replay, expiry, revocation, delayed execution, and crash recovery are explicitly labeled defensive engineering stressors where ATT&CK has no direct lifecycle technique. Results apply only to the named synthetic SUT, saved case, and recorded source revision.

Replay deduplication in v0.1 is keyed to the synthetic authorization nonce. Two
distinct, concurrently current authorizations for the same higher-level business
operation are not treated as one idempotency key; operation-level business
idempotency is a future qualification surface and is not claimed here.

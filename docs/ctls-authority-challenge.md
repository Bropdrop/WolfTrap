# WT-CTLS-001 — offline synthetic regulatory authority-transfer and revocation challenge

**Status:** SYNTHETICALLY VERIFIED for the authored fixtures after successful local qualification. **Health Canada CTLS status: NOT TESTED.** This is an independently invented **hypothetical licensing workflow**, not a description, imitation, or test of Health Canada's implementation, security controls, policy, or real data.

The purpose is to show how WolfTrap can qualify transfer authority and ledger effects in a controlled, fictional model before a separately authorized review. It contains **no HTTP requests, credentials, external addresses, government integration, account names, personal information or production data**. Identifiers and payloads are limited to bounded `syn-*` aliases.

## Run from the WolfTrap repository (Python 3.11+)

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -p test_ctls_challenge.py -v
PYTHONPATH=src python3 -m wolftrap.ctls_challenge run --output-dir /tmp/wt-ctls-001
PYTHONPATH=src python3 -m wolftrap.ctls_challenge verify --evidence-dir /tmp/wt-ctls-001
```

The output directory **must not already exist**. For a second run, use a different new path. No dependencies beyond the Python standard library are required for these commands. Tests mock `socket.socket` and `socket.create_connection` to fail immediately if used during evidence generation and verification.

## Exercised synthetic authority contract

1. A fictional organization owner prepares a transfer bound to organization, source, target, transaction ID, nonce, expected authority epoch and expiry. The resulting SHA-256 digest is a request-binding checksum, **not authentication or a cryptographic signature**.
2. A *different* still-authorized fictional reviewer must approve the exact bound transaction. Self-approval and destination-approval fail. This separation of duties is **a research policy we chose**, not a documented Health Canada requirement.
3. At commit, the current owner, active reviewer, intact binding, current epoch, live validity interval and known security state are checked. Commit changes the owner and increments the epoch once, records an effect, and creates an auditable outcome.
4. Revocation, expiry, authority-state loss, epoch advancement and cancellation fail closed. Closed transaction IDs and reserved nonces cannot be recycled by retrying after a simulated restart.
5. A lost acknowledgment returns `ACK_LOST` even though the synthetic effect committed; retrying the same transaction returns `ALREADY_COMMITTED` without a second effect. For profile-write idempotency, the caller is authorized **before** operation ID lookup.
6. The independent observer's effect ledger, the model's claimed effects, the authored expected effects and the final authority owners must match. The append-only hash-chained audit must agree with every effect. A fictional checkpoint can be restored in-process; this is **not a test of durable production storage**.

## Hostile scenario coverage

The fixed 37-case matrix covers: legitimate transfers; attempted original-owner access after transfer; cross-organization impersonation; missing, unauthorized and self-approvals; duplicate approval; repeated prepare/commit; lost commit response and restart; competing transfers with a single permitted winner; reviewer revocation before/after approval; epoch transitions; expiry at the exact boundary; cancellation and retained tombstones; unknown host security state; restart at several phases; copied approvals; altered request-binding digests; nonce collision and transaction ID conflict; duplicate and conflicting profile writes; unauthorized profile effects; unaffected neighboring tenant; and rejection of a cross-tenant commit.

Six deliberately defective models prove that the controls can reject: blanket denial (`DENY_ALL`), skipped reviewer requirement (`NO_WITNESS`), stale-epoch acceptance (`ALLOW_STALE`), previous-owner access (`ALLOW_OLD_OWNER`), false success without an independent effect (`FAKE_SUCCESS`), and ignored request binding (`IGNORE_BINDING`). A result for a known-defective model that unexpectedly passes **fails** qualification.

The 19 additional unittest methods check scenario witnesses, negative controls, unknown-field and non-synthetic-input rejection, replay, checkpoint and audit corruption, integrity-manifest rewriting, symlinks, missing and extra evidence, output overwrite refusal, deterministic replay and network-socket blocking.

## Evidence package

Each run produces precisely these four files:

| Artifact | Content |
| --- | --- |
| `wt-ctls-001.inputs.json` | Full authored fictional command traces, independent expected decisions, protected effects and final owners |
| `wt-ctls-001.report.json` | Case-level expected vs observed decisions, independent effect-witness ledger, claimed effects, audit head, checkpoint digest, six mutation results, module source SHA-256, and precise qualification classification |
| `wt-ctls-001.report.md` | Readable summary, per-case control results, mutation results and explicit limitations |
| `wt-ctls-001.manifest.json` | Completion marker plus exact byte counts and SHA-256 digests for all other artifacts |

`verify` rejects missing, extra, symlinked, oversize, altered or non-replayable artifacts. It *recomputes* the entire deterministic case matrix rather than trusting the submitted manifest. If an attacker controls the expected source or can replace the entire code checkout, an unkeyed SHA-256 manifest cannot provide authenticity; preserve the repository commit/tree and obtain those hashes from a trusted channel. The synthetic audit is not a signed regulator audit.

**Exit codes:** `0` full synthetic qualification; `1` failed authored control or mutation detection; `2` malformed inputs, evidence failure or incomplete evaluation. **No finding from this pack proves a CTLS security issue.** Do not send it as a government vulnerability disclosure unless a genuine issue is independently confirmed under authorized scope.

## Non-goals and future work

No CTLS endpoint probing, scanning, login, rate-limit testing, account manipulation, scraping, active vulnerability exploitation, personally identifiable records, or live operations. The simulator does not provide actor cryptographic identities, two-phase durable database commits, real time concurrency, restart persistence across processes, KMS/HSM evidence anchoring, hardware isolation or production implementation conformance.

A genuine conformance effort would require **written permission** from the asset owner, approved test assets and methods, a non-production environment, specified data handling, a trustworthy effect ledger and documented replay procedures. Keep these research cases detached from Health Canada systems unless that approval is secured.

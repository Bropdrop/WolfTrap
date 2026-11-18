# Sandbox isolation and authority funnel: three-stage synthetic challenge

**Research status: synthetic only.** This offline WolfTrap challenge tests the
*composition* of a fictional host-owned sandbox profile and the existing
host-owned authority-funnel model. It does **not** start an operating-system
sandbox, execute a model, contact OpenAI, or exercise a real Ground Truth or
HERCULES runtime. A declared sandbox policy is not evidence that a process
is isolated. Synthetic grants are not cryptographic credentials.

An execution sandbox and an authorization service address distinct risks:

| Boundary | Question | Evidence needed in a future live deployment |
| --- | --- | --- |
| Sandbox | What can a process read, write or reach? | Actual enforced filesystem, network and process isolation; tested denies and positive controls |
| Authority | Who may initiate this protected effect, now? | Trusted principal/delegate/tenant/target binding, fresh grant and independent verification |
| Effect boundary | What actually happened? | Independently retained effect records, replay prevention, final authority check and recovery tests |

Sandbox success never creates a grant. A grant never overrides sandbox denial.
Agent messages, model confidence, tool output or a CI report cannot promote
itself to current authority.

## Reproduce offline

From a public checkout with Python 3.11+:

```bash
export PYTHONPATH=src
python -m wolftrap challenge-sandbox-authority --output-dir /tmp/wolftrap-sandbox-authority
python -m wolftrap verify-sandbox-authority --evidence-dir /tmp/wolftrap-sandbox-authority
```

Use a fresh/empty evidence directory outside the source. The challenge writes
`sandbox-authority-challenge.json`, a Markdown overview and a SHA-256 manifest.
The verifier regenerates the finite corpus, compares saved report bytes and
rejects altered, missing, extra or symlinked files, including rehashed-but-
altered reports. These are replayable local integrity checks, **not signed
attestations or independent retention**.
The JSON retains a reason for every synthetic sandbox and authority decision,
plus the separately observed effect records and per-stage digest.

## Authored controls

Each stage contains **1,000 separately identified synthetic agent intents**,
processed sequentially as records. No parallel workers or real effects run.
The host's sandbox registry is distinct from submitted intents; agents cannot
invent an effective sandbox by claiming that one exists.

| Stage | Adversarial mix | Synthetic effect records |
| --- | --- | ---: |
| 1. Sandbox envelopes | 250 missing environments; 250 out-of-scope filesystem requests; 250 disallowed network requests; 249 lacking host approval; 1 admitted | 1 |
| 2. Host authority | 999 wrong-delegate requests carrying fake vendor approval; 1 matching host-delegated request | 1 |
| 3. Effect boundary | 300 stale-epoch; 300 revoked; 398 expired; 1 valid operation; 1 distinct valid grant competing for the occupied host slot | 1 |

The test requires all authored sandbox and authority decision counts to match,
the independently implemented authority oracle to agree with the gate, and a
**separately recorded synthetic effect sink** to match authorized effects.
Unit tests catch fail-open sandbox, deny-all and fabricated-success sentinels.
Malformed inputs and real path/network strings fail the bounded typed schema.

This composes boundaries that were previously qualified separately. The
earlier [authority-funnel challenge](authority-funnel-challenge.md) and
[extended effect qualification](authority-funnel-challenge.md#qualify-independently-recorded-effects)
remain unchanged. Stage 3's stale/revoked/expired conditions are pre-decision
snapshots; the existing phased qualification models changes *after* preparation.

## Fail-closed expectations for private live qualification

An authorized disposable runtime must stop protected effects if:

- Sandbox creation or enforced isolation is missing, unknown or weakened;
  an agent requests disallowed mounts, paths, network access or subprocesses.
- Broker authority is missing, invalid, stale, expired or revoked; principal,
  tenant, origin, delegate, slot, scope or operation digest mismatch; a replay
  or conflicting grant occurs; or security state is unknown.
- An approval response is treated as authorization without independent
  authority binding, or the required final commit-time check is absent.
- Independent effect evidence is absent/inconsistent, or after a crash the
  runtime cannot tell whether an effect committed. Unknown cannot become allow.

For real end-to-end qualification, capture actual OS sandbox configuration,
denial outcomes, trusted broker decisions, true effect records, final commit
checks, retained audit evidence and restart behavior. Run 1,000 *concurrent*
isolated agents only after those prerequisites. Keep private HERCULES and
Ground Truth source, receipts and credentials in their own repositories.

**Verdicts:** Passing this finite challenge means `SYNTHETICALLY VERIFIED`
for authored controls. Real isolation, live concurrency, runtime integration
and production attack prevention remain `NOT TESTED`. One authorized effect
per *tested contention slot* is a test policy, not a universal rule that
only one agent may ever act.

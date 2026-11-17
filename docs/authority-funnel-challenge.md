# ARTEX-informed synthetic authority-funnel challenge

This optional WolfTrap research preview exercises a **host-owned authority
decision** against untrusted agent proposals. It is an offline, bounded state
machine, **not a live ARTEX emulator or a Ground Truth runtime integration**.
The design draws defensive stressors from FBI `FLASH-20261113-001` (November
13, 2026) and Microsoft's October 21, 2026 investigation of Storm-0940:

- <https://www.ic3.gov/CSA/2026/261113.pdf>
- <https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/>

Those sources describe real malicious automation and stolen application
credentials. They do **not** independently validate this synthetic experiment.

## Run and verify

From the WolfTrap repository with Python 3.11+:

```bash
export PYTHONPATH=src
python -m wolftrap challenge-authority-funnel --output-dir /tmp/wolftrap-authority-funnel
python -m wolftrap verify-authority-funnel --evidence-dir /tmp/wolftrap-authority-funnel
```

The directory must be fresh or empty. Three fixed-name files are produced:
`authority-funnel-challenge.json`, `authority-funnel-challenge.md`, and
`authority-funnel-challenge.manifest.json`. The manifest pins the two report
files by exact byte size and SHA-256; verification regenerates the entire
finite corpus and independently checks its complete bytes. Altered reports,
extra files, symlinks, and incomplete manifests fail closed.

Exit codes: `0` means all authored synthetic controls matched the gate and an
independently implemented reference; `1` means an authorization mismatch;
`2` means malformed input, unknown execution state or evidence failure.

## Qualify independently recorded effects

Run the extended qualification at a clean source checkout. Choose a fresh
evidence directory outside the checkout.

```bash
export PYTHONPATH=src
python -m wolftrap.authority_qualification --output-dir /tmp/wolftrap-authority-qualification
python -m wolftrap.authority_qualification --evidence-dir /tmp/wolftrap-authority-qualification
```

The qualification exercises the original 3,019 proposals and adds 1,000
coordinated proposals with competing grants, substitutions, privilege claims and
replays. The expected outcome is one effect in the new case's host admission
slot. The test executor captures synthetic effect writes separately from the
gate's returned decisions and effect claims. Unknown proposal fields such as
votes, priority and confidence are rejected by the input schema.

Eight separate phase schedules exercise the existing synthetic authority
engine's positive control, revocation during execution, shared-nonce
contention, crash recovery and the effect of expiry, epoch changes or unknown
authority after preparation. The qualification requires the correct models
to match their oracles and the authored controls. It also requires all five
sentinels to produce their expected failures, covering omitted final checks,
omitted replay controls, missing tenant binding, fabricated success and deny-all.
An unexpected result or a sentinel that escapes fails qualification.

The manifest checks the byte counts and hashes of
`authority-qualification-inputs.json` and `authority-qualification.json`. These
files retain the full authored cases, observed and expected effects, independent
verdicts and exact Git commit and tree. The verifier regenerates and replays
the cases at that source revision. It checks the original execution's recorded
Python and platform metadata for format. Tampering that also rewrites artifact
hashes still fails when the resulting evidence differs from replay. The
manifest supplies integrity and replay checks without a signing identity.

Passing this qualification supports **SYNTHETICALLY VERIFIED** for the finite
controls. **NOT TESTED** applies to live conformance. Phase transitions and
tenant/delegate/slot checks run in distinct synthetic models. The disposable
ledger is process-local, and the crash schedules represent logical task
transitions. The tests use only fictional fixtures and need no network, API
credentials or model.

## Coverage and protected effect contract

The fixed **20-case, 3,019-proposal** corpus covers:

| Threat-inspired condition | Simulated authority requirement |
| --- | --- |
| Tool output claiming system or vendor approval | An untrusted marker never creates a host grant |
| Credential copied by an unauthorized agent | Host-owned grant must match the exact delegate |
| Cross-tenant application credential reuse | Host-owned grant must match the exact tenant |
| Role escalation or tool-argument substitution | Exact scope and canonical operation digest required |
| Origin and target-slot substitution | Origin and admission slot must match the trusted grant |
| Revocation, expiry, epoch changes, invalid seal, unknown host state | Fail closed before effect |
| 1,000-agent unregistered-grant flood | Zero synthetic effects |
| 1,000-agent contention with one trusted delegate | Exactly one synthetic effect |
| 1,000 repeated authorized proposals | One effect; all duplicate nonces rejected |
| Two distinct valid grants racing for one slot | At most one effect in that host-owned slot |
| Untrusted claim attached to an otherwise valid proposal | Do not let claim override the host's positive authorization |

The independent reference checks exact ordered decisions and synthetic
effect records. Separately authored positive and negative expected labels
ensure an always-deny implementation cannot pass, nor can an always-allow
implementation. Test sentinels explicitly verify both failures.

The host's registry of grants is **separate** from incoming proposals. The
`tool_claim` field uses inert enumeration values (`SYSTEM_OVERRIDE`,
`VENDOR_APPROVAL`, `GRANT_ADMIN`, `IGNORE_POLICY`) so neither free-form prompt
content nor a remote URL, credential, executable command or payload enters the
engine. No agent, model, API, service principal or network endpoint runs.

Grant fields represent hypothetical trusted facts: principal, delegate,
tenant, origin, resource scope, operation digest, validity interval, revocation,
epoch, nonce and slot. The `seal_valid` boolean is **not cryptography**. Neither
`grant_id` nor a matching string constitutes secure proof in real systems.

## Boundaries and next integration step

This challenge **cannot claim to stop stolen valid vendor credentials** when
an attacker becomes indistinguishable from a legitimately authorized caller.
It does not measure LLM prompt-injection resistance, live swarms, detector
accuracy, breach prevention, vendor security, or performance under concurrency.
Its 1,000 agent proposals run as deterministic logical events, not real threads.

For a future *private* Ground Truth conformance exercise, an authorized adapter
would need to:

1. Issue host-owned authority via the actual trusted broker, never via a tool
   response, agent declaration or public fixture string.
2. Bind authoritative principal, delegate, tenant, origin, operation digest,
   epoch and target from trusted provenance. Recheck them at the effect boundary.
3. Verify revocation and lifetime using authoritative state, and persist replay
   reservations and final effects across crashes.
4. Capture the **actual** protected-effect ledger (not the agent's reported
   success) and independently assess it, including one legitimate positive.
5. Run only in a disposable, isolated, explicitly authorized test environment.

There is no such adapter in this public preview. Keep Ground Truth, HERCULES,
MobiPute and other private runtime code and credentials in their own private
repositories. Copying them into public WolfTrap is neither needed nor allowed
by this experiment.

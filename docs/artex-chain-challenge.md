# ARTEX-inspired adversarial chain challenge (synthetic)

**Status: bounded offline research only.** The name describes a threat pattern,
not a claim to run ARTEX, detect a real intrusion, or reproduce the 2026
European Commission incident. This challenge does not connect to any target,
start an OS sandbox, invoke a model, execute tools, elevate privileges or
operate a Ground Truth/HERCULES runtime.

## Purpose

The earlier [1,000-intent sandbox/authority challenge](sandbox-authority-challenge.md)
tests isolation, approval and authorization conditions separately. This new
suite focuses on **four dependent steps in one simulated agent operation**:

1. `RECON` — request access to a fictional, explicitly scoped public index.
2. `ACCESS` — request a fictional record in that same tenant.
3. `PRIVILEGE` — request the specifically authorized synthetic viewer role.
4. `COMMIT` — request the final, exact-bound fictional protected effect.

The host-owned authorization ledger binds *each* stage to an agent, tenant,
chain, action/resource, operation digest, approval, grant lifetime, revocation
time and epoch. After the first accepted step, the chain keeps its original
agent/tenant/chain identity even if a later request brings an independently
valid grant for a different identity. A separate host-owned sandbox envelope denies out-of-scope
filesystem and network requests before checking authority. Untrusted
`SYSTEM_OVERRIDE` or `VENDOR_APPROVAL` tool claims are inert labels.

**One denial halts the entire chain.** Success at `RECON`, `ACCESS` or
`PRIVILEGE` cannot authorize `COMMIT`; its grant must still be current and
match the exact operation at final authorization time. The in-memory effect
sink must record the result independently of the gate's success claim.

## Reproduce without network access

Requires Python 3.11+ and a new/empty local output directory:

```bash
export PYTHONPATH=src
python -m wolftrap challenge-artex-chain --output-dir /tmp/wolftrap-artex-chain
python -m wolftrap verify-artex-chain --evidence-dir /tmp/wolftrap-artex-chain
```

The 16 fixed cases contain **65 sequential fictional attempts**. One
four-step positive control must write exactly one in-memory effect record.
Every adversarial case must write zero. Cases cover:

| Boundary | Adversarial control |
| --- | --- |
| Recon / sandbox | Unlisted network request, out-of-scope filesystem request, unknown isolation |
| Privileges | Attempted escalation from authorized viewer scope to unauthorized admin scope |
| Approval | Forged vendor approval and an explicit host approval denial |
| Authority continuity | Revocation after three successful preliminary steps, expiry at commit and stale epoch |
| Provenance | Wrong tenant, wrong delegate, substituted operation arguments, valid foreign grant splicing |
| Lifecycle | Duplicate/out-of-order step and unknown authority state |

Every synthetic attempt produces a recorded reason. The gate is compared
against a **separately implemented reference** and fixed authored expected
reasons. The separately captured effect ledger is compared against the gate,
reference and expected effect count. Unit-test sentinels demonstrate that
unconditional admission, deny-all, skipped revocation and fabricated success
are detected as `CONTROL_GAP`.

The evidence package contains `artex-chain-challenge.json`, a Markdown
overview and an SHA-256 manifest. The verifier replays the exact fixtures and
rejects missing, extra, symlinked or altered files, even if an altered report
is rehashed. Hashes support deterministic local integrity checks; they do
**not** establish a trusted signature or independently retained audit trail.

## What remains unqualified

- Real ARTEX activity, detection signatures, intrusion prevention or any
  European Commission network/system.
- Enforced kernel/OS sandbox isolation, intercepted subprocess destinations,
  network egress restrictions or any live scanning.
- Authentic human approval, cryptographic capabilities, host broker trust,
  cross-process state persistence or third-party evidence retention.
- Concurrent autonomous agents, crash/restart ambiguity or a live private
  HERCULES/Ground Truth end-to-end protected-effect boundary.

This is an authorization **design regression**, not a production safety
certification. The result `PASSED_BOUNDED` means only that these authored
inert controls matched their oracle and independently observed records.

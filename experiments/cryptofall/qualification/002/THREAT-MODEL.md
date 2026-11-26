# WT-CRYPTO-002 threat model and integration plan

## What supplies authority

The original signature evaluator accepts a claim only under an externally supplied policy, epoch, request ID, effect digest and clock. A hybrid policy requires both Ed25519 and ML-DSA-65 from each of two distinct roles. A PQ-only policy requires one ML-DSA-65 key per role. The maximum claim lifetime is 30 seconds. Both evaluators allow repeated verification of evidence.

The successor takes a versioned, canonical JSON wire. Its 32 KiB size bound and 12-level depth bound apply before interpretation. Exact schemas reject extra fields, duplicate names, unsupported numbers and unrecognized algorithms. Each signature binds its domain, realm, role, algorithm, key fingerprint and the complete claim or transition. The receiver selects slots from the provisioned policy. For effects the caller supplies the exact operation bytes and expected request ID. Changing either changes the verification outcome. Archive bytes checked against a retained digest receive only the historical classification.

A separate trusted fixture operation provisions or withdraws a disposable counter permit. It binds one exact request to a policy digest. Signature verification and policy publication cannot mint this permit. The counter checks it under the commit lock and uses the request ID as the durable one-use receipt key across epochs. The permit fixture lives on the test host. Real foreground approval, human identity, organizational custody and native execution authority remain unexercised.

## Changing or losing trust

The fixture pins genesis and provisions recovery and policy-witness public keys separately from effect keys. An ordinary rotation needs every current owner algorithm plus the independent policy-witness signature. A transition authenticates its scope, counter instance, action, time window and successor policy. The successor must increment the epoch by exactly one and name the exact predecessor digest. Key and algorithm revocations accumulate. A revoked key may be recorded in place to stop use immediately. An administrator cannot assign a removed revoked key back into a slot.

Emergency quarantine suspends effects. Recovery requires both separately provisioned ML-DSA-65 roots and a quarantined predecessor. A key-compromise exercise replaced the disposable owner and rejected its old signature. An algorithm-compromise exercise quarantined the hybrid policy, recorded Ed25519 revocation and explicitly selected PQ-only at recovery. Both surviving PQ roles signed the fresh claim. Revoking ML-DSA-65 or either necessary root blocks recovery that depends on it. A suspected failure of the shared backend, SHA-256 or the recovery primitive requires withholding the trusted checkpoint. This lab has no other independently provisioned authority to resume from such a failure.

The model assumes the pre-provisioned recovery roots, retained hashes and trusted clock are genuine. The pinned native extension was measured in the local environment. Its hash check is cached per process and assumes trusted imports, operating system and filesystem throughout that process. The CLI and Python verification backends use different OpenSSL builds. The RFC and ACVP results cover the cited vectors. No validation status or cryptographic break is inferred.

## Rollback, races and crashes

The checkpoint model holds the current policy, last trusted time, disposable permits and monotonic effect sequence outside SQLite's restore domain. The model serializes policy and permit updates with counter commits under one lock. SQLite writes an increment and its exact receipt in one transaction. Just before committing, the writer rechecks expiry and reserves the next external sequence. If SQLite rolls back after reservation, further writes freeze on the mismatch. Exact receipt recovery requires a fresh, synchronized checkpoint and matches the original request and authorization bytes.

Both lock orders were exercised. In one case a pending request verified, a policy update took effect, and only the newly authorized request incremented. In the other case the updater reached the held commit lock, one authorized write completed, and quarantine fenced the next attempt. A local policy snapshot restored at the same effect sequence froze until synchronization. A pre-effect database restored after a committed write continued to freeze on the effect sequence mismatch.

The crash runner killed the writer process inside the real counter adapter immediately before or after SQLite commit. A parent-owned shared-memory sequence survived the writer. The first outcome froze further writes. The second recovered an exact receipt after a lost reply and denied repeat execution. These experiments assume a live parent, one coordinating policy lock, trustworthy clock samples and normal SQLite durability. A silently stopped trusted clock, rollback of the parent together with the database, arbitrary database edits at a matching coordinate, loss of the checkpoint host, power failure and distributed fencing remain unqualified. Reconstructing an anchor from local genesis would require new, independent trust.

## Integration plan

1. Retain the hash-pinned v1 archive and run its 33 original tests with the published historical semantics. Keep the explicitly versioned v2 wire and registry opt-in. Use the paired role, freshness, request identity and legacy signature cases when changing either verifier.
2. Before any native integration, establish independent custody of real recovery trust and independently verify the supported backend distributions and provider configuration. Preserve WolfNet's evidence classifications, the release verifier's current versus historical rules and main's zero mandatory runtime dependencies.
3. Qualify a checkpoint service with authenticated fresh reads, monotonic updates and fencing shared across all intended writers. Exercise checkpoint outage, host loss, restored snapshots, ambiguous reservations and recovery on disposable infrastructure.
4. Qualify the native execution gate, exact-effect commit and a separately authorized foreground approval ceremony under their own governance. Production release remains BLOCKED. No production or human ceremony was authorized by this experiment.

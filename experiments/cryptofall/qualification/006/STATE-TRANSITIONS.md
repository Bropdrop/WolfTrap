# BLACKBOX state transitions

The disposable effect is the integer in the target's SQLite database. Gate processes forward authorized requests. Deleting a gate volume removes its signing identity. The counter, permits, reservations and receipts live on the target volume.

| Starting state | Input and preconditions | Transaction and observable outcome |
| --- | --- | --- |
| No permit | Fixture administrator grants the exact increment request under an active policy | Insert an unspent permit with a fresh ID, caller request ID, exact request digest and policy digest. |
| Unspent permit | Current gate signs prepare for the realm, generation, permit and request/evidence binding | Verify all required effect signatures, time window, request ID and current permit. Insert a unique reservation for the permit. Repeating the exact prepare returns the same token. A live reservation alone yields UNRESOLVED. |
| Reserved | The current gate signs execute for the same intent and reservation token | Acquire BEGIN IMMEDIATE. Recheck current policy, live clock, gate incarnation, exact request, permit and unused request ID. Increment the counter, mark the permit spent and insert the target-signed recovery receipt. Recheck expiry immediately before SQLite commit. Publish the receipt only after commit. |
| Reserved, including an obsolete epoch or generation | Two distinct provisioned administrative signers approve a fence for this realm, permit and current target revision | The same serialized target transaction spends the permit and inserts a signed NOT_COMMITTED tombstone. A delayed execution must still pass the unspent-permit, epoch and gate checks. A committed decision is terminal. |
| Committed or fenced | Authorized caller presents the permit, exact request and exact evidence | A matching durable decision supports recovery without a new execute. A different binding cannot disclose the receipt. |
| Pending during emergency quarantine | Recovery and policy-witness keys authorize a transition naming the exact predecessor and successor | Increment the policy epoch and record cumulative revocations. Existing reservations give no exemption at commit. A separately authorized recovery can select PQ-only. Its next increment requires both remaining PQ roles and a fresh policy-bound permit. |
| Gate replacement | Both administrative signers approve the new key and current revision | Advance generation and install the replacement key. Racing enrollment attempts serialize. Old signed traffic fails incarnation checks. Pending old-generation reservations can be explicitly fenced. |

## Two durability boundaries

The target uses SQLite FULL synchronous mode, a single write transaction and uniqueness constraints on permit, reservation and committed request ID. The decision signs the target realm, target revision, policy digest, request binding, permit, reservation token, authorization epoch, gate generation, outcome and resulting counter value. A COMMITTED decision, its spent permit and its increment become durable together. A NOT_COMMITTED decision consumes the reservation's permit without incrementing.

The rollback witness stores a digest of the full canonical projection of all four target tables. A target operation first checks the live head. Before committing a changed state, it advances the witness by compare-and-swap over the old head and consecutive revision. A target crash between that advancement and the local commit leaves a detectable mismatch. The successor freezes. Expiry in this interval also fails closed. BLACKBOX does not automatically rewind or repair this gap. A rolled-back or inaccessible target cannot establish a terminal result from the witness digest alone.

The gate's death has no authority to cancel an already dispatched target transaction. If the target is alive, its transaction may finish after the gate disappears. When the target also dies before witness advancement, SQLite rolls back staged writes. A surviving, matching reservation can subsequently be fenced to establish NOT_COMMITTED. If no reservation ever became durable, this protocol reports UNRESOLVED for that attempted submission.

## Recovery evidence

The auditor supplies a fresh challenge to the target and rollback witness over separately authenticated connections. Both must attest to the same realm, revision, challenge and target-state digest under the pinned, distinct identities. The auditor verifies the full ledger projection, pinned target signatures, request and reservation bindings, spent permits, contiguous effect values and uniqueness of committed request IDs before classifying a decision. A conflicting authenticated target claim for the same execution freezes classification. Ordinary log replicas supply no commitment vote, even if they all agree or contain a copied authentic receipt. The original receipt is historical evidence while live continuity is unavailable.

The harness separately reads physical SQLite rows to check the observed counter, receipt identities and consumed permits at every cut. Those observations are diagnostic. They cannot promote a recovery verdict.

## Trust and limits

The target signing key, runtime, clock and original provisioning pins are trusted. The witness and its volume must survive outside the target/gate restore domain. Restoring all trust domains and keys together defeats that assumption. Independent administrators would need to retain and compare their own copies of the pins. The experiment uses localhost TCP, separate processes, namespace identities and service-specific mounts and credentials on one trusted host. The fixture administrator provisions them all. Network authentication uses the inherited nonce-bound HMAC protocol. Durable attestations use the pinned ML-DSA-65 implementation. The full-snapshot design inherits the bounded RPC frame and was exercised on small disposable ledgers.

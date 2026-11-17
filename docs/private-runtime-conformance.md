# Private runtime conformance contract

**Status `NOT TESTED`.** This is a proposed public interface with fictional fixtures. The authoritative Ground Truth runtime revision and the technical owner of its broker and protected effects are `UNKNOWN/BLOCKED`. Private read-only comparison may inform a candidate assessment. Runtime conformance requires the technical owner to confirm which revision and APIs govern the tested effects.

## Public interface

| Operation | Contract |
| --- | --- |
| `begin_case(case_id)` | Start a disposable isolated resource and return an opaque case handle and an independently readable baseline effect cursor. |
| `issue_grant(case, binding)` | Ask the trusted runtime broker to issue genuine, scoped authority. Bind the principal, delegate, tenant, origin, resource, action, canonical operation digest, validity interval, epoch, replay key and admission slot. The broker establishes trusted provenance and returns an opaque handle. The validity interval includes its start and excludes its expiry. |
| `submit(case, request, grant_handle)` | Submit a permitted test operation. The request carries an opaque attempt ID. Acknowledgements, claimed execution and returned errors are diagnostic data. |
| `observe_phase(case, attempt)` | Use approved test instrumentation to observe or schedule checkpoints before the final authority check and effect commit. Unavailable checkpoints are recorded as `NOT TESTED`. |
| `advance_authority(case, transition)` | Let the authorized test controller advance a logical clock, revoke a grant, advance an epoch or simulate unavailable trusted state. It uses genuine broker controls in the private environment. |
| `recover(case)` | Restart the disposable operation path and retain authoritative reservation and effect state so that a retry cannot create a second effect. |
| `read_effects(case, cursor)` | Independently read the authoritative protected resource or effect ledger. Return a bounded delta with attempt, tenant, canonical operation digest, admission slot and stable effect reference. Unavailable or inconsistent record state is `INCONCLUSIVE`. |
| `end_case(case)` | Close the test resource after evidence collection under the private environment's retention policy. |

The protected-effect boundary must recheck currentness using trusted runtime state at execution. A grant that previously verified can expire, be revoked or cease to bind the requested operation. Persist replay and single-slot state across crashes. The owner must be able to explain how the final authority decision, reservation and durable effect evidence interlock, including when a reply is lost. A retry under unknown effect state must produce no additional protected effect. An independent evaluator derives expected deltas from the authored inputs and uses the authoritative effect reader to judge the result.

## Synthetic contract fixtures

The [versioned public fixtures](../tests/fixtures/private_runtime_contract/v1.json) specify a shared fictional binding, request and clean initial effect state. Each case starts from those defaults, applies its listed steps in order and compares the final effect delta with the authored expectation. Apply listed overrides to a copy of the corresponding grant or request defaults. For `submit`, use the specified grant reference. Each effect must have a stable reference alongside the fixture's expected correlation fields. `pause_after` and `resume` describe an explicitly caused phase boundary. The fixture references, digests and namespaces are illustrative synthetic values and confer no authority.

A case with an unchanged current grant establishes that one legitimate effect is possible. Negative cases cover missing grant, binding changes, revocation after preparation, unavailable authority and claims of execution with no effect. An additional case covers retry after the effect committed but before its acknowledgement was delivered. Case expectations are inputs to the independent evaluator. The private adapter must generate genuine grants for those bindings, and its own callback results cannot satisfy the expected delta.

## Private evaluation plan

1. Have the authorized runtime owner identify the canonical branch, exact commit and tree, broker owner, effect-store owner and authorized private testing environment. Resolve any ownership or branch ambiguity with those custodians before mapping the public contract to runtime APIs.
2. Record that mapping and the genuine runtime revision in the private evaluation record. Keep private repository names, branch and runtime paths, hashes, API details and environment configuration in the private review.
3. Build and review the adapter in a separately governed private repository. Use a disposable resource, no production accounts, approved isolation, scoped credentials and an independent effect observer with read-only access.
4. Run positive and negative cases at the pinned revision. Exercise any available final-check, replay and crash checkpoints with explicit fault placement. Record incomplete schedules and unavailable observations with their evidence statuses.
5. Have a reviewer independent of the adapter confirm the observed effect records, failure controls, and limits. Consider releasing only a separately approved summary with a public status, declared scope and limitations.

Public fixture validation carries no genuine runtime result. Keep proprietary source, credentials, configuration and evidence with their authorized custodians.

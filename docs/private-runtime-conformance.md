# Private runtime conformance contract

**Status `NOT TESTED`.** This is a proposed public interface with fictional fixtures. The authoritative Ground Truth runtime revision and the technical owner of its broker and protected effects are `UNKNOWN/BLOCKED`. Private read-only comparison may inform a candidate assessment. Runtime conformance requires the technical owner to confirm which revision and APIs govern the tested effects.

## Public interface

| Operation | Contract |
| --- | --- |
| `begin_case(case_id)` | Start a disposable isolated resource and return opaque case and resource handles and an independently readable, resource-scoped baseline effect cursor. |
| `issue_grant(case, binding, operation)` | Ask the trusted runtime broker to issue genuine, scoped authority. Bind the principal, delegate, tenant, origin, typed operation's resource, action and canonical digest, validity interval, epoch, replay key and admission slot. The broker establishes trusted provenance and returns an opaque handle. The validity interval includes its start and excludes its expiry. |
| `submit(case, request, grant_handle)` | Submit a typed disposable operation and an opaque attempt ID. The gate binds the actual operation validated for execution. Acknowledgements, claimed execution, digest hints and returned errors are diagnostic data. |
| `observe_phase(case, attempt)` | Use approved test instrumentation to observe or schedule checkpoints before the final authority check and effect commit. Unavailable checkpoints are recorded as `NOT TESTED`. |
| `advance_authority(case, transition)` | Let the authorized test controller advance a logical clock, revoke a grant, advance an epoch or simulate unavailable trusted state. It uses genuine broker controls in the private environment. |
| `recover(case)` | Restart the disposable operation path and retain authoritative reservation and effect state so that a retry cannot create a second effect. |
| `settle_case(case, resource, budget)` | Observe trusted completion or drain of the submitted work and any effect-capable deferred work for this resource within a fixed budget. Return a trusted completion observation and a scoped effect high-water cursor or equivalent stable read boundary. |
| `read_effects(case, resource, baseline, completion)` | Independently read the bounded authoritative delta within the disposable resource. Include all scoped effects and report their stable references, attempt correlation, tenant, applied typed operation, canonical operation digest and admission slot. Unavailable or inconsistent record state is `INCONCLUSIVE`. |
| `end_case(case)` | Close the test resource after evidence collection under the private environment's retention policy. |

The protected-effect boundary must recheck currentness using trusted runtime state at execution. A grant that previously verified can expire, be revoked or cease to bind the requested operation. Persist replay and single-slot state across crashes. The owner must be able to explain how the final authority decision, reservation and durable effect evidence interlock, including when a reply is lost. A retry under unknown effect state must produce no additional protected effect.

Before judging a final delta, independently confirm that submitted work can no longer produce effects on the disposable resource. Include queued retries, pending commits and deferred work in the completion observation. Acknowledgements, elapsed time and an empty preliminary read are insufficient. If the fixed budget expires or trusted completion or the stable scoped read boundary cannot be observed, record `INCONCLUSIVE`. Read all records between the baseline and completion boundaries for that resource, including unexpected effects or effects without a recognized attempt ID.

## Synthetic contract fixtures

The [versioned public fixtures](../tests/fixtures/private_runtime_contract/v1.json) specify a shared fictional binding, request and clean initial effect state. Each case starts from those defaults and applies its listed steps in order. Apply listed overrides to a copy of the grant or request defaults. An `operation` override replaces the entire typed operation. For `submit`, use the specified grant reference. `pause_after` and `resume` describe an explicitly caused phase boundary.

The typed fixture operation has exactly `action`, `resource` and `body` fields. `action` is `write-marker`, `resource` is the fictional disposable ledger, and `body` contains only `marker` (`baseline` or `alternate`) and `count` (the integer `1`). The effect is one append of that marker to the disposable ledger. For this public profile, compute `sha256:` followed by the lowercase SHA-256 digest of the operation's UTF-8 JSON, with keys sorted in every object and no whitespace outside strings. The attempt ID and authority binding fields sit outside the operation digest. The private adapter maps the typed operation to the genuine broker and gate; an independent evaluator checks that the authoritative runtime binding and observed effect cover the same typed operation, even if the runtime uses another encoding. If that mapping cannot be observed, report `INCONCLUSIVE`.

The operation-binding case alters the marker and retains the original digest in an untrusted hint. The changed typed operation has its own independently computed digest and must produce no effect under the original grant. Fixture digest expectations are oracle inputs. The adapter cannot rely on them to grant authority or describe the effect. Compare the final scoped effect records, including their applied operation, with the authored expectation after trusted completion. In the completion-unobservable case the expected status is `INCONCLUSIVE`; it specifies no final effect delta.

A case with an unchanged current grant establishes that one legitimate effect is possible. The other cases cover missing grant, binding changes, revocation after preparation, unavailable authority, claims of execution, and retry after an effect committed before acknowledgement. The fixture references and namespaces are fictional. Only the genuine private broker may issue authority for an actual conformance run.

## Private evaluation plan

1. Have the authorized runtime owner identify the canonical branch, exact commit and tree, broker owner, effect-store owner and authorized private testing environment. Resolve any ownership or branch ambiguity with those custodians before mapping the public contract to runtime APIs.
2. Record that mapping and the genuine runtime revision in the private evaluation record. Keep private repository names, branch and runtime paths, hashes, API details and environment configuration in the private review.
3. Build and review the adapter in a separately governed private repository. Use a disposable resource, no production accounts, approved isolation, scoped credentials and an independent effect observer with read-only access.
4. Run positive and negative cases at the pinned revision. Exercise any available final-check, replay and crash checkpoints with explicit fault placement. Apply the fixture's observation bound and record incomplete schedules and unavailable observations with their evidence statuses.
5. Have a reviewer independent of the adapter confirm the observed effect records, failure controls, and limits. Consider releasing only a separately approved summary with a public status, declared scope and limitations.

Public fixture validation carries no genuine runtime result. Keep proprietary source, credentials, configuration and evidence with their authorized custodians.

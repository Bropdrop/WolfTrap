# WolfPrint agent identity v1

WolfPrint records a reproducible architecture fingerprint and, when supplied with independent fictional issuer and host records, assesses a tenant-scoped workload and its current operation. The public implementation reads selected local JSON files. Each decision is a review proposal for a separately governed host. There is no enforcement interface.

## Reproduce a selected assessment

Use a POSIX editable checkout, Git and Python 3.11 or newer. All four commands also work as `PYTHONPATH=src python -m wolftrap <command>`. Provide fresh output directories outside the inputs' directory. Pin the full Git commit using `--expected-head` when comparing saved evidence.

```bash
wolftrap fingerprint-agent --manifest examples/wolfprint/architecture.json \
  --output-dir /tmp/wp-architecture
wolftrap verify-agent-fingerprint --manifest examples/wolfprint/architecture.json \
  --evidence-dir /tmp/wp-architecture

# This independently published pin applies only to the checked-in fictional example.
registry_pin=5d7517fd9b15ad2ed73820b23d7907518ed7ac296f69b9697643b71c39668430
args=(--manifest examples/wolfprint/architecture.json --request examples/wolfprint/request.json
      --registry examples/wolfprint/fixture-registry.json --registry-sha256 "$registry_pin"
      --at 30 --chain examples/wolfprint/identity-chain.json)
wolftrap fingerprint-agent "${args[@]}" --output-dir /tmp/wp-session
wolftrap verify-agent-fingerprint "${args[@]}" --evidence-dir /tmp/wp-session

wolftrap challenge-wolfprint --output-dir /tmp/wp-qualification
wolftrap verify-wolfprint --evidence-dir /tmp/wp-qualification
```

The published example produces architecture `1eb831471e151d55469c3c49ed25cb699d2c6230fa093499b5935437032629ed`. A selected reference manifest requires both `--baseline FILE` and `--baseline-sha256 HEX`. When paired with issuer evidence, its canonical fingerprint must also agree with the recorded historical baseline. Registry files require a separate byte pin and an operator-selected logical time. Replay requires the original inputs, pins and time. Hashing a file received with its proposed pin establishes no independent trust. [Example files](../examples/wolfprint) · [Input schema](../src/wolftrap/schemas/wolfprint-v1.schema.json)

## Four identity layers

| Layer | What is computed | Observable scope |
| --- | --- | --- |
| Architecture | Versioned digest of the canonical architecture manifest | A deployment description that may be shared by different principals |
| Principal | Digest of a registered workload alias with its issuer, trust domain and tenant | Stable across sessions and authorized signing-key revisions inside that fictional domain |
| Instance | Digest of the issuer-bound statement, including principal, architecture, instance alias, nonce, issue/expiry times, audience, key revision, policy revision and ordered delegation | One fictional session. Concurrent sessions have independent bindings. |
| Behavior | Digest of the ordered verb, prepare/commit decisions and independently recorded effect count, scoped by tenant, domain and issuer | Opt-in correlation of a verified fictional trace. Arguments, resource names, payload values, raw prompts, absolute times and identifiers are omitted. |

The binary hash input is ASCII `wolftrap.wolfprint/v1`, a zero byte, the ASCII domain name, a zero byte, then the canonical JSON bytes. Primary domains are `architecture`, `principal`, `instance` and `behavior`. JSON objects use lexicographically sorted keys, UTF-8 and no insignificant whitespace. All variable strings in canonical values are restricted to ASCII. Digests use 64 lowercase hexadecimal characters. Integers have bounded range. Floats, negative zero, duplicate decoded keys, unknown fields and Unicode lookalikes are rejected. The order of delegation and observations matters. Capabilities and namespaced MCP pairs are unique sets, sorted before hashing.

The architecture includes framework and version, provider/family, a model-revision label with its evidence digest if available, build artifact, dependencies, SBOM, sandbox and permissions, delegated capabilities, and an optional protected configuration digest. Each MCP entry names a server and tool by digest and binds a schema digest. The same tool name can appear under two servers. Operator-selected Bloodhound digests can describe an input. Descriptions and annotations cannot populate issuer or authority records.

Use the literal `UNKNOWN` for unavailable components. An omitted optional protected-configuration digest canonicalizes to `UNKNOWN`. A witnessed empty tool list and an unknown inventory have distinct hashes. Architecture-only inspection reports known values as `DECLARED`. Matching a pinned issuer session upgrades only explicitly corroborated components to `ATTESTED` within the fictional model. A hosted-model label or model-card digest cannot establish the identity of inaccessible weights. Evidence contains coverage and digests. Raw manifest labels and issuer files stay with the operator.

## Fictional issuer and policy

The registry describes one trust domain, issuer, tenant, audience, bounded time window, authority epoch and policy revision. It records workloads and key lineage, exact session statements, consumed presentations, session revocations, scoped grants, review rules and optional per-phase host bindings. The independently selected registry is the trust input. Candidate manifests and requests are untrusted. Registry contradictions, ambiguous records and stale pins fail closed. Replay and expiry apply at a specific logical time within that snapshot.

A presentation must match a registered statement, including every delegation link. The key must cover issuance and observation. Old and new keys can overlap during an issuer-recorded rotation. The classifier reports known or changed architecture, a new instance of the same principal, verified fixture rotation, a shared build under a different principal, conflicting claims, invalid/expired evidence, or an inconclusive identity. A changed build with its own current grant can qualify. A copied build cannot carry a different principal's grant or restriction.

The simulator checks principal, tenant, architecture, exact operation digest, resource scope, delegation, epoch, policy revision, expiration and revocation independently of identity. It then applies current scoped review rules. Supported proposals are `ALLOW`, `REAUTHENTICATE`, `READ_ONLY`, `REQUIRE_HUMAN_APPROVAL`, `QUARANTINE` and `DENY`. An incomplete required component triggers human review when a grant exists. A missing current grant yields denial for a verified principal. `READ_ONLY` never makes a protected write eligible. Behavioral similarity is absent from policy inputs.

Each proposal carries a source-bound audit digest, logical assessment time, validity bound, authority epoch, policy revision, scoped subject/operation, reason and tenant review route. Expiring, withdrawing or revising the relevant fixture rule allows reassessment and appeal. An unverified presentation receives no attributed principal. Nothing is added to a shared restriction or tracking list. Future SPIFFE/SVID or equivalent adapters would need separately authorized issuer authentication, proof of possession, trust bundles, audience checks, freshness and secure host custody. Those properties are outside this fixture protocol.

Each issuer session includes a separately recorded capability set or `UNKNOWN`. A grant for an operation outside the attested set goes to human review. A disagreement between that set and the selected manifest makes the identity evidence inconclusive.

## Identity-qualified Cursorial profile

```bash
cie=(--chain examples/wolfprint/identity-chain.json --require-wolfprint
     --registry examples/wolfprint/fixture-registry.json --registry-sha256 "$registry_pin")
wolftrap challenge-cursorial "${cie[@]}" --output-dir /tmp/wp-cursorial
wolftrap verify-cursorial "${cie[@]}" --evidence-dir /tmp/wp-cursorial
```

The v2 envelope contains an unchanged v1 trace and one WolfPrint witness for each binding's preparation and commit. Each independently pinned host record binds the complete trace digest, chain, proposal, operation digest, binding, phase, logical time and statement digest. Both phases must join to the actual tenant, actor and delegation path reconstructed by Cursorial. The report exposes the issuer-bound principal, instance and architecture alongside the host grant, gate decision and separate ledger receipt. The optional behavioral result is only attached to a selected session when the trace and operation match.

A missing, duplicate, contradictory or substituted witness yields `INCONCLUSIVE`. A changed instance during a prepared operation requires new evidence. An independently observed write following revocation remains visible as a discrepancy. A witnessed denial with an empty ledger delta is distinguishable from an absent ledger. The six counterfactual Cursorial variations have no inherited identity attestations. Existing v1 captures retain their original semantics. Use `--require-wolfprint` to reject a downgrade to v1.

The initiating session must already be valid at the proposal's logical time. The authority epoch observed by the host must agree with the selected registry at both gates. A single v1 registry cannot establish continuity across an epoch transition.

## Evidence, bounds and known limits

Each WolfPrint bundle contains `wolfprint.json`, `wolfprint.md`, `wolfprint.sarif` and `wolfprint.manifest.json`. Replay regenerates every byte, including the manifest, from the selected source and original inputs. Unsigned SHA-256 detects changes relative to an independent pin. It cannot authenticate a publisher. The source checkout is required because WolfTrap checks local tracked package bytes against the pinned Git objects.

Each selected input is limited to 96 KiB, 12 levels of JSON depth and 4,096 nodes including keys. There are at most 24 MCP entries, 16 registered principals, eight keys per principal, 32 session statements, 64 grants, 32 restriction rules, 48 host bindings and five principals per delegation path. Descriptor-relative reads reject symlinks, hardlinked inputs or evidence members, traversal, nonregular files and unstable inputs. The scanner reads at most five selected files and never loads an executable or contacts a model or issuer.

| Exit | Selected assessment | Qualification |
| --- | --- | --- |
| 0 | Complete declared fingerprint, or matching scoped fictional identity and eligible operation | All expected outcomes and deliberate defects qualified |
| 1 | Reviewable drift, a contradicted presentation, or a scoped restriction proposal | An authored control or mutation check failed |
| 2 | Missing, malformed, stale, unsupported, or unverifiable evidence | A trusted source or verifiable bundle was unavailable |

A replayed finding retains its original exit code. Identity-qualified Cursorial reports use Cursorial's own exit contract.

The 256-case corpus contains 200 identity and policy cases across four tenants/delegation depths, 44 joined Cursorial cases and 12 hostile input controls. Eleven deliberately defective implementations exercise false authorization, missed identity conflicts, cross-principal restrictions and false positives on verified rotation and upgrades. The suite includes a benign deployment with missing issuer coverage that prompts review, a benign lookalike that remains eligible, and a copied session presentation indistinguishable from its legitimate holder before any independent replay witness. Redacted behavior intentionally collides for different payloads with the same projected actions. These observations supply no production error rates.

The dedicated workflow regenerates and replays three bundles twice, independently scores the saved classifications against authored expectations, and joins the example's issuer, host and ledger evidence from disk. Qualification runs in a verified loopback-only namespace. The independent research, MCP and Cursorial workflows qualify the same submitted Git head. Routine workflow setup and publication use GitHub's hosted infrastructure. [Qualification runner](../scripts/qualify-wolfprint.py) · [Workflow](../.github/workflows/wolfprint-qualification.yml)

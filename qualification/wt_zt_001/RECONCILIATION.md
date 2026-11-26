# WT-ZT-001 source reconciliation

Authenticated GitHub repository ID 1436465132, owner Bropdrop (246173990). GitHub PR metadata and independently fetched Git objects agreed on the eight heads. All eight were open drafts. The candidate has the same tracked engine tree as main. A detached worktree per historical head preserves each experimental contract. No historical code is linked into the new lab.

| Workstream | Exact commit / tree | Classification in the candidate | Selected unittest suites / discovered and passed |
|---|---|---|---|
| Public engine | ec6c3c1b2a50d702d202bd9b4e40842ba6e395f2 / cfcda2adf37f8862451601d96292f9cbf32e3a7f | IMPLEMENTED_AND_EXECUTED | main CLI help, identical engine bytes exercised by #28 |
| #13 Bloodhound | e1f80816ddc8a05faf2f784dd979a3d08b0b0c48 / c7705853642f717496c4aaa6624a061952ee52d8 | IMPLEMENTED_NOT_INTEGRATED | test_mcp, 30 |
| #14 Cursorial | 02dcbdd60a6249590dbf4b2e69d1c207657b537c / 44eece525840d8b000007e253ae6c01eae140220 | IMPLEMENTED_NOT_INTEGRATED | test_cursorial and test_cursorial_evidence, 30 |
| #17 WolfPrint | 0c537d128eb78554dc9fb938d650eb0c532bf48b / 9eef80970e12811e5212cb9dc4c3facb4d6779d0 | IMPLEMENTED_NOT_INTEGRATED | test_wolfprint and test_wolfprint_evidence, 42 |
| #22 WolfNet | 67d66a93c75e3be881953fd31d50ceab88a7815b / 330ec2e12f2cc3a94a140003deda65841f45f688 | IMPLEMENTED_NOT_INTEGRATED | test_wolfnet and test_wolfnet_evidence, 42 |
| #24 Product | 67811c4ed073572aea2da894b5368c4e45eb7002 / e3545cfdc8265ad81ec4dccc1aa21f52bfb44d8b | IMPLEMENTED_NOT_INTEGRATED | test_product, 19 |
| #25 Release trust | e652e62377fe9fc096cc3695d9ad49b753ef9941 / 6af529bffb4f8610e238f17a8670abce839c9401 | IMPLEMENTED_NOT_INTEGRATED | test_release_trust, 15 |
| #26 Governed release | 7d9d753247f878d731f7c92b0f95d9f619a725b2 / 9c637ffe201987dceb11a48ea64745d8c625ec0e | IMPLEMENTED_NOT_INTEGRATED | governance preflight and six governed suites, 55 |
| #28 wolftrap-security | d9a91cc1fae237600d67239ebdcf9200388229ca / fa864ac7f1a9a3362384a6bae20ebd2329740548 | IMPLEMENTED_AND_EXECUTED | plugin package and integration, 12 |
| GeoTrace v1 | unavailable | UNAVAILABLE_OR_BLOCKED | 0 executed. Prior-session 21/21 supplied by requester |
| GeoTrace v2 | unavailable | DESIGNED_OR_UNEXECUTED | 0 executed. Depends on recovered original |
| WolfAlibi / Ground Truth external authority contracts | unavailable for integration | UNAVAILABLE_OR_BLOCKED | No verified external receipt, issuer or recovery interface. Main's synthetic gt-vsa is a separate profile. |

All 245 selected tests ran on Linux x86-64, CPython 3.12.14, with zero failures, errors or skips. Scope excludes unselected suites and hosted installation matrices. S0 evidence files numbered by PR contain exact commands, exit statuses and verbose test names. The historical statements from the GitHub PR bodies are separately retained in S0/github.json. Statements about historical CI are attributable to their authors.

## Dependency graph

    main ─┬─ #13 ─┐
          ├─ #14 ─┴─ #16 (80af479d6eb6908de6dc69ea3e7bf533e44cb956) ─ #17 ─ #22
          ├─ #24 ─ #25 ─ #26
          └─ #28 ─ WT-ZT-001 offline experiments
    original GeoTrace archive + independent custody → v1 baseline → v2 → intended plugin

## Contracts and integration decisions

The immutable commit in each row selects the referenced source, docs, examples, schema and verifier. All engine checkouts declare Python >=3.11, no mandatory runtime dependency and optional PyYAML for build scanning. The practical POSIX, cryptographic and installer dependencies below narrow that declaration.

- #13 uses explicit tools/list baseline and candidate captures with scan-mcp and verify-mcp, plus challenge-mcp and verify-mcp-challenge. Select the expected baseline digest out of band. docs/mcp-bloodhound.md documents all argument and return-code profiles. POSIX descriptor-relative I/O and a Git checkout are required. Its replay and seeded defective classifiers cover metadata drift. Runtime consent and server behavior require separate evidence. Keep the comparator isolated pending plugin baseline selection.
- #14 accepts an authored corpus or a selected wolftrap.cursorial-chain/v1 input with challenge-cursorial --chain and verify-cursorial --chain. See docs/cursorial-intelligence.md and the chain and graph schemas. It correlates four role-owned channels and observes an in-memory SyntheticEffectLedger. This qualifies trace semantics inside its model. Durable transactions, signatures and restart fencing require different state and a fresh oracle. Reuse its historical tests in isolation.
- #17 fingerprints a manifest via fingerprint-agent and verify-agent-fingerprint. challenge-wolfprint and verify-wolfprint exercise the wolfprint-v1 schema. An operator-selected issuer registry, time and pin are needed for stronger classifications. See docs/wolfprint.md. authenticate explicitly reports cryptographically_authenticated=False for the pinned fixture. Keep this profile isolated until a separately qualified signature adapter exists.
- #22 adds verify-wolfnet-feed, evaluate-wolfnet, challenge-wolfnet and verify-wolfnet-challenge. See docs/wolfnet.md for required trust/checkpoint pins, selected feed, subject and evidence paths. Its closed wolfnet-v1 schema, signed feed and separate subscriber evidence qualify fictional evaluation. Its signing trust policy grants no authority to the plugin.
- #24 adds doctor, list-rules, quickscan --root/--demo --output-dir and verify-report with the original scope and --evidence-dir. See docs/offline-product.md. Verifier reconstructs the report from selected source and installed build bytes. Installation coverage is limited to the documented Ubuntu profiles. Require a separately reviewed package before reuse.
- #25 verifies detached CMS/in-toto evidence for exact wheel, SBOM and release manifest under an independently pinned subscriber policy. Standalone release/verifier verify and install take capsule, trust, sequence and purpose arguments in docs/release-verification.md. OpenSSL 3 and the separately maintained verifier are trust dependencies. The historical cross-check uses gpgsm. Evaluation fixtures confer no production signer identity.
- #26 adds governed preflight and custody policy, anti-rollback and reconciliation outside the installed CLI. See docs/governance-preflight.md, docs/governed-custody.md and release/replay_governed.py. Keep live governance, signing and release jobs outside scope. Historical authority and custody require an independent surviving policy and archive.
- #28 exercises scan-build, scan-agent, scan-effects, scan-prompts and scan-go-authority using --root and --output-dir. verify-effects, verify-prompts and verify-go-authority accept --evidence-dir. The package checks a closed manifest and fixture outcomes. See plugins/wolftrap-security/tests and each mode's docs. These static results remain advisory. Desktop installation requires separate testing.
- GeoTrace recovery checked reachable Git objects across fetched branches, Git history, workspace input folders, GitHub issue search, release assets and names of 159 Actions artifacts. No original archive surfaced. Drive search returned USER_NOT_LOGGED_IN. Absent authenticated source and independently rerunnable tests, both proposed commands remain unavailable. Required next input is the original ZIP and separately grounded provenance. GeoTrace stays in the first release gate.

The branch-only suites demonstrate that their original interfaces can be exercised locally. The only reusable release interfaces verified in the plugin are the five existing scans and their documented verification paths. These decisions permit an isolated experiment on durable, signed synthetic effects. They provide no approval to import a historical release chain.

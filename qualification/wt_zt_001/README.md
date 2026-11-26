# WT-ZT-001 pre-publication qualification

**BLOCKED — SECURITY OR EVIDENCE GAP.** The intended first release includes GeoTrace. Its original prototype, independent provenance and baseline tests are unavailable here. This branch provides a qualified research increment for review. The skills-only evaluation ZIP contains the existing scanner guidance. It cannot satisfy the amended release scope.

## Revisions and results

| Stage | Immutable implementation commit / Git tree | Observed result |
|---|---|---|
| S0 reconciliation checkpoint | 1190d92062cc4b04a7d9c1e06122c1047cb7226d / 43951642dbf1494d8eabffb76f69261e9a5dd05c | Eight draft heads cross-checked against authenticated PR metadata, selected suites 245 discovered/executed/passed, 0 failed/skipped. Each original source and tree is in RECONCILIATION.md |
| S1 first signed and durable profile | 268a64119e515c00009ae6f3f629495d68d96c68 / 39c83a6cee90f48f8e2d3cbf0ddb9a7d7a406e80 | 62/62 cases reproduced; original bundle retained. An earlier refactor produced two incorrect missing-witness reason codes, fixed before this cut |
| S2 taxonomy and guards | fab20bc00543b27be7606c455f2580d24eee544d / 9f002b87b5ca067828f0272249a9b64aa9e2b7c5 | 11 categories mapped. Pinned rerun of 76 scanner and 3 guard tests, all passed. Unsupported detectors identified in TAXONOMY.md |
| S3 initial mutations | 2dca16722ae9750d54628f8b161216f5318172b7 / e402d52892a1ad03fb67a6652aafb483566fa275 | 14 effect mutations, 13 detected and 1 survived. Fresh-state restoration matched for all. Refined signed-subject case preserved |
| Final S1/S3/S4 lab | 6fbf2be31b29983d1f6542740165c24ee59d38d9 / 6baec37053ec1a7748b75c07a19dcca08f46eeed | 64/64 reference cases, 11/11 evidence-boundary, 3/3 state and 3/3 guard tests passed. 19 mutation/case pairs, 17 detected, 2 survived. Clean local CLI installation/removal/reinstallation test 1/1 |
| Paired WolfTrap engine | d808b7e4d1070497ff5d2da8f5571247a547b035 / 081cf5e67108db481dadc65e8a9277d0429b7cc4 | Full engine suite 381 discovered/executed/passed plus 12/12 plugin tests. Engine distribution and module version agree on 0.5.3. Original module constant incorrectly reported 0.1.0 |
| Packaged plugin input | d9a91cc1fae237600d67239ebdcf9200388229ca / fa864ac7f1a9a3362384a6bae20ebd2329740548 | wolftrap-security 0.1.0, five reviewed files. Deterministic ZIP, 19,591 bytes, SHA-256 926927fa3e28223f519041c74fe2aec014383262677086f6bbb05e722aca891b |
| Isolated MCP experiment | af5b35f55926176e0ab928d53703ce1202eba554 / 5549000ac29fbcfbfcf624632930a14da030dcd8 | One stdio protocol test discovered/executed/passed; no adapter in the plugin |

Counts are scoped to the named runs. Some suites and cases were rerun across revisions. The last runs reported zero unittest failures, errors or skips. Historical hosted job links and statuses are recorded separately in S0/inventory.json. Existing scanner return codes and command names retain their original meanings.

## Reproduction

Use an independently acquired, reviewed checkout of Bropdrop/WolfTrap. Checkout the exact lab implementation above or use a detached worktree. Trust the commit pin through a channel independent of the evidence being reviewed. The experiment uses preinstalled CPython 3.12.14, PyJWT 2.13.0, cryptography 50.0.0, SQLite 3.53.1, Git and Linux libseccomp. No install step runs. The existing scan-build tests used PyYAML 6.0.3. The parent and all new evidence directories must be local, private and outside both source and any inspected repository. Reuse the verifier from the corresponding immutable revision when checking historical evidence.

```sh
pin=6fbf2be31b29983d1f6542740165c24ee59d38d9
lab=qualification/wt_zt_001
out=$(mktemp -d)
export PYTHONPATH="$PWD/src" PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 PYTHONHASHSEED=0 PIP_NO_INDEX=1
python3 -I "$lab/evidence.py" create --expected-commit "$pin" --evidence-dir "$out/cases"
python3 -I "$lab/evidence.py" verify --expected-commit "$pin" --evidence-dir "$out/cases"
python3 -I "$lab/offline.py" python3 "$lab/mutations.py" > "$out/effect-mutations.json"
python3 -I "$lab/offline.py" python3 "$lab/boundary_mutations.py" > "$out/file-mutations.json"
python3 -I "$lab/offline.py" python3 -m unittest discover -s "$lab" -p test_artifacts.py -v
python3 -I "$lab/offline.py" python3 -m unittest discover -s "$lab" -p test_state.py -v
python3 -I "$lab/offline.py" python3 -m unittest discover -s "$lab" -p test_guards.py -v
python3 -I "$lab/offline.py" python3 "$lab/package.py" create "$out/package"
python3 -I "$lab/offline.py" python3 "$lab/package.py" verify "$out/package"
python3 -m unittest discover -s "$lab" -p test_client.py -v
```

For the paired engine use a separate detached worktree at the engine commit, set PYTHONPATH to that checkout's src, and run both unittest discoveries under its offline.py launcher. Use `python3 -m unittest discover -s tests -v` and `python3 -m unittest discover -s plugins/wolftrap-security/tests -v`. The client-specific test uses a clean temporary home and follows the Codex child processes with strace, rejecting socket, connect and io_uring_setup. Local Unix socket pairs remain available for runtime signaling. The initial universal seccomp profile denied the client's internal signal pair during startup. No client success is attributed to that failed attempt.

## Evidence and provenance

The expected casebook, issuer fixture, host, recovery reader and reference observer are distinct sources. Only the host owns the effect transaction. Both role statements must bind the exact operation, and the reference checker uses its own fixed public-key pins and a read-only ledger observation. Signed freshness uses the fictional host clock. Changing path selection, revocation or the effect acknowledgement can change an outcome even with syntactically valid statements.

The verifier takes a separate full commit pin, checks ancestry to the verified candidate, materializes only enumerated source blobs, reruns the corpus from clean state, and compares every member of the closed JSON/Markdown bundle. Existing scanners additionally produce SARIF under their existing contracts. Byte-for-byte replay includes tool versions and platform metadata; another environment may yield INCONCLUSIVE. Assumptions include a trusted Git object database, independent selection of the verifier, the specified interpreter/dependencies and private local storage. Tamper resistance against a privileged same-UID adversary, trusted time and independent production custody are unverified.

| External evidence for the final lab cut | Bytes | SHA-256 |
|---|---:|---|
| reviewed/cases/assessment.json | 267170 | f11c3c9ba89ceae0a763447345769e2ec807fa18fbd9908c122c339867355c95 |
| reviewed/cases/manifest.json | 527 | 5dea666c199dc31d22146f58b49d5df0aae7ef8f5721b12d03c0fd42ccc0bc3f |
| reviewed/effect-mutations.log (JSON) | 204458 | 5b577691b0c3d30aeb8450eb56177c597e9a22fb427c9932caaf61fd5a72655c |
| reviewed/file-mutations.log (JSON) | 1270 | 884bcc2e4746fa9ad50bb229c0e29dd06129846c7ec86898d451d19a3794115a |
| reviewed/package/package-receipt.json | 1654 | 5e6c0e02bf666a593179b4b6a11dea0c1741490a785259c2076e271c1f7188b7 |

Hashes bind these byte sequences to the selected evidence. The JWT checks authenticate particular synthetic statements under the pinned keys. The candidate ZIP and assessment have no independently trusted production signature. S0 preserves revision-specific historical evidence separately; the selected #25 verifier suite exercised its own synthetic provenance profile.

## Release assessment

**Intended contents.** Five existing public scanner entry points, their supported evidence-review paths, and an independently selectable read-only GeoTrace capability. The lab, mutation harness, historical draft modules and MCP prototype are review material outside the skills ZIP. The ZIP is a baseline package for testing. No GeoTrace feature appears in its manifest or skills.

**Passed for a bounded profile.** All five scanner modes ran against local fixtures. Linux source/output path isolation and symlink checks, tamper rejection, deterministic ZIP assembly, local marketplace installation, cache inventory and removal/reinstallation passed. All five installed file hashes matched the receipt. The client run used Codex CLI 0.172.0-alpha.2 on Debian 13 x86-64. No external socket creation or connection attempt was observed in the traced installation. The reviewed package has two skills, two guides and plugin.json, with no executable or lifecycle hook. The receipt identifies the separate engine commit, source tree, runtime requirement and optional dependencies. Installed package metadata alone cannot attest to which engine a future client invokes.

**Critical gaps.** GeoTrace v1 source and custody, eligibility of any combined MCP submission, and the intended end-to-end GeoTrace plugin flow are BLOCKED. An independently governed production signer and independent release review are outstanding. A malicious OS, shared key custodian or rollback of the authoritative host and witness storage is outside the synthetic profile. Ambiguous/contradictory external outcomes require HOLD. Executed corpus cases do not establish resistance to every language-model decision or attack variant.

**Compatibility and review.** Windows and macOS, ChatGPT desktop installation/activation, cloud-only rejection without a local executor, arbitrary client version negotiation and a live credential-access audit are NOT_TESTED. The metadata requires a local executor. Upgrade between distinct published versions, production settlement and cross-machine replication are NOT_TESTED. The receipt and external inventory cover the shipped ZIP and selected software prerequisites; transitive OS/toolchain provenance remains unverified. Reviewers should check the exact paired revisions, declared distribution scope and platform requirements before considering a new release decision.

**Rollback.** A local clean removal and reinstallation of the exact pinned evaluation ZIP reproduced all member bytes. For any future upgrade retain the previous independently approved package, engine commit, receipt, policy generation and evidence outside the installation. Remove the changed client package, restore that pair in a clean local profile and rerun receipt and fixture verification. Revoked authority and superseded witness state must survive application rollback. No prior publicly qualified GeoTrace-enabled version exists in the recovered evidence.

## Mandatory GeoTrace gate

Neither scan-geotrace nor verify-geotrace is a current public command. The artifact search also covered fetched PR-head objects and repository issue comments. There was no independently obtainable copy of WolfTrap-API-GeoTrace-v1.zip. The current environment executed zero GeoTrace tests. Test discovery, source commit, implementation tree, dependencies and operating modes are unknown. The reported historical 21/21 is retained as a prior-session assertion.

| Required qualification after recovery | Controls and independent observation | Current status |
|---|---|---|
| v1 compatibility | Independently inventory original source and dependencies; reproduce normalization and all 249 country entries against a separately sourced reference. Re-run the exact 21-test inventory, configurable policy and disconnected operation | BLOCKED |
| Separate geography evidence | Distinguish authenticated controlling principal, workload, execution region, network egress, infrastructure provider, destination/intermediaries, jurisdiction policy and action authorization. Preserve unknown and contradictory evidence | BLOCKED |
| Routing and freshness | Positive explicit local evidence; misleading IP, VPN exit substitution, cloud egress mismatch, multi-hop route, conflicting providers, expired/invalid evidence, stale checkpoint and missing jurisdiction. Independent oracle retains uncertainty and observes zero unauthorized effects | NOT_TESTED |
| Substitution and trust | Provider/agent substitution, cross-border scope mismatch, changed destination after approval, conflicting identity/location/policy witnesses and origin inferred from IP alone. A signature authenticates only its statement | NOT_TESTED |
| Mutation and integration | Alter one binding, freshness or jurisdiction check at a time; compare actual fictional effect and restore. Gate strict local schemas, explicit selection, outside-tree outputs, independent verification and discoverability on passing results | UNEXECUTED |

The original ZIP plus independently grounded custody is the next prerequisite. Release scope can change only by a separate human decision. ARCHITECTURE.md records the distribution decision, TAXONOMY.md the eleven audit categories and ADVERSARIAL.md the complete scenario and mutation accounting.

# WT-PKG-005 Linux evaluation

The assembly is a private Linux evaluation of the WolfTrap adapter, the two WolfTrap Security skills and the separately invoked slot verifier. Its broker, worker, policy, engine, tool schemas and permissions come from PR #34. The packaged skills use the existing separate skills distribution. Users run the MCP evaluation through the owner-held supervisor and a private stdio session.

## Source and package pins

| Item | Pin |
| --- | --- |
| GitHub repository | `Bropdrop/WolfTrap`, repository ID `1436465132` |
| Candidate source commit | `4d39dbee2aca4a680cd1a916bc4beb0f54cccb30` |
| Candidate source tree | `a04d65fd3535c74ea8991e557b14d1e6899caa8e` |
| Evaluation ZIP, 205,923 bytes | `f4d6188d47bb6c4fdcde3c76b54cb5ac0430c927d3d43b82b15b79c427c535dd` |
| Nested 0.3.0 adapter ZIP, 156,318 bytes | `ee05c9f82ebc718973fa8b937c776be093c77c15bb1b0209bf004177e3d489f0` |
| Prior adapter source commit and tree | `7522d75c0c258f79a2f35b46a9afb72083a19c67`, `31bdb25120bba8881c5b9adee31576446153d348` |
| Prior adapter ZIP, 144,357 bytes | `b74eaaeb1af8860582e5c5f9e12c6301fbf843e05de285d10166db287c61428d` |
| External verifier code at PR #34 | `f0928a20f6d208092d6a24e740fc459200cac6085afa335d90a46766c1eb9374` |
| External verifier reference | `3421ee83fb916dba6177bf21709d2ff9a24839f9d2a8b4e77eba8a708b980877` |

`wt_pkg_005.py` makes a private local clone, materializes the pinned commits in detached worktrees and invokes each revision's original adapter builder. It reconstructs the outer ZIP from the candidate adapter and the reviewed member paths in Git. Stored ZIP members, sorted names, fixed timestamps and Unix file modes preserve the WT-MCP-004 bytes, including its fixed receipt. Live verdicts are reported separately in `result.json`. Transported archives are compared with the reconstruction before the driver writes installation files. Both installations have closed file and directory inventories.

## Independent Chromebook procedure

Run as the ordinary user in the device's Crostini terminal. Use a local Git checkout containing the pinned PR #34 commit and its PR #33 parent. The previously tested target was Debian 13 x86-64 with CPython 3.13.5 and Bubblewrap 0.11.0. The protected run requires the pinned launcher library layout, working user, mount and network namespaces, and libseccomp. The script uses local Git and Python's standard library for the model-free fixture. Keep the device's existing security configuration.

Save the reviewed standalone driver at a local path and run the following from the Linux filesystem. Choose a private output directory outside the checkout with enough retention for independent inspection.

```bash
(
set -euo pipefail
umask 077
driver=/absolute/path/to/wt_pkg_005.py
source=/absolute/path/to/local/WolfTrap
out=$(mktemp -d)
python3 -EBS "$driver" build --source "$source" --output "$out/build"
package="$out/build/wolftrap-wt-pkg-005-linux-evaluation.zip"
printf '%s  %s\n' f4d6188d47bb6c4fdcde3c76b54cb5ac0430c927d3d43b82b15b79c427c535dd "$package" |
  sha256sum --check -
package_status=0
python3 -EBS "$driver" qualify --source "$source" --zip "$package" --output "$out/package" ||
  package_status=$?
rollback_status=0
python3 -EBS "$driver" stateful-rollback --source "$source" --zip "$package" --output "$out/rollback" ||
  rollback_status=$?
printf 'Package exit %s, stateful rollback exit %s\n' "$package_status" "$rollback_status"
printf 'Private test output: %s\n' "$out"
)
```

Use the reviewed digest from an independent channel for `sha256sum`. If you received a ZIP privately, set `package` to that file and use the same digest and `--zip` argument. Stop if the digest check fails. Every qualification invocation reconstructs the package and checks the supplied bytes again. Exit 0 means the specific phase passed and exit 2 means it blocked. Use `portable` in place of `qualify` to check integrity and file installation on a different build host.

| Phase | Required evidence |
| --- | --- |
| `qualify` | Exact assembly and both install inventories; new namespaces; MCP initialization and all three closed tool schemas; denied unrelated task with both slots unchanged; one authorized commit; idempotent retry; evidence replay; separate read-only verifier and exact journal check; candidate removal; retained prior installation reverified; evidence auditable after removal. |
| `stateful-rollback` | A separate synthetic state is committed using PR #34. The driver selects the measured PR #33 installation against that same live state and requires discovery and an idempotent retry. It then revokes the live generation, requires denial under PR #33, and compares journal and artifact observations before and after. It independently audits the retained commitment. A prior-runtime discovery failure blocks this phase. |

This rollback procedure selects a verified retained installation and measures it with the matching reviewed supervisor. The file-level test selects and verifies the prior tree after removing the candidate. PR #33 used nested Bubblewrap and had a historical UID-map failure on this device, so file-level rollback cannot establish that the prior process can be reactivated. If prior activation fails, retain the current committed state and its distinct pins. Continue using a separately reviewed compatible profile with fresh approvals when appropriate. The stateful procedure keeps the live owner, source, generation and SQLite objects in place. Whole-store restoration, including restoration of spent approval state, stays blocked.

The driver tears down its temporary clones and installations on exit. It keeps the assembly, `result.json`, and the private evidence that was produced. It leaves the input checkout and any existing WolfTrap installation alone. Runs use separate fictional state. Keep `private/` on the device, including the live SQLite files, artifact bytes stored in them, protocol logs, audit pins and runtime measurement. To re-audit before relocating the state, run the PR #34 `audit.py` and its pinned `reference.json` from a separate reviewed checkout:

```bash
/usr/bin/python3.13 -IBS "$reviewed/qualification/wt_mcp_002/audit.py" \
  --state "$out/package/private/state" --handle alpha \
  --owner-pin "$owner_sha_from_private_audit_pins" \
  --reference-pin 3421ee83fb916dba6177bf21709d2ff9a24839f9d2a8b4e77eba8a708b980877
```

Share only `result.json` and an independently reviewed compatibility note. The result records phase, immutable pins, driver digest, check outcomes and a bounded failure classification. Review it before sharing. Owner pins, raw responses, host details and databases stay private. Clean up retained evidence only after review and under the operator's evidence-retention policy.

## Hosted qualification

The workflow targets a pull request stacked on `feat/wt-mcp-003-sibling-sandbox` and checks out the exact head. The portable job verifies the deterministic archive, rejects a substitution and checks clean file installation and rollback. The OS job first requires an unprivileged, egress-isolated parent and then uses the protected launcher. It also runs the pinned worker and broker confinement canaries. A missing runtime layout, an unavailable isolation primitive or a failing confinement check stops that job with a nonzero status. Its summary reports the blocking stage. The jobs publish sanitized summaries and retain the package and raw evidence only in runner-local temporary storage.

A hosted runner's namespace result applies to that runner. A compatible device can establish the scoped exact-package runtime result with its own evidence. The hosted lane remains separately accounted for.

## Review record and current verdict

| Gate | Status |
| --- | --- |
| Source architecture and historical evidence | Frozen at PR #34. PRs #28–34 and the previous qualification records are retained. |
| Portable assembly and installed files | **GO for independent device evaluation.** The Cloud build matched WT-MCP-004 byte for byte. Repeat builds, a substituted transport rejection, both clean extracted inventories, candidate removal and prior file verification passed. |
| Protected runtime on Codex Cloud | **BLOCK.** The user UID map was read-only before a broker could launch. The hosted-style outer isolation check also blocked. |
| Historical Crostini source result | The saved records reconcile with 49 request cases, 11 recovery cases and nine detected/restored mutations at PR #34. The operator additionally reported two successful audits, six tamper rejections and restoration of valid evidence. The original DBs, raw GeoTrace bundles, kernel traces and six machine-readable tamper records were absent from the handoff and remain **NOT REPLAYED**. |
| Exact-package Crostini run | **BLOCK / NOT TESTED.** Requires the independent device run and review. |
| Stateful rollback | **BLOCK / NOT TESTED.** The prior runtime and in-place journal, artifact and revocation checks need separate execution on a compatible host. |
| Intended clients and distribution | SDK and Codex app-server claims keep their historical test scope. Exact-package client registration, desktop installation, macOS and Windows compatibility, OpenAI local-MCP eligibility, publisher identity and signed provenance remain open. Real model-selected behavior is **NOT TESTED**. |
| Stacked draft and production | **BLOCK.** A new stacked draft requires review of qualification of the implemented work. Production and submission require separate decisions and evidence. |

The local rebuilds used CPython 3.12.14 and 3.13.5. Independent archive inspection checked 10 outer payloads and 24 adapter payloads against their receipts and pinned Git blobs. The original source's portable suites passed 21 GeoTrace v1, 22 GeoTrace v2 and 13 plugin tests. The workflow shell steps were exercised on Codex Cloud. A GitHub-hosted run remains pending.

The two historical WT-ZT-001 results remain **SURVIVED**. For issuer subject / substitute-principal, a second binding check denied both trials with zero rows. For the initial closed-set check / extra member, the final inventory check rejected the added file. The results apply to those specific trials. [WT-ZT-001 mutation accounting](../wt_zt_001/ADVERSARIAL.md)

The existing unexecuted gates retain their scope, including full host compromise, whole-store rollback, real-storage power-loss durability, kernel security, individual seccomp rules, clock rollback, SQLite storage failure and per-member ZIP mutation coverage in the historical suite. The new byte comparison qualifies the fixed distribution and the tested package substitution. The original trial results and compatibility limits remain binding to their revisions and runtimes. [WT-MCP-002 qualification](../wt_mcp_002/qualify_release.py) · [WT-MCP-003 device profile](../wt_mcp_003/README.md)

### Human review before advancing

- [ ] Compare the live PR stack and review the tooling diff against PR #34. Confirm the measured broker, workers, engine, tool schemas and owner policy are the pinned source.
- [ ] Rebuild the ZIP independently and compare the pinned digest, reviewed member inventory and nested adapter bytes. Verify the reviewer tool and reference from a separate copy of the selected source.
- [ ] Witness the Chromebook run with the reviewed driver. Confirm the package, application, runtime and driver identities, all protected checks, both rollback results and raw evidence custody. Verify the committed SQLite slot and GeoTrace evidence independently. Record any platform-specific failure at the observed layer.
- [ ] Review the compatible runtime and client support matrix. Confirm unprivileged user, mount and network namespace enforcement, inherited filter enforcement and the limits of the canaries on each claimed platform.
- [ ] Preserve the historical gaps, mutation limits and outstanding platform, client and model-behavior gates. Sanitize only the reviewed metadata intended for a public PR.

### Production provenance requirements

Require a verified publisher identity and documented key custody, a signed release manifest with exact source, tooling and package digests, and independently verifiable build provenance. Record trusted build inputs and runtime library pins, dependency inventory, licenses, compatibility evidence, signatures and verification instructions. Require independent human security sign-off, a defined rollback and revocation policy, evidence retention and a distribution eligibility determination. Treat the Linux evaluation ZIP and its matching digest as inputs to that review. Production and OpenAI plugin submission remain blocked.

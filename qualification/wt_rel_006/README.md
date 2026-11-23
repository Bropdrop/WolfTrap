# WT-REL-006 release trust review

Reviewed draft [PR #35](https://github.com/Bropdrop/WolfTrap/pull/35) at `8a33bc6d2230bff0a05aff77648a8362ed8e84eb`, tree `c7178601b7eb8c467bba3168d4b099304d23c2a7`. The 205,923-byte Linux evaluation ZIP is frozen at SHA-256 `f4d6188d47bb6c4fdcde3c76b54cb5ac0430c927d3d43b82b15b79c427c535dd`, source `4d39dbee2aca4a680cd1a916bc4beb0f54cccb30`, tree `a04d65fd3535c74ea8991e557b14d1e6899caa8e`. Driver SHA-256 is `ea6f28b4727480369c5fd20322c686ddbd8ff7ca5d9ca14a7b9bd9595fa03d00`. The trust material is external to the ZIP.

## Independent workflow and evidence audit

- The diff against PR #34 contains only the workflow, driver and evaluation README. The workflow is scoped to the PR #34 stack base, uses a commit-pinned checkout with read-only contents permission and disabled credential persistence, and separates portable checks from mandatory containment. PR head jobs execute candidate code. Keep those jobs on disposable hosted runners. Promote only reviewed immutable inputs to trusted CI through a separately controlled workflow. The README's historical “hosted run remains pending” statement is superseded by run 45092478659. The portable job succeeded. Protected runtime stopped before qualification at `HOSTED_UID_MAP_PERMISSION_DENIED`, exit 2. [Hosted run](https://github.com/Bropdrop/WolfTrap/actions/runs/45092478659)
- The driver uses fresh private directories, reconstructs pinned bytes before installation, compares transported bytes, and checks installed inventories. It checks distinct user, mount and network namespaces and loopback-only networking before running the reviewed launcher. Hosted mode additionally requires the parent network isolation and worker and broker confinement canaries. Those canaries never ran in the blocked hosted job. The output is a procedural test record. It has no signed binding to a builder, host or request transcript.
- The uploaded ZIP contains three summaries. All pin and check maps match the expected portable, qualify and stateful phases. The two runtime summaries omit `mcp_outcomes`, which the reviewed driver always assigns after checking `DENIED, AVAILABLE, COMMITTED, ALREADY_COMMITTED, VERIFIED` for a successful runtime. The portable summary correctly lacks this field. The runtime exports cannot be byte-identical full driver results. The reason for omission is unverified. Preserve the supplied files as received and leave the omitted field absent. Require the original results and a private comparison to the retained responses for independent runtime sign-off. The exports support operator-reported checks, including the prior-state retry and revocation, and supply no independent execution observation.
- WT-ZT-001 issuer subject / substitute-principal and initial closed-set check / extra member stay **SURVIVED**. A second binding check denied the first case with zero rows, and a final inventory check rejected the second. The historical 49 request cases, 11 recovery cases and nine restored mutations retain their original scope. Six tamper rejections, two audits and restoration were operator-reported. Their original SQLite data, raw artifact and trace data, and six machine-readable tamper cases were absent from the historical handoff. Whole-store rollback, full host compromise, power loss, clock rollback, SQLite storage failure, kernel security, individual seccomp rule coverage, and historical per-member ZIP mutation coverage remain outside demonstrated scope. [Mutation record](../wt_zt_001/ADVERSARIAL.md)

## Unsigned review materials and production verification

From the trust review worktree, run with two independently selected Python installations. Use a fresh private destination outside the checkout.

```bash
python3 -EBS qualification/wt_rel_006/prepare_review.py "$out" "$python_a" "$python_b"
```

The procedure rebuilds twice with the exact reviewed driver and checks byte equality, lengths, SHA-256, receipt inventories and pinned Git blobs. It emits an in-toto Statement with an unsigned local rebuild predicate, a CycloneDX 1.6 file inventory covering both ZIP layers, and a draft manifest binding the ZIP, statement and SBOM digests. Two invocations with the same toolchain produced identical metadata, and the SBOM passed the official CycloneDX 1.6 schema. Local runs used Git 2.56.1 and Python 3.12.14 and 3.13.5. These runs share an administrative trust domain. The build statement makes no SLSA level claim. [CycloneDX schema](https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json) · [in-toto statement](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)

For production, require a second builder under independent custody to rebuild and compare the exact ZIP, then compare the two builder attestations. A trusted build service should emit signed provenance identifying its authorized builder, Git materials, exact workflow, builder image/toolchain digests, invocation policy and subject digest. Validate it against the release policy, including builder authorization and exact source refs. Add a runtime inventory separately for each supported environment. List Debian package names, versions, architecture, file digests, licenses and supplier for CPython and its standard library, Bubblewrap, the dynamic loader, SQLite, libseccomp and all library paths in the pinned `reference_pin.py`. Include the kernel build, image digest, measured launcher configuration, effective policy and support/update owner. Keep raw host paths private. The CycloneDX file inventory covers packaged bytes. Runtime provisioning and license/security review require their own evidence. [SLSA provenance](https://slsa.dev/spec/v1.1/provenance)

After approval, require an independent authority to establish the publisher identity, its permitted artifact scope, and the fingerprint of its approved key via a separate channel. Check key status and revocation against that authority and record approved custody and rotation policy. Have the authorized publisher issue a new approved manifest version with the exact release decision, including artifact media type, byte length, review decision identifiers, required provenance and SBOM digests, and the trusted signer and signing profile references. Sign the canonical bytes under approved custody. One verification profile is an Ed25519 detached signature over the exact UTF-8 manifest bytes:

```bash
openssl pkey -pubin -in "$trusted_pub" -outform DER | sha256sum
openssl pkeyutl -verify -rawin -pubin -inkey "$trusted_pub" \
  -in release-manifest.json -sigfile release-manifest.sig
```

Run signature verification only after comparing the DER fingerprint with the independently approved value. Require a trusted clock and current authorization and reject expired, revoked or ambiguous authority. After verification, parse the expected manifest schema with duplicate-key rejection, require the exact expected subject names, verify sizes/digests of regular files without following symlinks, and compare package/source/tooling pins and evidence approvals with independently selected policy. A valid signature under an unverified key proves only key control. The lab tested valid and modified messages with a disposable synthetic key. The draft release manifest and actual package have no production signature.

## Private independent review

1. The device custodian and a separate reviewer establish consent and custody. Keep the original `private/` data on the Chromebook, under a private directory and a quiescent fixture. Record a local hash inventory of each original result, transcript log, audit-pins file, owner/generation data and SQLite slot before and after review. Compare the exact exported summaries with the originals and document every redaction. Preserve raw hashes, paths and detailed custody records locally.
2. On the original filesystem, use a separately obtained pinned copy of the auditor and reference. Verify their SHA-256 pins `f0928a20f6d208092d6a24e740fc459200cac6085afa335d90a46766c1eb9374` and `3421ee83fb916dba6177bf21709d2ff9a24839f9d2a8b4e77eba8a708b980877`. For both the package and stateful runs, invoke the command below for alpha and beta using the phase-specific owner pin recorded during the run. Keep stdout and pins private.

   ```bash
   /usr/bin/python3.13 -IBS "$trusted_auditor" --state "$phase_state" \
     --handle "$slot_handle" --owner-pin "$recorded_owner_pin" \
     --reference-pin 3421ee83fb916dba6177bf21709d2ff9a24839f9d2a8b4e77eba8a708b980877
   ```

   Expect alpha `VERIFIED_COMMIT` with the four pinned artifact digests and beta `NO_COMMIT` with empty phases and artifacts. Check ordered alpha transitions `DISPATCH, LISTED, DISPATCH, COMMITTED, DISPATCH, VERIFIED`; require one commit. The verifier opens SQLite read-only and checks source filesystem identity. A copy on a different filesystem cannot establish the original identity check; record that limitation.
3. Parse retained replies as data, with bounded reads and duplicate-key rejection. Check protocol version, reply IDs and correlation to the driver's reviewed case order, catalog schemas and statuses. Check both prior-session logs for `ALREADY_COMMITTED` followed by `DENIED` in the revoked session, and compare recorded pre/post effects and generation where available. The driver logs responses. If independent request-side capture, before/after snapshots or kernel evidence is unavailable, require a witnessed repeat with fresh, separate synthetic state to substantiate those claims. Never restore spent approvals or exercise fresh scans under PR #33 as part of this protocol.
4. Issue a reviewer-controlled record containing only immutable public pins, platform class, per-check decisions and gaps, reviewer identity/role and sign-off scope. Quarantine mismatches and mark missing checks unexecuted. Keep raw DBs, captures, owner pins, transcripts and actual host metadata off Git and ordinary CI. A separate authorized reviewer signs only after executing and documenting the protocol.

## Linux support and CI

| Environment | Scope |
| --- | --- |
| Debian 13 Crostini x86-64, reported kernel `6.6.119-09251-gf81e51484dec`, CPython 3.13.5, Bubblewrap 0.11.0, libseccomp 2.6.0 | Operator-reported PASS for the pinned protected fixture and scoped stateful reuse. Exact runtime identities and client compatibility await review. |
| GitHub-hosted Ubuntu 24.04 | Portable PASS. Protected job blocked at UID mapping. |
| Codex Cloud Debian 13 x86-64 | Portable assembly PASS. Protected preflight blocked at read-only UID mapping. |
| Dedicated x86-64 Debian 13 VM on an organization-controlled hypervisor | Candidate trusted CI environment, enrollment and validation pending. Other kernels, architectures and Linux clients remain unqualified. |

Use an ephemeral self-hosted runner in a restricted private runner group, with a pinned Debian 13 guest image on dedicated, organization-controlled infrastructure. Stage the reviewed SHA and dependencies through a trusted controller. Run as an ordinary uid with the required namespace, library and seccomp profile inside a fresh offline guest, or enforce guest egress externally and run the reviewed loopback-only parent wrapper. Keep runner control traffic outside the test namespace. Require namespace inode separation, only loopback in the parent and worker isolation probe, broker and worker confinement canaries, a host-level deny-egress control and the exact-package suite. Archive only sanitized outcomes and separately controlled builder attestations. A failure remains a blocked gate. Prevent direct execution of PR-head workflows on this runner, keep credentials and signing keys out of the guest, and destroy the VM after each job. A compatible, trusted host has yet to be provisioned and measured. [GitHub ephemeral runners](https://docs.github.com/en/actions/hosting-your-own-runners/autoscaling-with-self-hosted-runners) · [GitHub security hardening](https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions)

## Distribution eligibility

The portable skills packaging has no bundled MCP server and calls a local CLI. Its pinned manifest sets `requires_local_executor: true`. OpenAI classifies that as Desktop only and routes it through standard submission, with organization/project permissions and verified developer or business identity. Clean installation and the applicable portal validation are still required. The separate frozen Linux evaluation ZIP is an engineering artifact for the protected stdio MCP adapter. A future distributable local MCP plugin needs approved-partner status, an allowlisted submitting organization, a clean desktop install, and conforming plugin layout with the server, dependencies and stdio config in the initial ZIP. The portal's Skills only selection is the documented upload route for that approved local MCP case. Adding MCP to an existing skills-only submission is unsupported. Actual publisher credentials, allowlisting and package acceptance are unverified. [OpenAI desktop-only policy](https://developers.openai.com/plugins/deploy/desktop-only) · [OpenAI submission prerequisites](https://developers.openai.com/plugins/deploy/submission)

## Decision

| Basis | Gate | Verdict |
| --- | --- | --- |
| Independently checked | Immutable source, ZIP and receipts, portable rebuild, review metadata | **GO for private evaluation review.** |
| Independently checked | Current GitHub-hosted protected runtime | **BLOCK.** UID map denied. |
| Operator reported, summaries reconciled | Crostini protected fixture and live-state PR #33 retry/revocation | **GO for reported scope.** Independent on-device review pending. |
| Unexecuted | Trusted CI enrollment, private evidence review, clean exact-client compatibility, authorized signing and publisher authentication, distribution access | **BLOCK.** Each needs separate evidence. |
| Release decision | Production release, signature, tag, deployment, merge and submission | **BLOCK.** Require the applicable gates and approval. |

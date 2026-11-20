# Assessing production release authority

The production decision for this implementation is **BLOCKED**. The assessor reads configuration and compares evidence. Its process has no signing, installation or publication operation. The protected workflow stops at its signing gate. The ephemeral CMS evaluation issuer has no production authority. [Workflow](../.github/workflows/protected-release.yml) · [Evaluation trust model](release-trust.md)

## Read the decision

Run the program from a separately reviewed checkout on Linux. Select the PR, commit and tree from the subscriber or maintainer's own source record. Use a GitHub account with read access to repository settings for the live query. Capture stdout and retain the exit status.

```bash
python3 -I release/governance/readiness.py --pr "$pr" \
  --expected-head "$approved_commit" --expected-tree "$approved_tree"
```

The `awooo.production-readiness/v1` output lists each mandatory condition, its evidence source and every unmet requirement. `GITHUB_API` identifies a result from the GitHub collector invoked during this assessment. `UNKNOWN` covers unreadable or unsupported controls. `IMPLEMENTATION_LIMIT` identifies requirements for which this version lacks a qualified production adapter or independent approval. For endpoint-level explanations, run the preflight with the same PR, commit and tree. Even successful settings checks describe only the instant of observation. [Preflight](../release/governance/preflight.py)

For offline replay, add `--offline` and optionally `--qualification-dir DIRECTORY` containing the exact candidate's `qualification.json`. Offline source coordinates record the caller's selection. The optional digest labels a supplied evaluation report. Anyone can construct those bytes. Their strongest classification here is `FIXTURE_REPORTED`, with no effect on a production condition. The readiness command exits 1 for BLOCKED. Argument errors exit 2. A future production path requires review and implementation of the missing evidence adapters. [Executable assessor](../release/governance/readiness.py)

## Release binding check

The separate `compare` operation checks whether a normalized release projection agrees with independently selected release policy. It can detect inconsistent claims in an incident review or qualification run before an operator examines their authoritative sources. Replay it using a separately obtained policy digest and independently known UTC epoch seconds.

```bash
python3 -I release/governance/readiness.py compare \
  --policy approved-policy.json --policy-sha256 "$policy_pin" \
  --claims observed-claims.json --as-of "$epoch_seconds"
```

Both JSON inputs use sorted keys, two-space indentation, ASCII escaping and one trailing newline. The reader rejects duplicate keys, excessive sizes, unexpected fields and unsafe file types. The policy schema is `awooo.release-binding-policy/v1` and the projection schema is `awooo.release-claims/v1`. The executable control fixture supplies concrete examples of both. [Control fixtures](../tests/test_governed_readiness.py)

| Input | Required binding |
| --- | --- |
| Policy | Validity interval, minimum sequence, exact authorized release tuple, dispatch initiator, source author, workflow run ID/attempt, and role-specific stable GitHub account IDs for source review, release approval and publication. Release and publication rosters must be disjoint. |
| Release tuple | Exact commit/tree, stable three-part public version, positive sequence and eight SHA-256 digests. They cover the protected workflow bytes, source/build inputs, dependency lock, build parameters, wheel, SBOM, release manifest and unsigned provenance statement. The approved manifest must bind platform and documentation digests. |
| Builder | GitHub OIDC issuer, fixed repository name and numeric ID, protected main, explicit dispatch, GitHub-hosted runner, pinned workflow path/revision, source revision, certificate identity and SLSA predicate type. |
| Review and deployment records | The source author and release requester are ineligible to approve. Source review covers exact commit/tree. Signing and publication records cover commit/tree, sequence, version, manifest and workflow run ID/attempt. Stable reviewer IDs, purpose and record identifiers are required. The deployment phases require distinct records. |

A successful comparison emits `MATCHED_BINDINGS` and exits 0. Inconsistent projections exit 1. Unavailable or unsupported input exits 2. Every result contains `release_authorized: false`. A fabricated set of matching policy and claims can pass this structural comparison. Neither a matching policy digest supplied by an attacker nor a GitHub display name authenticates its inputs. Only a separately reviewed adapter that derives each claim from its authoritative witness could use a match as one component of a future authorization decision.

## Production mechanism and prerequisites

For a future protected GitHub Actions builder, use GitHub artifact attestations backed by Sigstore workload certificates. GitHub's verifier can constrain source digest, workflow identity, signer workflow digest, OIDC issuer and runner type. A wheel, its CycloneDX SBOM and its release manifest each need a digest-bound attestation and policy comparison. SLSA Build Provenance v1.2 specifies the in-toto Statement v1 provenance predicate. Its type and subject hashes alone cannot convey reviewer consent, independent custody or release sequence. Cosign also supports blob and bundle verification, but would require a separate GitHub-specific policy adapter for this profile. [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations) · [GitHub CLI verification](https://cli.github.com/manual/gh_attestation_verify) · [SLSA Build Provenance v1.2](https://slsa.dev/spec/v1.2/build-provenance) · [Sigstore verification](https://docs.sigstore.dev/cosign/verifying/verify/)

1. The repository administrator establishes the protected-source settings, independent review and separate signing and publication environments in the governance runbook. Independently review the exact release workflow, dependency pins and CODEOWNERS at the candidate revision. Capture the required check runs and effective approval records. An open PR, a draft review or a green check alone provides no release authority. [Governance runbook](governed-release.md)
2. The release board authorizes the exact source, build definition, expected distribution bytes, platform matrix and release number/sequence. Bind these to expiring approvals. Define how GitHub review decisions and production deployment approvals bind the exact immutable manifest presented to each approver. Require separate publication consent. GitHub environment names and workflow inputs alone do not prove which bytes a human reviewed.
3. After independent review, a protected, isolated signing job may receive the short-lived workload identity. The documented binary attestation path uses job-scoped `id-token: write`, `attestations: write` and `contents: read`. Do not grant these privileges to PRs or to build/test jobs. Use immutable Action revisions and disallow unreviewed inputs, artifact names as identities, execution of candidate code or arbitrary caller-selected subjects in the signing job. The production signer must check its dispatch and independently approved manifest inside the boundary that actually obtains its credential. This implementation grants no such privilege. [Generating GitHub artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations) · [OIDC security](https://docs.github.com/en/actions/concepts/security/openid-connect)
4. The subscriber independently obtains the approved verifier, trusted Sigstore root, repository ID, issuer and workflow, version/sequence floor, current revocations and reviewed source/manifest pins. For the chosen GitHub CLI version, qualify offline bundle verification with `--bundle`, `--custom-trusted-root`, `--repo`, `--source-ref`, `--source-digest`, `--signer-workflow`, `--signer-digest`, `--cert-oidc-issuer`, `--predicate-type` and `--deny-self-hosted-runners`. Verify each subject's bytes before extraction or installation. Independently check the approved tree, parameters, dependencies, platform and review/withdrawal evidence. Qualify real success, rejection, revocation and stale-policy behavior using actual protected builds before accepting the adapter. [GitHub CLI verification](https://cli.github.com/manual/gh_attestation_verify)
5. The custody and incident operators verify an independently controlled durable copy, recovery exercise, historical withdrawal record and subscriber freshness plan. The release board checks documentation approval and naming clearance, records the final decision, and authorizes publication for that manifest only. Obtain an independent review of the complete control chain before enabling signing or publication. [Operational release guide](governed-release.md)

The v1 comparator deliberately accepts only stable three-component versions, a direct workflow at the reviewed commit, a GitHub-hosted runner and the fixed protected workflow path. Reusable-workflow identity, merge-queue lineage, enterprise issuers, alternative build hosts and fresh deployment-approval authentication require separate qualification. This PR exercises the offline policy comparisons and the existing evaluation issuer. No production workload certificate, authorized production release or durable public custody receipt was issued.

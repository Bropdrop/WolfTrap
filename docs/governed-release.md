# Verify and install awooo for evaluation

awooo is the distribution name. The package and command are `wolftrap`. Local scanning is free for personal and commercial use under Apache-2.0. You need a trusted copy of Python, a local project you have permission to inspect, and an evaluation capsule approved by your software custodian. The scanner runs offline without an account, telemetry, API key or administrator access. Production installation is **BLOCKED**. The procedure below selects the evaluation authority explicitly. [License](../LICENSE) · [Release decision](production-authority.md)

## Your first local scan

Use Ubuntu 24.04 on x86-64 or arm64 with CPython 3.12.14, venv, pip and system OpenSSL 3. Check the two installation jobs at the exact candidate revision for evidence on your architecture. Other Python versions, macOS, Windows and other Linux distributions are outside the installation profile. [Qualification workflow](../.github/workflows/governed-release-qualification.yml) · [Product coverage](offline-product.md)

1. Get the unopened capsule from the custodian. Through a separately authenticated channel obtain a reviewed copy of `release/verifier`, the subscriber trust directory, the SHA-256 of its policy, the release sequence and the current minimum allowed sequence. For governed evaluation also obtain the minimum incident-policy generation and the v2 policy. Your administrator should confirm those values are current. Keep the verifier and trust directory outside the download. The system clock and local machine must be trustworthy. If you have only the download, stop here and request the independent material. [Trust bootstrap](release-verification.md) · [Subscriber incident policy](subscriber-incidents.md)
2. In Bash, set the variables below to the values provided. The verification step runs the independently reviewed verifier. Installation verifies the capsule, creates a fresh private virtual environment, and rechecks current policy before pip installs the wheel. Keep this terminal open for step 3.

```bash
read -r -p 'Path to reviewed verifier directory: ' verifier
read -r -p 'Path to evaluation capsule ZIP: ' capsule
read -r -p 'Path to subscriber v2 trust directory: ' trust
read -r -p 'Independent policy SHA-256: ' pin
read -r -p 'Approved release sequence: ' seq
read -r -p 'Current minimum release sequence: ' floor
read -r -p 'Current minimum policy generation: ' generation
work=$(mktemp -d)
args=(--evaluation --bundle "$capsule" --trust-dir "$trust" --policy-sha256 "$pin"
      --sequence "$seq" --minimum-sequence "$floor" --minimum-policy-generation "$generation")
python3.12 -I "$verifier" verify "${args[@]}" &&
  python3.12 -I "$verifier" install "${args[@]}" --venv "$work/venv" &&
  "$work/venv/bin/wolftrap" doctor
```

3. Continue after both verification steps report `VERIFIED` and `doctor` exits successfully. `REJECTED` means a trust or integrity check failed. `INCONCLUSIVE` means some required evidence or verifier capability was unavailable. In either case, keep the reason and contact the custodian before trying again. For a first scan, run the included two-file example. The expected scan exit is 1. Then replay and open the human-readable result.

```bash
wt="$work/venv/bin/wolftrap"
"$wt" quickscan --demo --output-dir "$work/example"
"$wt" verify-report --demo --evidence-dir "$work/example"
cat "$work/example/quickscan.md"
```

The example flags an unconditional approval callback in a fictional program. Successful replay exits 0 and shows that the installed engine reproduced the evidence. To review a local project, replace the example commands with the following. Keep reports and the installation outside the project.

```bash
read -r -p 'Local project directory you are authorized to inspect: ' project
"$wt" quickscan --root "$project" --output-dir "$work/project-review"
"$wt" verify-report --root "$project" --evidence-dir "$work/project-review"
```

Scan exit 0 means the supported patterns did not match the selected inputs. Exit 1 asks for human review. Exit 2 indicates incomplete coverage, unsafe inputs or another reported failure. Read the coverage section before interpreting results. Only static checks on supported local files ran. Keep a separately retained report manifest digest when later comparison to the original matters. No human onboarding or download-time target has been established. The earlier v1 fixture remains available for historical evaluation under its original policy. [Report fields, file selection and replay](offline-product.md) · [Earlier evaluation instructions](release-verification.md)

## Configure a production review boundary

The following steps require separate authorization from the organization that owns the repository and its release infrastructure. They describe actions for identified human owners. The draft and its evaluation jobs hold no production signing or publishing authority.

| Responsible operator | Setup and evidence to retain |
| --- | --- |
| Repository administrator | In **Settings → Rules → Rulesets**, inspect repository and inherited rules for `refs/heads/main`. In **Settings → Branches**, configure classic protection for exactly `main`, the profile this preflight supports. Escalate any additional effective rulesets for independent evaluation. Require reviewed pull requests, dismissal of stale approvals, code-owner approval, approval of the latest reviewable push, and successful up-to-date checks from their expected GitHub App. Disable force pushes, deletions, bypasses and unreviewed direct pushes, including administrator exemptions. Use the currently supported preflight profile. Capture effective protection after saving. |
| Security and release engineering owners | Adopt ownership assignments on the base branch after the named owners consent. Protect the ownership file itself. Select required checks by their actual unique job names and publishing App IDs. The preflight checks the governed and release-trust workflows for the protected main target, including both native platforms and research. Consult the preflight policy for exact job names, workflow paths and App ID. A missing job, an ambiguous context name, a changed check source, a skipped result or an approval on an earlier head needs investigation. [Proposed ownership policy](proposed-codeowners.md) |
| Repository or organization Actions administrator | In **Settings → Actions → General → Workflow permissions**, select the read-only default and disable Actions approval of pull requests. Inspect organization policy, installed Apps, deploy keys, outside collaborators, runner configuration and who can change workflows or issue release credentials. Restrict Actions to the reviewed immutable action revisions or the equivalent organization policy. Record effective token policy and origin of each required check. A forbidden API response requires an authorized read-only observer. |
| Environment administrator | In **Settings → Environments**, create separate `awooo-release-review` and `awooo-publication-review` environments. Restrict deployments to the exact protected `main` branch, exclude tags, require disjoint sets of eligible human reviewers for each environment, prevent self-review and prohibit administrator bypass. Check environment-scoped secret **metadata** and grant only the capabilities required by a separately approved workflow. Retain deployment protection-rule and selected-branch evidence. Verify the policy on the job that would actually request a signing or publishing credential. |
| Independent source reviewer | Review the source, build definition, verifier, tests, documentation and dependency locks. Record the reviewed head commit and tree; approve that exact change through GitHub. Recheck the head, effective rules and authoritative checks after changes. A PR author's own assertion, a review on a previous revision or success in fixture CI cannot approve a release. If integration creates a new build revision, bind and qualify that revision explicitly. |
| Signing and publication reviewers | Review the authorized repository, workflow revision, exact protected source commit/tree, release version and sequence, builder identity, inputs, wheel, SBOM, provenance and manifest. Bind the selected digests to the approval. Have a separately accountable publisher verify that approval, current revocation state, naming clearance and independent durable custody. Keep real approver IDs, exact scopes and timestamps in controlled audit storage. Multiple names on a GitHub environment reviewer list do not require everyone on the list to approve. |

Use the read-only governance preflight to retrieve effective settings and current GitHub records. Preserve its observation time, exact head/tree, API failures and reported blockers with the revision being considered. Settings can change between audit and signing. Repeat the observation at authorization time and validate the builder's workload identity independently. The source audit cannot see every organization control, human role conflict, credential outside GitHub or actual signing-provider policy. If an account, plan, permission or reviewer cannot provide the required control, leave production disabled. [Preflight command and API coverage](governance-preflight.md) · [GitHub protected branches](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches) · [GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)

## Read and reproduce qualification

Open the qualifying PR's checks for its exact head. Download the `governed-evaluation-ubuntu-24.04` and `governed-evaluation-ubuntu-24.04-arm` artifacts. In each, inspect `governed/qualification.json` for the source and isolation record, `governed/unit-tests.json` for the test results, `governed/custody.json` for the disposable recovery exercise and `governed/readiness.json` for production blockers. Also inspect each native host’s `governed/incident-install.json` for the v2 install and withdrawn-release refusal. The archives include release-trust and foundation evidence. The independent research job retains an index in `governed-research-index`. A separate verifier archive is available for comparison with a trusted checkout. The Actions retention request is 30 days. Preserve independently checked copies beyond that window. [Hosted qualification](../.github/workflows/governed-release-qualification.yml)

On Linux with user network namespaces available, start from a clean, independently selected checkout. Use the interpreter and reviewed local dependencies matching the qualification job. This command exercises the governed controls with a fresh output directory. The complete platform installation, release cryptography and research commands appear in the workflow. If namespace creation is denied, record that local isolation was unavailable and consult matching hosted evidence.

```bash
git diff --quiet && git diff --cached --quiet &&
  head=$(git rev-parse HEAD) &&
  parent_ns=$(readlink /proc/self/ns/net) &&
  work=$(mktemp -d) &&
  unshare -Urn -- env -i PATH="$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 \
    python3.12 -I release/governed_qualification.py --expected-head "$head" \
    --parent-netns "$parent_ns" --output-dir "$work/governed"
```

With independently selected GitHub Actions artifact metadata, compare the local result to the original downloaded artifact ZIP for the same platform. Obtain the artifact SHA-256 from the authenticated run you selected by repository, workflow and exact revision. Supply the expected commit and tree from your trusted source record. A digest copied from inside the ZIP cannot authenticate it.

```bash
python3.12 -I release/replay_governed.py --artifact "$hosted_zip" \
  --artifact-sha256 "$independent_sha256" --local-dir "$work/governed" \
  --expected-head "$approved_commit" --expected-tree "$approved_tree"
```

A matching replay exits 0. A mismatch exits 1 and unavailable evidence exits 2. The result covers the declared evaluation evidence on that platform. The draft workflows target particular stack branches. Release operators must separately qualify required checks for the protected source branch, verify their actual workflow and revision, and re-observe their effective enforcement. A job name and the GitHub Actions App ID can be shared by different workflows.

## Who can authorize the first production candidate

1. The release owner obtains the exact protected source decision and qualification evidence. The platform owner independently establishes the production builder identity, issuer, signed provenance and subscriber verification policy. PR builds keep read-only access. The authorized job must have an identity restricted to the reviewed workflow, immutable source and protected environment. A preceding review job alone does not authenticate a later job's signing identity.
2. The archive owner demonstrates replication to independently controlled storage, retention lock, recovery, withdrawal and detection of conflicting histories. The subscriber owner exercises verification from a clean trusted machine with a current policy acquired out of band. A public recovery receipt can identify restored bytes. Subscriber pins, keys and sequence floors require their own trusted distribution channel.
3. The independent reviewer records the tested platform, outstanding risks and exact approvals. The product owner supplies written clearance for the public name. The release authority rechecks every mandatory readiness condition. Any absent, stale, or contradictory witness keeps the decision **BLOCKED**. A future change to enable production signing or publication requires its own approval. The present workflow stops before either operation. [Machine-readable release decision](production-authority.md) · [Existing release trust boundaries](release-trust.md) · [Naming clearance](https://github.com/GovernableIntelligence/WolfTrap/issues/21)

## Suspend, recover and resume

| Event | Immediate action | Evidence needed before resuming |
| --- | --- | --- |
| Suspected compromise or loss of signer | The release owner suspends signing and publication. The identity administrator revokes the affected workload or key at the provider. The subscriber authority distributes a fresh, independently authenticated bulletin and policy pin, scope, generation and release floor. A disconnected subscriber waits for current policy. | Identify every affected issuer, key revision, source and release. Rotate independently and test old/revoked identities and new authorized identities. Record the incident and positive and negative verification results. |
| Withdrawal or supersession | The release owner identifies the exact sequence and manifest, records the reason in the controlled incident record and distributes the withdrawal or new approved sequence. Keep the old bytes in custody for investigation. | Verify the withdrawn object remains identifiable and refuses installation. A superseded, unwithdrawn version may be examined historically. Reinstallation needs the subscriber's explicit, time-limited rollback decision. |
| Mirror corruption, missing custody or interrupted publication | The archive owner quarantines the suspect copy, pauses publication and compares retained objects, index history and externally held head pins across independent replicas. Preserve partial files and competing histories for investigation. Restore into an empty destination. | Compare restored wheel, SBOM, manifest, signed capsule, sequence and index to pre-incident independent pins. Repeat standalone signature verification under current policy. A missing trusted checkpoint or conflicting retained history requires investigation before selecting a branch of history. |
| Subscriber state lost, stale or contradictory | Stop installation and preserve the policy files and failure reason. Rebootstrap verifier, clock, trust roots, current policy pin, generation floor and release sequence floor from independent subscriber administration. | Repeat verification and the host-matching install exercise. The distributor's current mirror cannot establish an independently trusted subscriber high-water mark. |

Run the custody recovery exercise on a disposable destination before accepting a production storage provider. Preserve evidence and escalate under the disclosure policy when real keys, storage or source authority may be affected. A private evaluation fixture exercises recovery logic. Production restoration also requires surviving evidence and independent operators in the real storage and trust domains. [Custody and disaster recovery](governed-custody.md) · [Subscriber revocation and rollback](subscriber-incidents.md) · [Security disclosure](../SECURITY.md)

# WolfTrap Stage 3 — local build inspection v0.3 candidate

## Purpose

Let an independent developer scan **their own local build configuration**
without making that build run or contact a network endpoint. WolfTrap's
original synthetic authorization harness remains separate. Stage 3 adds
bounded static triage of configured trust boundaries, not penetration
testing, malware generation, or an authorization oracle over the target.

## Supported input

- GitHub Actions YAML in `.github/workflows`, up to 64 files and 256 directory entries.
- Top-level `Dockerfile` and `Containerfile`.
- At most 256 KiB per supported file and 2 MiB total.
- No symlinks in supported inputs, YAML aliases, duplicate YAML keys, or
  unbounded parser nodes. Unsupported forms fail **INCONCLUSIVE**.
- No project code, dependency, artifact, or container is executed. The tool
  performs no HTTP, DNS, Git checkout, model call, or external scan.
- Scanner output must be a fresh or empty directory **outside** source root.

## Findings

| Rule | Static review signal | Notes |
| --- | --- | --- |
| WT-GHA-001 | Privileged PR trigger + untrusted HEAD checkout + subsequent code execution | Write-capable token increases severity; never claims exploitability |
| WT-GHA-002 | Untrusted event or free-form input expression in a `run` script | Review interpolation and validation |
| WT-GHA-003 | Non-SHA-pinned external action | A supply-chain reproducibility consideration |
| WT-GHA-004 | Workflow token permissions unspecified | Effective org defaults not inferred |
| WT-GHA-005 | `workflow_run` + artifact download + write-capable token | Potential untrusted artifact path; actual use must be reviewed |
| WT-GHA-006 | Matched PR workflow upload → triggering run download in an explicitly write-capable downstream workflow | Cross-file trace, artifact-name digest, and higher severity if the downloaded directory is directly executed |
| WT-GHA-007 | Pull-request-triggered job explicitly selects `self-hosted` runner label | HIGH conditional review signal; effective runner isolation, approvals and repository visibility are not inferable |
| WT-DOCKER-001 | Base image lacking digest pin | Does not imply image compromise |
| WT-DOCKER-002 | Fetch-and-execute shell pipeline in Docker build | Conditional risk; no remote content fetched by WolfTrap |

Findings carry file-relative locations, supporting condition labels,
deterministic finding IDs, and per-condition counterfactuals. A counterfactual
describes a **detector cut**, not proof that the application would become safe.
Neither absence nor presence of a static pattern alone establishes an
exploitable vulnerability.

### Self-hosted runner exposure (community candidate)

`WT-GHA-007` recognizes a `pull_request` or `pull_request_target` job with an
**explicit** `self-hosted` label, including `runs-on` lists and label mappings.
It reports a HIGH-priority *review*, even with a read-only token, because
local YAML cannot prove that the runner is freshly provisioned, isolated or
protected by contributor approval. The rule is supported by 21 synthetic
positive, negative and ambiguous selector cases. Unresolved expression-based
runner labels return `INCONCLUSIVE` rather than a security pass. Custom runner
labels and group-only selectors are outside exact attribution; a no-match does
**not** prove that a runner is hosted by GitHub. It never contacts a runner.

- [GitHub: hardening for self-hosted runners](https://docs.github.com/en/actions/reference/security/secure-use#hardening-for-self-hosted-runners)

## Stage 4 additive model: cross-workflow artifact paths

Stage 4 correlates **multiple local workflow files** rather than looking only
at one file's configuration. WT-GHA-006 requires all of these concrete links:

1. A local upstream workflow with an explicit, exact name and a
   `pull_request` event uploads a named artifact via `actions/upload-artifact`.
2. A local downstream workflow subscribes to that name through
   `on.workflow_run.workflows` and has **explicit** write-capable permissions.
3. A downstream job downloads the same artifact (or all artifacts) using
   `actions/download-artifact` with a token and `run-id` set to the triggering
   `${{ github.event.workflow_run.id }}`.
4. If the same downstream job later directly invokes a script under the
   download directory, the review signal is **HIGH**; an otherwise matched
   artifact handoff is **MEDIUM**. Neither signal is a confirmed exploit.

The report includes `trace.producer_workflow`, `trace.consumer_workflow`, a
SHA-256 digest of the matched artifact name, and whether direct script use was
seen. Each factor also points to its source file and approximate line. Raw
scripts, artifact content, source text, tokens and secret values are not saved.
The counterfactuals show *detector* conditions, not proof of a fix.

Precision controls: a mismatched upstream workflow name or artifact name,
a default/current-run download, a job with explicit read-only permissions, or
an unambiguous `workflow_run.event` guard excluding PRs does not create a
WT-GHA-006 signal. Dynamic artifact names, duplicate matching upstream names,
or cross-repository artifact references are **INCONCLUSIVE** within the bounded
path model. WT-GHA-005 remains a separate per-file, conditional signal.

Known limitations: this is not a full data-flow engine. It does not resolve
reusable workflows, API/`gh` artifact retrieval, shell aliases, scripts in
different jobs, indirect taint through files, nested builds, or arbitrary
security guards. The absence of WT-GHA-006 can mean *outside its model*.
Repository/org token defaults are never inferred from static YAML. A finding
requires an owner/maintainer to verify actual conditions before disclosure.

### Differential mutation corpus

`tests/fixtures/stage4_artifact_path_corpus.json` records **39 deterministic
synthetic cases** with distinct positive, medium-risk, negative, and
inconclusive controls. The test harness renders complete upstream/downstream
YAML files in isolated temporary directories, checks the exact new rule and
severity, asserts that input bytes do not change, and independently checks
JSON/SARIF/report-manifest consistency and hashes. This corpus is synthetic,
not evidence of exploitation or a detection-rate benchmark against real
incidents.

Authoritative background:

- [GitHub Security Lab: preventing pwn requests](https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/)
- [GitHub Docs: securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [GitHub Docs: secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [Official download-artifact run-id semantics](https://github.com/actions/download-artifact)

Useful primary references:

- [GitHub: securely using pull_request_target](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [GitHub: secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub: SARIF code-scanning format](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
- [Docker: building best practices](https://docs.docker.com/build/building/best-practices/)

## Example for a developer

```bash
python -m pip install -e '.[build-scan]'
wolftrap scan-build \
  --root /work/acme-api \
  --output-dir /work/wolftrap-acme-evidence
```

Outputs:

- `build-scan.json`: summary and conditional findings with factors.
- `build-scan.md`: human-readable review.
- `build-scan.sarif`: SARIF 2.1.0 findings for compatible tools.
- `build-scan.manifest.json`: SHA-256 and byte length of the other outputs,
  plus a digest of the bounded input inventory.

An interrupted write leaves an `INCOMPLETE` manifest; a completed scan whose
input was unsupported is `INCONCLUSIVE`. File paths are relative and source
contents or secrets are not copied into findings. The scanner never reads
password stores or environment variables.

Status codes:

- **0 — NO_PATTERN_MATCH:** no supported static rule matched. Not a PASS of
  the application's security.
- **1 — REVIEW_REQUIRED:** one or more conditional review signals.
- **2 — INCONCLUSIVE:** unsupported, ambiguous, too large or missing source,
  or scanner configuration error. No claim of safety.

## Verification scope and limitations

Positive controls are safe synthetic workflow/container fixtures. Negative
controls intentionally contain compound risky patterns, malformed YAML,
duplicate keys, symlinks, oversized content, or conflicting outputs. They
demonstrate pattern detection and fail-closed boundaries only. They do not
demonstrate real exploitation, automatic remediation, runtime isolation, or
complete coverage of another repository.

No automatic SARIF upload or downstream GitHub permissions are enabled. A
repository owner can choose to ingest reports through a separately reviewed
workflow. Broader source-language analyzers, actual artifact provenance
validation, dynamic sandbox replay, external target adapters, and model-led
hypothesis proposals remain **DESIGNED ONLY**.

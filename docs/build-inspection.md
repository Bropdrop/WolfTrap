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
| WT-DOCKER-001 | Base image lacking digest pin | Does not imply image compromise |
| WT-DOCKER-002 | Fetch-and-execute shell pipeline in Docker build | Conditional risk; no remote content fetched by WolfTrap |

Findings carry file-relative locations, supporting condition labels,
deterministic finding IDs, and per-condition counterfactuals. A counterfactual
describes a **detector cut**, not proof that the application would become safe.
Neither absence nor presence of a static pattern alone establishes an
exploitable vulnerability.

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

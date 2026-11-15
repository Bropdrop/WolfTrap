# WolfTrap — quick start for repository maintainers

WolfTrap helps you review local GitHub Actions and root container-build trust
boundaries. It does **not** execute your application, run a pentest against a
host, read secrets, or guarantee that a repository is secure.

## Choose your path

### 1. Local command line (public beta)

Requirements: Python 3.11+, Git, a checked-out repository you are authorized
to inspect, and the optional YAML parser.

```bash
git clone https://github.com/GovernableIntelligence/WolfTrap.git
cd WolfTrap
python3 -m pip install -e '.[build-scan]'
wolftrap scan-build --root /path/to/my-repo --output-dir /tmp/wolftrap-my-repo
```

The target must be a local path. Use an initially empty output directory
outside the target. WolfTrap only inspects supported GitHub Actions workflow
files and root `Dockerfile`/`Containerfile`, subject to strict limits.

### 2. GitHub Action (public beta)

Copy [the reference workflow](../examples/wolftrap-scan.yml) into your own
repository at `.github/workflows/wolftrap.yml`. The example pins the Action
to the complete, hosted-qualified commit SHA
`4d1f075dadf257375a0ea59d39dea9151d07e3f5`. That immutable reference
does not automatically follow `main`; review and update it deliberately when
adopting future versions.

The Action defaults to **advisory** mode:

| Outcome | Meaning | CI default |
| --- | --- | --- |
| `NO_PATTERN_MATCH` | No supported pattern matched the inspected inputs | Success, **not** security PASS |
| `REVIEW_REQUIRED` | One or more conditional static findings | Success, evidence to review |
| `INCONCLUSIVE` | Incomplete, unsupported, missing, or corrupt input | Failure, never a clean result |

Set `fail-on-findings: 'true'` to fail CI on `REVIEW_REQUIRED` as well. It
does not change scanning behavior or grant additional authority.

The Action exposes `status`, `findings`, `unknown-inputs` and `evidence-dir`
step outputs, and retains evidence for 14 days by default. The uploaded
artifact contains the scanner-owned JSON, Markdown, SARIF, SHA-256 manifest,
and small action-status summary. It does **not** include your source code.

The GitHub runner downloads vetted pinned actions and installs PyYAML from
the package registry. **The scanner itself** does not make network requests
or execute the checked-out project. No GitHub token write access, secret,
model credential, or hosted external target is needed.

### 3. Challenge WolfTrap with synthetic adversarial cases

```bash
wolftrap challenge-build --seed 20261115 --cases 128 --output-dir /tmp/wt-challenge
wolftrap verify-challenge --evidence-dir /tmp/wt-challenge
```

The 128 saved synthetics cover 32 high-priority script paths, 32 artifact-only
handoffs, 32 broken links and 32 ambiguous paths. Matching all 128 is a finite
synthetic regression result; it is **not** an external exploit detection rate.

## Interpret the results

- Open `build-scan.md` for recommendations and cited conditions.
- Use `build-scan.json` for structured downstream review.
- Use `build-scan.sarif` in compatible scanning/report tools, without granting
  WolfTrap a security-events write token by default.
- Verify `build-scan.manifest.json` SHA-256 hashes when retaining the report.
  Hashes are unsigned integrity checks, **not** proof of a trusted publisher.
- Treat HIGH and MEDIUM as **review priorities**, not confirmed exploits.
- `WT-GHA-007` flags explicit self-hosted runner labels in PR-triggered jobs.
  Custom labels or runner groups without that label cannot be reliably
  attributed from workflow text; `NO_PATTERN_MATCH` does not establish
  runner isolation or guarantee repo safety.

## What it does not do

It is not a generic SAST engine, dependency CVE scanner, SBOM generator,
container image scanner, live penetration-testing platform, fuzzing engine
for arbitrary services, or replacement for CodeQL/OSV-Scanner/OpenSSF.
Unknown workflow constructs or missing permission semantics may be outside
its model; absence of findings is not evidence of absence of risk.

Only scan repositories you own or are authorized to examine. For confirmed
upstream defects, use the owner's responsible-disclosure process.

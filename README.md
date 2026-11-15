# 🐺 WolfTrap

**Find risky CI trust paths before they become somebody else's incident report.**

WolfTrap is a **read-only, offline trust-boundary inspector** for GitHub
Actions, Dockerfiles, bounded JavaScript/TypeScript agent code, and Stage 5.2
protected-effect boundary patterns across agent skills and scripts. Its
independently labelled synthetic challenge labs test the detectors without
contacting external systems. WolfTrap identifies *conditional review signals*,
explains the contributing conditions, and produces portable JSON, Markdown,
SARIF and integrity manifests. No inspected project code is executed.

Licensed under the [Apache License, Version 2.0](LICENSE).

**9 explainable CI/build review rules** currently cover privileged PR execution,
untrusted shell interpolation, mutable actions, unknown token authority,
cross-workflow artifact handling, self-hosted PR runners and risky container
build instructions. Each rule has a bounded scope and an explicit limitation.
**3 separate Stage 5.1 agent signals** cover recognizable fail-open moderation,
unconditional authentication/approval callbacks, and supported session-credential
logging patterns. **13 Stage 5.2 conditional patterns** add agent launch,
host-secret copying, sandbox and network isolation review, browser-managed
keys, skill instructions, API upload controls, and remote fetch bounds. None
establish real-world exploitability.

> **Public beta:** The read-only CI/build inspector, Stage 5.1 agent inspector,
> synthetic challenge labs, and community CI/build Action are available on
> `main`. The earlier community Action's
> [hosted qualification passed](https://github.com/GovernableIntelligence/WolfTrap/actions/runs/43663128275)
> at commit `4d1f075dadf257375a0ea59d39dea9151d07e3f5` before this
> documentation update. An empty scan is **not a security certification**.
> Findings are conditional and require human review; there are no confirmed
> external exploits here.

## Start here — three ways to use the wolf

### Option A: Scan your repository locally

Requires Python 3.11+ and a local authorized checkout:

```bash
git clone https://github.com/GovernableIntelligence/WolfTrap.git
cd WolfTrap
python3 -m pip install -e '.[build-scan]'
wolftrap scan-build --root /path/to/YOUR-repository --output-dir /tmp/wolftrap-review
```

The command installs the public beta from the default branch. For repeatable
security reviews, check out a reviewed exact commit rather than following a
moving branch. Use a new/empty output directory **outside** the target
repository.

### Option B: Add the GitHub Action (public beta)

Copy [`examples/wolftrap-scan.yml`](examples/wolftrap-scan.yml) to
`.github/workflows/wolftrap.yml` in **your** repository. It uses a read-only
token, checks out the requested revision without persisting credentials, runs
only WolfTrap's scanner, and retains a report artifact. The example pins a
hosted-qualified Action implementation to an immutable 40-character commit
SHA; review that exact revision before adopting or updating the pin.

Or run the 128-case offline detector challenge yourself:

```bash
wolftrap challenge-build --seed 20261115 --cases 128 --output-dir /tmp/wolftrap-challenge
wolftrap verify-challenge --evidence-dir /tmp/wolftrap-challenge
```

### Option C: Review local JavaScript/TypeScript agent boundaries

Point the separate `scan-agent` command at a local source checkout you own
or have permission to inspect. It accepts selected `.js`, `.ts`, `.jsx`,
`.tsx`, `.mjs`, and `.cjs` files; it does **not** launch the agent,
authenticate users, or call a model or API.

```bash
wolftrap scan-agent --root /path/to/YOUR-agent-source \
  --output-dir /tmp/wolftrap-agent-review
```

The output directory must be new or empty and outside the inspected source.
`WT-AGENT-001`, `WT-AGENT-002`, and `WT-AGENT-003` are conditional static
review signals, **not confirmed vulnerabilities**. An unconditional
authentication callback remains `REVIEW_REQUIRED` even when its name
explicitly indicates a demo/mock; unrelated comments cannot confer mock
context. Unsupported syntax or coverage limits produce `INCONCLUSIVE`.
See [agent rule scope and limitations](docs/agent-inspection.md) and the
[Stage 5.1 quick start](docs/quickstart.md#4-offline-agent-source-review-stage-51).

Want to see a wolf bite immediately? This bundled **synthetic** repository
fixture has a PR artifact → privileged consumer path:

```bash
wolftrap scan-build --root tests/fixtures/stage4_demo --output-dir /tmp/wolftrap-demo
# REVIEW_REQUIRED: 2 files, 2 review-required signals, 0 unknown inputs
```

**Results:** `NO_PATTERN_MATCH` (0, no *supported* pattern matched),
`REVIEW_REQUIRED` (1, manual triage), or `INCONCLUSIVE` (2, incomplete/unsupported;
never a clean pass). With the GitHub Action's default advisory setting, review
signals leave CI green but **unknown always fails**. Set `fail-on-findings:
'true'` to make known review signals fail CI as well.

### Option D: Stage 5.2 protected-effect boundary review

For a local repository with agent launch code, scripts, or `SKILL.md`
instructions, run the **separate** offline command:

```bash
wolftrap scan-effects --root /path/to/YOUR-agent-repo \
  --output-dir /tmp/wolftrap-effects-review
wolftrap verify-effects --evidence-dir /tmp/wolftrap-effects-review
```

Supported input: bounded JS/TS variants, `.py`, `.sh`, and only files named
`SKILL.md` among Markdown. Use repeated `--file` to select a small review set.
The scanner does not query credential stores or contact endpoints; its evidence
omits any credential literals that may be present in inspected source and
replaces original paths with SHA-256 aliases. It reviews unrestricted CLI flags,
host credential copying, explicit sandbox bypass and broad mounts, browser API
keys, potentially unsafe remote fetches, and skills instructing unauthorized
effects or excessive tool access. An agent skill cannot grant its own authority.
Every finding is `REVIEW_REQUIRED`, never proof of an attack; incomplete
inspection is `INCONCLUSIVE`. The existing community Action continues to run
**only** the CI/build scanner. [Stage 5.2 rule scope and limits](docs/effect-inspection.md).

See the [60-second quick start](docs/quickstart.md),
[supported rules and limitations](docs/build-inspection.md),
[responsible disclosure](SECURITY.md) and [contributing guide](CONTRIBUTING.md).

---

## Research engine and detailed qualification

**Adversarial authorization experiments + an offline CI attack-path inspector.**
Run it against your *own* checked-out repository to review risky GitHub Actions
and container-build trust boundaries; get explainable JSON, Markdown, SARIF and
tamper-evident report hashes without executing the scanned project. The Stage 4
detection adds cross-workflow artifact-path correlation and a 39-case
differential mutation corpus. [Quick start](#stage-4-cross-workflow-attack-path-correlation).

**Stage 5:** the offline *evasion challenge* generates 128
independently labelled synthetic workflow pairs, probes the detector for
missed or downgraded trust paths, and saves every YAML case plus SHA-256
evidence. It never attacks a real repository or runs target code.
[Try the challenge](#stage-5-the-offline-evasion-tournament).

**Stage 5.1:** a separate offline, bounded agent-code recognizer emits three
conditional JavaScript/TypeScript review signals. Its independently labelled
108-case corpus supports saved-input replay and evidence verification.
The scanner does not interpret arbitrary agent framework semantics or establish
effective deployment and authority. [Agent inspection details](docs/agent-inspection.md).

**Stage 5.2:** a separately invoked, lexical protected-effect reviewer emits
13 *conditional* patterns learned from authorized read-only reviews of an
agent harness, a browser BYOK demo, and an agent skill library. It also fixes
the CI scanner's repeated mutable `uses:` action attribution by locating the
actual YAML step in each job. Neither feature expands Stage 5.1's syntax
contract or silently enables an automated block. [Details](docs/effect-inspection.md).

The original WolfTrap v0.1 is a bounded, standard-library Python research harness for testing authorization controls against synthetic systems. It translates defensive lessons from FBI `FLASH-20261113-001` into deterministic experiments. The synthetic authorization harness does not contact, exploit, or deploy to external systems; the optional local build inspector is a separate, later capability.

This repository is a security-engineering instrument, not an intrusion platform. Its deliberately defective systems are local test sentinels; a finding against one is not evidence of a real-world vulnerability. FBI and MITRE references provide threat provenance and taxonomy, not endorsement.

## What the engine verifies

WolfTrap schedules protected operations through explicit logical phases so that revocation, replay, crashes, recovery, and competing agents can be interleaved without relying on thread timing or wall clocks. A separately implemented reference-state oracle evaluates the actual append-only synthetic effect ledger. It does not accept a system-under-test response as proof that an effect did or did not occur.

The qualification invariants are:

- no current authority means no protected effect;
- no valid origin binding means no protected effect;
- revoked authority means no new protected effect;
- replayed authorization means no duplicate effect;
- verified does not mean authorized;
- authorized does not mean executed; and
- an unknown security state fails closed.

A legitimate positive control must also commit exactly one expected effect. Consequently, an implementation that denies everything cannot qualify.

The corpus has one positive baseline, seven strict negative baselines that must
produce no effect, and three mixed stateful threat baselines containing both
legitimate and rejected transitions. Reports account for these groups separately
and require all ten threat baselines to pass.

The bounded stateful explorer varies principals, scopes, authorization epochs, operation digests and arguments, execution order, concurrent requests, revocation timing, crash sites, retries, and recovery. Complete generated cases and schedules are evidence artifacts; a seed is not treated as a substitute for the saved case. Potential counterexamples are minimized on fresh fixtures and must reproduce independently before they can be classified `CONFIRMED`.

## Safety boundary

- All principals, credentials, resources, origins, destinations, effects, and defects are synthetic.
- Protected resources use the `synthetic://` namespace; transfer destinations use `synthetic-sink://`.
- The runtime accepts no hostname, target URL, shell command, payload, production credential, or arbitrary callable.
- The engine requires no Docker service, physical device, commercial system, paid API, or external target.
- OpenAI integration is disabled. No API key is read and no model call is required.
- The manual GitHub workflow has read-only repository permission. It neither deploys nor opens, merges, or modifies pull requests.

The optional defensive-hypothesis interface is intentionally separate from experiments and findings. The requested GPT-5.6 Sol with Daybreak Blue capability was not available during v0.1 construction, so it was not substituted with another model or represented as used. A future model proposal would remain `PROPOSED` until translated into a bounded deterministic test and independently verified by the same oracle and reproduction process.

## Local use

Python 3.11 or newer is required; Python 3.12 is used by the workflow. No runtime package dependencies are required.

```bash
export PYTHONPATH=src
python -m wolftrap.test_runner --output reports/unit-tests.json
python -m wolftrap run --seed 20261113 --max-mutations 32 --output-dir reports \
  --unit-test-summary reports/unit-tests.json --sut correct-v1
```

The runner writes canonical JSON evidence, a Markdown rendering, and a completion
manifest containing both artifact hashes. The pair is authoritative only when
the manifest state is `COMPLETE`; reproduction validates it before loading a
finding. Use the saved report and finding identifier to replay the exact
minimized case:

```bash
python -m wolftrap reproduce --report reports/wolftrap-report.json \
  --finding-id WOLFTRAP-F-0123456789ABCDEF0123 --output-dir reports/reproduction
```

Run `python -m wolftrap --help` for the implemented bounds and command names. Exit status `0` means the bounded qualification completed without a verified violation and all required controls passed; `1` means a finding or qualification-control failure occurred; `2` means schema, infrastructure, execution, or evidence state was unknown and the run stopped safely. A bounded result is never an exhaustive proof.

A qualifying campaign requires a mutation budget of at least 32 and at least one
depth-2 interaction. The default `32` / `8` bounds also require the complete
11-scenario corpus, all ten mutation axes, selected replay/revocation/recovery
race windows, and both positive and negative controls. `--scenario` is a targeted
diagnostic mode; it intentionally returns a non-qualifying result because it does
not exercise the complete gate.

The GitHub Actions workflow automatically runs a bounded Stage 2 qualification on pushes to the exact `feat/wolftrap-autonomous-stage2-v0_2` branch. It also supports manual dispatch using a validated seed. Each run executes the unit suite and the same fixed three-seed, 128-mutation, 55-pairs-per-seed synthetic qualification, verifies the aggregate completion manifest, and retains the evidence as a GitHub Actions artifact for 14 days even if qualification fails. There are no scheduled, pull-request, external-target, model, or paid-API triggers.

## Evidence and provenance

Each security finding records the source and ATT&CK references, exact source commit and tree, dirty state, seed and full case, expected and observed behavior, independent pre/post ledger evidence, minimization and reproduction attempts, severity, confidence, and classification. Model-generated hypotheses cannot set a finding classification.

The authoritative threat input is:

- Federal Bureau of Investigation, `FBI FLASH-20261113-001`, November 13, 2026
- <https://www.ic3.gov/CSA/2026/261113.pdf>
- SHA-256 `3dd86a94d33b29c65f56b4307919b74358e63cfde33a600b61adce5794d169e2`

See [the source mapping](docs/threat-mapping.md) and its machine-validated
[complete advisory technique inventory](src/wolftrap/data/advisory-techniques-v1.json)
for the behavior-to-experiment trace. See [the research status](docs/research-status.md)
for lifecycle claim definitions. Generated reports are the authority for the exact
tested revision and actual counts.

## Non-goals

WolfTrap v0.1 does not perform external penetration testing, reproduce an intrusion campaign, provide offensive payloads, validate a live product, or expand into HERCULES, Ground Truth, MobiPute, financial systems, blockchain effects, or deployment. Owner authority remains with Stackbleed — Governable Intelligence.

## Stage 2: autonomous synthetic frontier

Stage 2 adds an unattended, bounded multi-seed sweep over all **55/55**
pairwise compositions of the existing 11 synthetic scenario families. Each seed
retains its complete case schedules, findings, JSON/Markdown reports, and
completion manifests. A stage-2 aggregate manifest is marked `COMPLETE` only
after its summary and constituent reports have been written. A single failing
control, missing unit-test attestation, truncated pair frontier, source change,
or infrastructure error prevents a `PASS`.

```bash
export PYTHONPATH=src
python -m wolftrap.test_runner --output reports/unit-tests.json
python -m wolftrap sweep --seed 20261113 --seed-count 3 \
  --mutation-budget 128 --unit-test-summary reports/unit-tests.json \
  --output-dir reports/stage2
```

Each seed runs with the same explicit bound of 55 interaction pairs, plus a
bounded mutation and schedule frontier. A `PASS` proves only this finite
synthetic qualification, not the correctness of an external system or an
exhaustive security analysis. A finding against a deliberately defective
sentinel is not a real-world vulnerability.

**No model integration has been enabled in Stage 2.** The optional GPT-5.6 Sol
/ Daybreak Blue hypothesis boundary remains disabled. Stage 2 reads no API
key, sends no network request, spends no credits, and exposes no external
target. A future model suggestion will have to become a schema-valid,
bounded deterministic case before the independent oracle can classify it.

## Stage 3: scan your own build, offline

WolfTrap Stage 3 adds a read-only local configuration inspector. It identifies
*conditional* GitHub Actions trust-boundary chains and Dockerfile supply-chain
signals, then produces JSON, Markdown, SARIF 2.1.0, and a SHA-256 evidence
manifest. Counterfactual explanations list the factors that would need to
change to break each composite detection. It does not execute inspected code.

Install the optional YAML parser in the environment running the scanner:

    python -m pip install -e '.[build-scan]'

Inspect your own local project and write results **outside** that project:

    wolftrap scan-build --root /path/to/my-project --output-dir /path/to/new-evidence

The root must be a local directory; URLs and network targets are unsupported.
Only top-level Dockerfile/Containerfile and GitHub Actions workflows are read,
with strict file-count and byte bounds. No secrets, source lines, subprocesses,
model calls, network calls, deployment, or credential use are required. The
scanner currently supports a finite rule set; it is not a general-purpose code
scanner, container image vulnerability scanner, or a certificate of security.

Exit status `0` means no supported pattern matched; `1` means human review is
required; `2` means incomplete/unsupported input and never implies safety.
Reports use `REVIEW_REQUIRED`, **not CONFIRMED EXPLOIT**. SARIF can be ingested
by compatible code-scanning tools under a separately authorized workflow.
See [Stage 3 build inspection](docs/build-inspection.md) for threat scope,
counterfactuals, usage, and interpretation.

The separate Stage 3 GitHub Actions qualification is limited to the
`feat/wolftrap-stage3-build-inspector-v0_3` branch and manual dispatch. It
installs a pinned YAML parser, runs the tests, scans only this repository's
build configuration and a deliberately flawed synthetic fixture, verifies
report hashes and expected findings, and retains evidence for 14 days. It
does **not** scan outside repositories, execute inspected target code, or
prove that a real-world build is exploitable.

## Stage 4: cross-workflow attack-path correlation

Stage 4 follows a *possible* supply-chain path across multiple GitHub Actions
files: an untrusted pull-request build produces an artifact, and a
`workflow_run` consumer with a write-capable token retrieves that **same
artifact from the triggering run**. Rule `WT-GHA-006` traces both workflow
files, links an artifact name by its SHA-256 digest, and increases the review
priority if it sees direct script execution from the downloaded directory.

This is more specific than a broad warning about privileged artifact use;
it does not infer missing permissions or claim a proven exploit. The packaged
39-case synthetic mutation corpus includes safe, concerning, and ambiguous
handoffs; ambiguous inputs fail **INCONCLUSIVE**. All targets remain local,
bounded, read-only and unexecuted.

**Try it on your own checked-out project:**

```bash
python -m pip install -e '.[build-scan]'
wolftrap scan-build --root /path/to/project --output-dir /path/to/new-evidence
```

The same command reports both existing Stage 3 rules and new Stage 4 traces
in JSON, Markdown and SARIF with a hash manifest. For a guaranteed positive
demo, scan `tests/fixtures/stage4_demo`; its workflows are deliberately
flawed **test data** and are not active GitHub Actions. See
[the Stage 4 path model and limitations](docs/build-inspection.md#stage-4-additive-model-cross-workflow-artifact-paths).

The independent Stage 4 workflow is branch-only/manual, uses read-only GitHub
permissions and uploads its local qualification evidence. It never runs code
from a scanned external repository. CodeQL, OpenSSF Scorecard, OSV-Scanner and
other mature tools remain complementary; WolfTrap does not claim to replace
them or to perform live penetration testing.

## Stage 5: the offline evasion tournament

Challenge WolfTrap's **own static detector** before asking it to review a
project. The tournament generates 128 synthetic workflow pairs divided equally
among direct script execution (`HIGH`), artifact-only handoff (`MEDIUM`),
broken trust links (`NONE`) and ambiguous linkage (`INCONCLUSIVE`).

The additional variants cover common execution wrappers such as
`bash -e`, `python3 -B`, `node --trace-warnings` and `env bash`, plus
noise steps, paths, artifact names and token/trigger changes. An independent
generator labels each case; those labels do **not** come from scanner output.
A deliberately crippled detector must fail the challenge's positive controls.

```bash
python -m pip install -e '.[build-scan]'
wolftrap challenge-build --seed 20261115 --cases 128 \
  --output-dir /path/to/new-challenge-evidence
wolftrap verify-challenge --evidence-dir /path/to/new-challenge-evidence
```

The report, Markdown scoreboard, and complete generated YAML cases have a
completion manifest with SHA-256 and byte counts. `PASSED_BOUNDED` (exit 0)
means only that this finite challenge matched all its synthetic expectations.
`DETECTOR_GAPS` (exit 1) means at least one mismatch. Invalid, incomplete, or
corrupt evidence fails closed (exit 2). Count must be a multiple of four from
64 to 256; seed is an unsigned 32-bit integer. Inputs and output are local.

Running `scan-build` on somebody else's checkout remains **read-only triage**;
it is never an authorization to execute that code, scan live hosts, or claim
a confirmed exploit. See [Stage 5 scope and replay](docs/evasion-challenge.md).

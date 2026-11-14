# WolfTrap

WolfTrap v0.1 is a bounded, standard-library Python research harness for testing authorization controls against synthetic systems. It translates defensive lessons from FBI `FLASH-20261113-001` into deterministic experiments. It does not scan, contact, exploit, or deploy to external systems.

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

The GitHub Actions workflow runs only when manually dispatched. It runs the test suite and a fixed-budget synthetic qualification, then uploads the report directory as an artifact even when qualification fails. There are no push, pull-request, or scheduled triggers.

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

## Stage 2: autonomous synthetic frontier (local candidate)

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

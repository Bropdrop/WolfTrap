# WolfTrap Stage 5 — finite offline evasion challenge

## Objective

Stress the **Stage 4 WT-GHA-006 static trust-path detector** with controlled
synthetic variants whose expected outcomes are defined by the generator, not
the inspected scanner results. This is an adversarial *detector regression
lab*, not penetration testing of an external system or a vulnerability claim.

## Grammar and independent labels

Each case creates two or three isolated GitHub Actions YAML files in a new
temporary directory. The upstream simulates an untrusted pull-request build
that may upload an artifact. The downstream simulates a `workflow_run`
consumer with explicit permissions, optionally retrieving the matching named
artifact with the producer's exact run ID. Both are **text only**.

| Label | Defined synthetic condition | Expected WT-GHA-006 result |
| --- | --- | --- |
| HIGH | Linked PR artifact is downloaded and directly invoked as a script in a write-capable job | HIGH |
| MEDIUM | Same linked boundary, without direct invocation from download directory | MEDIUM |
| NONE | A required edge is absent (e.g. read-only token, mismatched artifact, wrong run ID, guarded non-PR run) | No WT-GHA-006 |
| INCONCLUSIVE | Attribution is ambiguous (duplicate producers, dynamic artifact names, external repository) | Explicit exit 2 |

The grammar varies folder names, upload names, optional unrelated jobs,
interpreter flags and launch wrappers, missing edges, and ambiguous links.
It does **not** attempt arbitrary shell language or undocumented GitHub
semantics. The fact that the generator and detector are maintained in the same
repository is a possible common-mode bias; this is not independent red-team
validation of real workflow behavior.

## Run and replay

```bash
python -m pip install -e '.[build-scan]'
wolftrap challenge-build --seed 20261115 --cases 128 \
  --output-dir /tmp/wolftrap-evasion-20261115
wolftrap verify-challenge --evidence-dir /tmp/wolftrap-evasion-20261115
```

- `challenge-cases.json`: all complete, generated synthetic YAML texts,
  parameters, IDs, styles, and independent expected labels. This is the replay
  record; the seed alone is insufficient evidence of what was tested.
- `challenge-report.json`: observed detector classifications, per-case input
  SHA-256 hashes and coverage digest, mismatch count, and group counters.
- `challenge-report.md`: human-readable differential scoreboard.
- `challenge.manifest.json`: `INCOMPLETE` until all files are written, then
  `COMPLETE` with SHA-256 and exact byte counts.

The verification command checks the manifest, member hashes, and case/report
identity. These unsigned hashes catch accidental corruption but **do not
authenticate** a maliciously replaced report and manifest. A trusted external
signature/attestation would be a separate feature.

To reproduce a run exactly, use the same source commit, seed and case count,
compare the saved complete case files and their manifest hashes, and inspect
individual YAML records by case ID. No generated workflow is launched.

## Qualification and limits

- A passing 128-case run has **32 cases per group** and zero mismatches.
- At least one legitimate high/medium positive control is mandatory; a
  deny-everything detector fails the challenge.
- The scanner's own JSON/SARIF/Markdown completion hashes are verified during
  each isolated synthetic scan before its classification is accepted.
- Inputs are never executed or changed. No GitHub token, provider key, public
  repository, remote URL, Docker daemon or deployment is contacted.
- This lab tests a narrow, declared syntax grammar, not all GitHub Actions
  shell wrappers, reusable workflows, API calls, attack techniques, or actual
  privilege escalation. A matching `HIGH` remains `REVIEW_REQUIRED`.
- `PASSED_BOUNDED` is finite self-qualification, not certification or a
  measured real-world true/false-positive detection rate.

The branch-only Stage 5 GitHub Actions workflow runs the same unit suite,
128-case tournament and integrity verifier with read-only repository
permission, pins third-party actions, and retains evidence for 14 days.

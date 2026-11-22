# WT-GEO-R00 — GeoTrace original source recovery gate

**Status: RECOVERY IMPLEMENTED / FIRST-RELEASE GEOTRACE STILL BLOCKED.**

This is new tooling introduced after WT-ZT-001 PR #29. It is not the missing
`WolfTrap-API-GeoTrace-v1.zip`, does not implement GeoTrace v1 or v2, and does
not claim that any of the original **21** GeoTrace tests ran. Its own tests
validate the archive gate, not the geographic security engine.

## Source prerequisite

The user's prior ChatGPT conversation reported a downloadable
`WolfTrap-API-GeoTrace-v1.zip` with an offline prototype and 21 passing tests.
The original bytes, an independently selected SHA-256, exact file inventory,
source custody, and test execution were not recovered from GitHub or the
current workspace at the time this gate was authored. This report is historical
context, **not** authenticated source evidence.

Retrieve the original attachment from its generating conversation (or a
trusted retained copy). Keep it **outside the public repository** until its
contents, provenance, redistribution permissions and secret exposure have
been reviewed. Do not create a new ZIP and label it as the recovered original.

## Inspect inertly (no extraction or execution)

Requires Python 3.11+; only the standard library is used. In a trusted local
checkout of this exact branch, and with the original archive placed outside
the repository:

```bash
python3 qualification/geotrace/recovery.py inspect \
  --archive /absolute/path/to/WolfTrap-API-GeoTrace-v1.zip \
  --evidence-dir /absolute/path/to/new-empty-parent/geotrace-inventory
python3 qualification/geotrace/recovery.py verify \
  --archive /absolute/path/to/WolfTrap-API-GeoTrace-v1.zip \
  --evidence-dir /absolute/path/to/new-empty-parent/geotrace-inventory
```

An **independently selected** expected hash can be supplied with
`--expected-sha256 <64-lowercase-hex>`. The operator must obtain it through a
separate trustworthy channel, not copy it from the newly generated report and
call that independent custody. Matching an independently supplied hash still
proves only byte agreement with that expected value, not the author's identity
or the correctness of the ZIP's contents. If no independently grounded hash
exists, record custody as unverified.

The gate does not extract, import, run tests from, or otherwise execute the
original ZIP. It scans a bounded ZIP inventory, calculates member SHA-256 and
archive SHA-256, and creates only three evidence files in a **new** output
directory outside the source checkout. It rejects unsafe member names,
traversal, case ambiguity, symlinks, special files, encrypted or unsupported
compression, excessive member sizes, expanded-size bounds, and suspicious
compression ratios. The verifier independently rereads the original ZIP and
compares exact report content and closed artifact hashes, including after
manifest manipulation.

A successful `inspect` exit means `INVENTORY COMPLETE ONLY`. The JSON report's
qualification always remains
`BLOCKED_ORIGINAL_BASELINE_NOT_EXECUTED`. The verifier does not provide
publisher authentication or authorize a production/plugin release.

Limits: 64 MiB ZIP, 512 entries, 8 MiB/member, 64 MiB expanded total, 16 path
components and a maximum 250:1 ratio for members exceeding 4 KiB. An archive
rejected for size or format remains **BLOCKED**, not malformed by definition;
the approved review may adjust bounds with new hostile tests, without relaxing
path safety. Malicious local OS/kernel, compromised reviewer and archive
replacement between separate operator steps are out of scope. Use an isolated
review environment for any later execution of source code or tests.

## Original v1 baseline replay: not performed

Only after source provenance has been assessed:

1. Preserve original ZIP bytes and the independently selected hash. Inventory
   all source, test, documentation and dependency files without running code.
2. Record precise source identity, test names, execution prerequisites, fixture
   origins and any claims about the 249-country ISO dataset. Validate country
   definitions against a separately versioned reference.
3. In a *disposable, separately reviewed and network-isolated* environment,
   execute the original baseline tests only after reviewing their contents and
   dependencies. Do not install or execute unreviewed package scripts or use
   real provider keys. Record discovered/executed/passed/skipped counts, source
   revision where applicable and the actual command.
4. Reproduce both intended geographic positives and contradictory/unknown
   cases. Preserve test output and source evidence through a separately selected
   verifier. Never rewrite historical outcomes.
5. Only then consider GeoTrace v2 work and plugin integration in an independent
   development branch. Explicitly separate reported execution-region,
   network-egress, intermediary and destination observations from verified
   controlling principal identity and authorization. No IP or cloud region
   may independently grant permission to perform a protected effect.

**Mandatory gate:** WT-ZT-001 intended initial plugin scope still includes
GeoTrace. PR #29 and PR #28 remain unmerged. `scan-geotrace` and
`verify-geotrace` are NOT existing public-main commands. Do not list them as
available in the plugin until their own implementation and integration
qualification have passed. Do not submit or publish the plugin while the
required first-release scope remains blocked.

## Verify this recovery gate's own tests

```bash
python3 -m unittest discover -s qualification/geotrace -p test_recovery.py -v
```

These tests generate only fictional ZIPs in private temporary directories,
confirm rejection of unsafe artifacts, and ensure no uploaded source code is
executed. **Passing recovery-gate tests cannot substitute for the missing 21
original GeoTrace tests.**

## R00 integration qualification

The supplied recovery-gate package is 10,607 bytes with SHA-256
`62a873a7abbf77002434e5015e33e526ba9e7cc7980a7985a95427b0e2fffe2f`.
Its four regular members were compared byte for byte to commit
`d3d0fad2b6f263a181fec93c9b68d1f1c71e57c2`, tree
`fa859c8b11744772b47fd5fd96f1d80bc1a9ae40`. This identifies the user-supplied
gate archive. Its publisher identity was not independently authenticated.

The integration additionally checks canonical manifest bytes and rejects
ambiguous decoded member and implicit parent names. The 19 original gate tests
and three integration regressions passed on the qualified implementation
`5ac63741f792f518c5013bfa8a687866fd2cab15`, tree
`0b916e8e746dbd99d5898e2c4425433f639057e6`. Run from the repository root:

```sh
python3 -I qualification/wt_zt_001/offline.py python3 -B -m unittest discover -s qualification/geotrace -p 'test_recovery*.py' -v
python3 -I qualification/wt_zt_001/offline.py python3 -B qualification/geotrace/qualify_mutations.py
```

All six one-control mutation trials were DETECTED. The independent suite
caught removal of the expected digest check, false custody, a fabricated
v1 test count, promotion of release status, acceptance of an undeclared
manifest field and acceptance of inconsistent implicit directory casing.
Every clean and restored control passed. An initial harness layout placed
temporary evidence under the disposable checkout and made four trials
INCONCLUSIVE. Relocating the fixtures allowed all six trials to execute
with the original outside-tree guard intact.

The verifier recomputes the inventory from an independent reread using the
same parser and serialization implementation. This checks consistency with
the selected bytes under the tested profile. It does not provide an
independent parser implementation. Use a private local filesystem with
trusted path ancestors for the archive and evidence.

The dedicated workflow runs the same suites in a network namespace on a
read-only GitHub job. Local qualification used the inherited Linux libseccomp
launcher. See [the proposed v2 evidence contract and integration sequence](V2-ARCHITECTURE.md).

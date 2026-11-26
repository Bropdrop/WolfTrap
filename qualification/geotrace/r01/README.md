# R01 recovered baseline and GeoTrace v2 candidate

WolfTrap 0.6.0 and the skills-only wolftrap-security 0.2.0 candidate expose two offline commands for an explicitly selected local capture. The unchanged v1 historical CLI is confined to the recovery directory. The installed analyzer retains its in-memory country and provider matching; the v2 commands own all file access and policy evaluation.

## Source and reproduction

| Selection | Commit | Git tree |
|---|---|---|
| Verified draft #30 base | 7ac92867f8ded031c0b6b36611ccc95ead0a449c | 5fd8f20f486db0870f35c3dc21c17c158a527a81 |
| Exact v1 import and independent probes | ac97c591f8e4ea55eaec4a091448dd635d6fa41e | 9227e46414454e847185bc8e129d816fc059a9f1 |
| Qualified engine, plugin, fixtures and workflow | 117ccf550713056fab3ef35069ddd61d00c8f4af | 7e2c3f485b45d4e7fcd6122c2bf4636d277e4afd |

The handoff ZIP measured 27,105 bytes, SHA-256 `954f953d9056930587e733aa177b897be6a6f94f30e8621029434327a913fc41`. All eleven indexed members matched their recorded lengths and hashes. The enclosed original ZIP measured 17,236 bytes, SHA-256 `793df00656593d1a63d11e66d2c292d14104aaaf493beec58bf7773f4b273be3`. The six imported regular files and independent test file matched [the source receipt](source-receipt.json). The original upstream commit, original author and historical timestamp remain unverified. The import commit identifies this recovered copy.

A fresh local Linux network namespace reproduced all 21 original tests and eight separate probes. Two probes observed writes inside the selected source and through a symlinked output parent. They characterize v1 limitations. The original sample scan and verify also passed, and the sample report matched the recovered reference byte for byte. All 249 original country codes matched a separate local Debian iso-codes 4.18.0-1 reference. The handoff's pycountry comparison was a separate run.

From a clean trusted checkout, run each legacy suite in its own interpreter with the engine's PYTHONPATH unset. Keep bytecode outside the preserved source and block networking. The dedicated workflow applies a network namespace before running the suites.

```sh
r=qualification/geotrace/r01
python3 -B "$r/verify_source.py"
env -u PYTHONPATH python3 -B -S -m unittest discover -s "$r/wolftrap-api-geotrace-v1/tests" -v
env -u PYTHONPATH python3 -B -S -m unittest discover -s "$r/independent_tests" -v
PYTHONPATH=src python3 -B -m unittest tests.test_geotrace_v2 -v
python3 -B "$r/qualify_mutations.py"
```

## Run scan and replay

Use a separately reviewed engine installation. Select a local source root, an explicit relative JSON file, an external policy and its independently retained digest, and an evaluation date. For the committed fictional example:

```bash
sample="$PWD/qualification/geotrace/r01/examples"
out=$(mktemp -d)
args=(--root "$sample/capture" --file capture.json
      --policy "$sample/policy/policy.json"
      --policy-sha256 7327994f3e6d80e490a4900670dab1dfb853b4abe708e3e2321df9816a6b98f7
      --as-of 2026-11-22)
wolftrap scan-geotrace "${args[@]}" --output-dir "$out/review"
wolftrap verify-geotrace "${args[@]}" --evidence-dir "$out/review"
```

The example has five different answers. The provider registry claims France; the network estimate places VPN egress in Canada and a gateway hop in the US. A separate capture record claims execution in Germany, another claims processing jurisdiction in Brazil, and explicit intermediate hops claim Japan and Sweden. These are geographically scoped assertions. Operator and workload identity remain unverified. Protected effects are outside the observer and action authorization remains NOT_EVALUATED.

## Versioned contract

- **Capture.** `wolftrap.geotrace-input/v2` requires exactly schema, task, workload, session, capture and observations. The embedded capture follows the recovered v1 metadata schema. Its policy is untrusted input and has no effect on v2 policy comparisons. A direct v1 capture is supported with policy task v1-import and workload/session unknown.
- **Context.** Each observation names an event, binding_sha256, kind, hop, country, source handle, observed_on and valid_until. The binding hashes compact, key-sorted UTF-8 JSON followed by LF, containing task, workload, session and the exact event object. Binding detects substitution relative to a supplied observation. Anyone can author an unsigned capture. Execution region and processing jurisdiction each use hop zero. Intermediaries use ordered hops 1–32. A source handle identifies an input record's claimed origin; it confers no issuer trust. Evidence points back to capture indices. The CLI never dereferences handles.
- **Freshness and uncertainty.** The operator's date must equal the capture snapshot. Expired, future or over-age context cannot establish a country. Different current countries for the same dimension and hop yield CONFLICTING. Discontinuous hop indices make an intermediary policy comparison INCONCLUSIVE. Even a contiguous reported path has unverified completeness. A processing-jurisdiction claim requires an explicit record; provider nationality, egress and runtime region cannot fill it.
- **Policy.** `wolftrap.geotrace-policy/v2` requires schema, task, workload, session, allowed, max_age_days, valid_from and valid_until. Allowed is a nonempty mapping of selected dimensions to country allowlists. Exact bytes must match the operator's external pin. Use an independently controlled policy location. The evaluation date is operator supplied. Production time, policy custody and signers are outside the profile.
- **Results.** The scan returns 0 for NO_PATTERN_MATCH within selected dimensions, 1 for REVIEW_REQUIRED and 2 for INCONCLUSIVE. A missing or conflicting required dimension takes overall precedence; other observed policy mismatches remain visible per event. Malformed inputs fail before evidence creation. Verification returns 0 only for an exact four-file replay, including when the saved geographic result is INCONCLUSIVE. It returns 2 on mismatch. The verifier recomputes with the same reviewed parser. Independent expectations in the test suite check semantics separately.
- **File boundary.** POSIX descriptor-relative walks reject symlinks at each component. Only bounded, singly linked regular JSON files are selected. Inputs are limited to 256 KiB, policy to 16 KiB, context to 512 observations and the total provider-domain count to 512. V1 bounds apply within the capture. Evidence is written in a new external directory with exclusive file creation, and the manifest is written last. Verification reads only the expected JSON, Markdown, SARIF and manifest. Trust the mount namespace, interpreter, engine and parent-directory ownership for the duration of the operation. Concurrent hostile mount replacement, privileged filesystem attackers and Windows reparse points remain outside the tested profile.
- **Privacy and provenance.** Reports omit raw hosts, IPs and v1's stable per-address aliases. Exact capture, policy and selection digests remain correlatable. Treat evidence as restricted. The report identifies the engine version and relevant installed source digests. The review receipt binds the tested source to a specific repository revision. An exact replay establishes byte consistency under those selections; it cannot authenticate the capture publisher or establish geographic truth.

## Qualification and release decision

The R01 suite covers 22 v2 tests, including explicit source selection, both previously observed v1 write behaviors, conflicting jurisdictions, stale evidence, scoped observations, external policy, tamper-and-rehash rejection and legacy sample compatibility. All six v2 mutations were detected and all six restorations passed. The mutations changed egress-to-runtime inference, freshness enforcement, conflict classification, destination binding, policy pin checking and authorization reporting. An initial harness placed fixtures under the disposable engine's checkout. Four trials were inconclusive and two survived because the checkout guard intervened. Re-running with sibling fixture and engine directories preserved the guard and exercised all intended controls.

A clean Linux Codex CLI installation and separate offline wheel installation exercised the packaged skills and both engine commands. Desktop UI execution, Windows and independently attested production builds remain unqualified. The recovered baseline and the bounded v2 implementation qualify for draft engineering review.

**Initial public release: BLOCKED — SECURITY OR EVIDENCE GAP.** Original test recovery is now complete. Independent release review, trusted production provenance and the outstanding client compatibility gates remain open. Keep rollback material for the separately pinned previous plugin and engine pair. Neither this candidate nor the historical skills package authorizes a production action.

| Regression scope at the qualified implementation | Observed result |
|---|---|
| Engine discovery | 403 passed, including the 22 R01 tests |
| Skills package and CLI fixtures | 13 passed |
| R00 recovery | 22 passed; six mutations detected and restored |
| WT-ZT-001 | 18 tests passed; all 64 pinned cases reproduced by independent replay |
| WT-ZT-001 mutation accounting | 17 detected, two survived, all 19 restorations matched the original controls |
| Separate v1 baseline and independent probes | 21 and eight passed, respectively |

The final named unittest runs had zero failures, errors and skips. Counts overlap where a suite was also run separately. The Linux Codex CLI installation used 0.172.0-alpha.2, and all five installed plugin files matched their selected Git blobs. The skills ZIP SHA-256 was `11ced64d42ac5778d8c586350a1e3625bfe31d2505437878e3378f5da82c7bb8`. A local CLI test does not establish a desktop UI result.

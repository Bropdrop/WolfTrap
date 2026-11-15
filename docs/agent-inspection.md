# WolfTrap Stage 5.1 — bounded agent trust-boundary inspection

Stage 5.1 adds an offline public-beta static review command
for recognizable JavaScript and TypeScript agent boundaries. It reads local
source as data. It does not execute the application, resolve dependencies,
contact endpoints, invoke a provider, or establish a real-world vulnerability.
The public `scan-build` rules, community Action, and Stage 5 workflow challenge
remain separate and retain their existing behavior.

## Rules and conditional interpretation

| Rule | Supported review signal | Required interpretation |
| --- | --- | --- |
| `WT-AGENT-001` | A recognizable guardrail/classifier operation has a caught error path returning an allow-like result, such as `tripwireTriggered: false`. | A moderation failure can permit output in that local path. Output moderation does not confer tool authorization. Boundary attribution is explicit; uncertain semantics remain inconclusive. |
| `WT-AGENT-002` | A recognizable authentication or approval callback returns literal unconditional success without checking its identity, request, or decision input. | This can be an intentional demo/mock. Every match requires review of its actual use; one stub does not establish that the whole application lacks authentication. |
| `WT-AGENT-003` | A recognizable session token or ephemeral credential is explicitly passed to a supported browser-visible console/debug/event-display sink. | The signal concerns the local source-to-sink pattern. It does not prove delivery to a real browser, credential validity, or exposure in production. |

All signals are `REVIEW_REQUIRED` with `CONDITIONAL_STATIC` confidence. Findings
never receive `CONFIRMED` or an exploitability claim. The report records zero
confirmed vulnerabilities regardless of the number of static matches.

For WT-AGENT-002, demo/mock context is attributed only to the recognized
callback's explicit name, such as `mockAuthenticate` or `demoApprove` (including
the existing `fake` and `stub` prefixes). Comments do not establish that context.
A plain callback name retains `CONTEXT_NOT_ESTABLISHED`; unconditional success
still requires review in either context. Naming alone does not prove deployment
or establish that an application is only a demo.

Meaningful conditional authentication, rejecting guardrail error paths,
non-sensitive logs, and supported redaction patterns are negative controls.
Comments and strings containing code-like text are not executable syntax for
the recognizer. Recognized uncertainty takes precedence over a no-match result.

## Supported scope and containment

The scanner supports selected lexical patterns in `.js`, `.ts`, `.jsx`, `.tsx`,
`.mjs`, and `.cjs` files. A supported extension means the file is considered for
inspection, not that every language construct is understood. `.git` and
`node_modules` are excluded and reported as excluded scope.

The scanner bounds inspection to 64 files, 256 KiB per file, 2 MiB aggregate,
1,024 directory entries, and 12 directory levels. Lexical work is limited to
32,768 tokens and 96 delimiter levels per file; reports retain at most 256
findings before returning an inconclusive result.
Missing inputs, invalid UTF-8, unsupported syntax, malformed input, exceeded
bounds, path escapes, symlinks, and nonregular files produce `INCONCLUSIVE`.
Directory-component and final-component checks prevent source reads through
symlinks. The source is opened read-only, and report output must be a fresh or
empty directory outside the inspected tree. Unsafe output configurations are
refused before report publication.

Bounded rediscovery and a second read of selected files detect ordinary source
changes during inspection. This is not an atomic filesystem snapshot; use a
stable, owner-controlled source checkout for reproducible inspection.

No inspected code, package installer, shell command, network client, browser,
or provider SDK is invoked. The inspector does not read provider credentials.
Its tests block process creation, sockets, and DNS while running the scanner,
and compare fixture bytes before and after inspection.

## Use and exit codes

From an owner-controlled local checkout:

```bash
PYTHONPATH=src python -m wolftrap scan-agent \
  --root /work/owned-agent-source \
  --output-dir /work/wolftrap-agent-evidence
```

The source root must be explicitly chosen by the operator. There is no remote
target option and no automatic network discovery.

Use repeatable `--file relative/path.ts` options for explicit file selection.
Selections are root-relative and must not contain parent traversal or symlink
components. Without `--file`, discovery examines the bounded supported tree.

| Exit code | Status | Meaning |
| --- | --- | --- |
| `0` | `NO_PATTERN_MATCH` | No supported rule matched in the declared inspected scope. This is not a security certification. |
| `1` | `REVIEW_REQUIRED` | At least one conditional static signal requires human review. |
| `2` | `INCONCLUSIVE` | Source, syntax, configuration, coverage, or evidence is unknown or unsupported; no secure result is inferred. |

These codes agree with the established static-inspection convention. They do
not change `scan-build` or the synthetic authorization harness's semantics.

## Evidence and non-disclosure

Each completed scan writes:

- `agent-scan.json`: deterministic coverage, conditional findings, and sanitized
  inspection errors.
- `agent-scan.md`: the human-readable review report.
- `agent-scan.sarif`: SARIF 2.1.0 results for the three agent rules.
- `agent-scan.manifest.json`: completion state, input inventory digest, and the
  exact SHA-256 and byte count for each report artifact.

The manifest starts as `INCOMPLETE` and becomes `COMPLETE` only after all report
artifacts are written. A missing, incomplete, corrupt, or mismatched manifest
invalidates the evidence. Hashes protect artifact integrity; they are not
authentication of the reporter or proof of the application's security.

Reports contain fixed descriptions and structural factors, not source excerpts,
string literals, identifier values, or credential values. Raw relative paths
are also suppressed because filenames can themselves contain sensitive data.
A file location is rendered as `source-<SHA-256(relative-path-UTF-8)><extension>`,
along with the source line. Coverage records the corresponding path digest.
An operator can calculate the digest of a known relative POSIX-style path
locally to locate the source without putting its name in exported evidence.
The inspector does not persist a raw-path lookup file.

Full replayable source is saved only for the independently labelled synthetic
qualification corpus. Its values are inert synthetic placeholders. Real
inspected source is never copied into scan artifacts.

## Qualification and replay

The new corpus independently declares expected rule sets and statuses before
inspection. It includes supported positives, benign negatives, ambiguous or
unsupported forms, and evasion-style formatting and syntax variations. It also
includes bounded filesystem/encoding failures. Expected labels are not computed
from the scanner's observations.

Qualification saves each synthetic input, its expected and observed outcomes,
and evidence digests. Detection misses, false-positive controls, and unresolved
input/classification gaps are reported separately. Sentinel detectors that
report everything or nothing must fail the appropriate controls. Replay reads
the verified saved synthetic case inputs and performs the inspection again.
An absent mismatch is evidence only within this finite declared corpus.

The final candidate must also pass the existing complete regression suite and
the existing 128-case Stage 5 challenge. Actual counts, skips, failures, seeds,
source identity, and artifact checksums belong in the qualification handoff.
An author's synthetic tests do not confer independent hostile-review status.

```bash
PYTHONPATH=src python -m wolftrap challenge-agent \
  --seed 20261115 --output-dir /work/agent-challenge
PYTHONPATH=src python -m wolftrap verify-agent-challenge \
  --evidence-dir /work/agent-challenge
PYTHONPATH=src python -m wolftrap replay-agent-challenge \
  --evidence-dir /work/agent-challenge --output-dir /work/agent-replay
```

Challenge and replay output directories must be fresh. Keep the case records,
report artifacts and completion manifest together when transporting evidence.

## Known limitations and remaining review

This is a bounded lexical inspector, not a JavaScript/TypeScript compiler or a
complete program-flow analysis. It does not establish callback reachability,
effective framework configuration, production deployment, identity policy,
current authority, real credential sensitivity, or runtime browser exposure.
Cross-module and arbitrary interprocedural alias/data flow are outside scope.
Relevant credential reassignment, member mutation and unsupported scope
transitions are treated as unknown rather than inferred safe.
Template interpolation, JSX syntax, unresolved computed access and other
unrecognized relevant constructs can make inspection inconclusive. Renaming or
framework wrappers outside the explicit recognizers may remain detection gaps.

No match is proof of security. A review signal is not proof of exploitation.
Manual source review must establish the actual boundary and use conditions.
Output moderation and authentication callbacks do not substitute for current
authorization of a protected tool effect. The laboratory continues to require:

- No current authority means no protected effect.
- Verified does not mean authorized.
- Authorized does not mean executed.
- Unknown source or ambiguous security evidence fails closed.

Public publication, a public branch or PR, merge, deployment, live target
testing, and paid model calls remain outside this confidential milestone.

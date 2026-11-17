# Cloud-C2 challenge: GitDoor-inspired synthetic controls

Status: **experimental, offline, non-malware, not an infection detector**.

## Evidence and provenance

Kaspersky GReAT described Operation ShadowCloud on November 17, 2026. Its
GitDoor analysis reports a cloud command-and-control pattern involving
GitHub issue creation, changing an issue's `bug` label, polling repository
content, and uploading encrypted results with filenames that resemble
JavaScript source maps. The original report supplies observation context;
**no attack sample or third-party infrastructure is included here**.

- [Kaspersky — GitDoor and initial intrusion](https://securelist.com/operation-shadowcloud-gitdoor/122004/)
- [Kaspersky — GraphDoor and attribution limits](https://securelist.com/operation-shadowcloud-graphdoor/122005/)
- [Sophos — related BRONZE SANDCASTLE research](https://www.sophos.com/en-gb/blog/bronze-sandcastle-deploys-modified-meterpreter-shells)

The exercise does not attribute actors, prove an active intrusion, or assume
that every use of GitHub, Microsoft Graph or SharePoint is suspicious.

## Scope

`wolftrap challenge-cloud-c2 --output-dir /new/empty/directory` replays an
eight-case synthetic corpus against two narrow conditional signatures:

| Rule | Synthetic correlation | Conclusion |
| --- | --- | --- |
| `WT-CLOUD-C2-001` | One synthetic process session creates an issue, adds a label, polls repository content, removes a label, and polls again within 200 **logical** ticks | `REVIEW_REQUIRED` only |
| `WT-CLOUD-C2-002` | One synthetic process session creates an issue, polls content and subsequently writes an artifact classified upstream as source-map-like within the same window | `REVIEW_REQUIRED` only |

Inputs to the pure detector contain only `{at, actor, kind}` with a fixed set
of action kinds and `synthetic-session://` actors. The detector is **not** a
network sensor. It does not parse GitHub audit logs or identify real addresses,
API credentials, command bodies or malware. That would require a separate
trusted event-normalization and data-handling design before deployment.

The eight authored cases cover complete and partial suspicious sequences,
ordinary issue triage, routine source-map generation, unrelated actors and
events beyond the correlation window. These are regression controls, **not**
representative measurements of true/false positive rates. An all-denying
detector fails the challenge's positive controls.

The unit suite separately exercises WolfTrap's existing synthetic authority
system: a signed authorization tied to a different origin cannot grant a
cloud-origin request a protected effect; a legitimate positive control must
still commit once. This is a boundary regression, not a demonstration of
protection on GitHub, Windows or a live HERCULES deployment.

## Security constraints and interpreting results

- The new challenge uses no network, subprocess, sample execution or live service.
- It accepts no external URL, hostname, token, arbitrary payload or command.
- Inputs and output artifacts use only fixed synthetic events, aliases and labels.
- The output directory must be empty; reports have fixed names and an integrity manifest.
- `verify-cloud-c2` independently regenerates the corpus and compares the artifacts.
- `PASSED_BOUNDED` means the eight saved controls matched their authored expectations;
  it does not indicate threat coverage, detection effectiveness on endpoints,
  or security certification.
- A benign automated workflow can resemble a signature; other hostile cloud
  command channels can evade both. Detection would require endpoint and
  cloud-side behavior telemetry, provenance, and human review.

For real incident response, use the researchers' published indicators only
with appropriate authorization, keep suspicious samples quarantined, and do
not access or interact with suspected live attacker infrastructure.

## Offline normalized event review (second, narrower stage)

`wolftrap scan-cloud-trace` adds **conditional correlation** across a process or
credential session, an issue in a result repository, and a distinct command
repository. It is not a live GitHub client or an importer for raw HTTP/audit
logs. The source must be *already sanitized* by an authorized analyst from
trusted telemetry. No attack infrastructure or third-party source code is used.

```bash
wolftrap scan-cloud-trace --root /path/to/sanitized --file events.json \
  --output-dir /path/to/new/evidence
wolftrap verify-cloud-trace --root /path/to/sanitized --file events.json \
  --evidence-dir /path/to/new/evidence
```

The file `events.json` uses schema `wolftrap.normalized-cloud-trace/v1`:

```json
{
  "schema": "wolftrap.normalized-cloud-trace/v1",
  "events": [
    {"at": 1, "session": "session-a", "repository": "results-a", "issue": "issue-a", "kind": "issue_create"},
    {"at": 2, "session": "session-a", "repository": "results-a", "issue": "issue-a", "kind": "bug_label_add"},
    {"at": 3, "session": "session-a", "repository": "commands-b", "issue": null, "kind": "repo_poll"},
    {"at": 4, "session": "session-a", "repository": "results-a", "issue": "issue-a", "kind": "bug_label_remove"},
    {"at": 5, "session": "session-a", "repository": "commands-b", "issue": null, "kind": "repo_poll"},
    {"at": 6, "session": "session-a", "repository": "results-a", "issue": null, "kind": "source_map_put"}
  ]
}
```

Only the **six** fixed kinds `issue_create`, `bug_label_add`, `bug_label_remove`,
`repo_poll`, `source_map_put` and `other` are accepted. `at` is a monotonic
logical integer in the range 0–10,000, not a timestamp; windows are 200
logical ticks, **not** an inferred one-hour interval. The file is bounded to
64 KiB and 128 events. The issue alias is required only for issue events and
must otherwise be null. All aliases are opaque, 2–32 character lowercase
letters/digits/underscore/hyphen beginning with a letter. Bare URLs, tokens,
usernames, domains, raw source-map content and unknown properties are rejected.

| Rule | Requires within one trusted session | Output |
| --- | --- | --- |
| `WT-CLOUD-C2-003` | One issue in the result repository has a bug-label add, poll of a different repository, bug-label removal and repeat poll of the **same** command repository | `REVIEW_REQUIRED` |
| `WT-CLOUD-C2-004` | An issue is created in the result repository; a distinct command repository is polled, then the result repository receives a source-map-classified upload | `REVIEW_REQUIRED` |

Reports contain SHA-256-derived session and repository-pair aliases, rule IDs,
and an integrity manifest; no original event aliases or trace content are
copied. Use a **fresh empty** evidence directory **outside** the source tree.
The `verify-cloud-trace` command independently re-reads the local source and
recomputes report artifacts. Replacing the source or editing artifacts fails
verification. Its reported source identity is explicitly **unverified**.

GitHub organization audit logs by themselves may not include each repository
read or API request. GitHub says `api.request` events require **enterprise
audit log streaming with API request event streaming enabled**. Thus a
complete sequence should **not** be inferred from missing org audit-log
entries alone. See [GitHub's enterprise audit log guidance](https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/accessing-the-audit-log-for-your-enterprise).

The hostile regression cases prevent joining unrelated sessions, issues,
command repositories or unordered/out-of-window activity. They do **not**
authenticate upstream session provenance, measure production false-positive
rates, establish attribution, or demonstrate a real-world infection. A benign
build or automation can produce similar events; an attacker may avoid the
specific sequences entirely. A clean scan is **not** clearance.

## Adversarial camouflage experiment

The next stage tests the **limits** of these correlations, using the same
strictly sanitized, metadata-only schema. Everything is generated locally and
the expected labels are authored independently of the detector under test.

```bash
wolftrap challenge-cloud-camouflage --output-dir /new/empty/evidence
wolftrap verify-cloud-camouflage --evidence-dir /new/empty/evidence
```

There are 20 distinct event-sequence templates exercised under eight identity,
logical-time and timing-scale variations, for 160 deterministic cases:

| Synthetic group | Cases | What is measured |
| --- | ---: | --- |
| Pattern-positive controls | 40 | Whether the two narrow rules still match their authored signatures |
| Benign negatives | 40 | Whether incomplete or unrelated ordinary activity stays unflagged |
| Benign automation lookalikes | 40 | How a *benign-by-construction* sequence can still trigger a suspicious pattern |
| Threat-inspired evasion variants | 40 | Known blind spots such as command-repository rotation, issue mismatch, session separation, unclassified uploads and activity beyond the window |

The last two groups are **not errors in the test harness**: they expose the
limits of metadata-only correlation. A `PASSED_BOUNDED` result means the
observed rule IDs equal the **author-assigned expectations** across the corpus,
including the intentionally flagged lookalikes and unflagged evasions. An
all-denying or all-flagging detector is caught by separate hostile tests.

Do not interpret these authored proportions as a measured false-positive rate,
true-positive rate, detection probability or representative attack sample.
The source never contains malware, credentials, URLs, actual GitHub accounts,
attacker instructions or live cloud telemetry. The saved JSON and Markdown
reports are independently regenerated and checked against SHA-256 manifest
entries by `verify-cloud-camouflage`.

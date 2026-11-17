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

`wolftrap challenge-cloud-c2 --output-dir /new/empty/directory` replays a
eight-case synthetic corpus against two narrow conditional signatures:

| Rule | Synthetic correlation | Conclusion |
| --- | --- | --- |
| `WT-CLOUD-C2-001` | One actor creates an issue, adds a label, polls repository content, removes a label, and polls again within 200 **logical** ticks | `REVIEW_REQUIRED` only |
| `WT-CLOUD-C2-002` | One actor creates an issue, polls content and subsequently writes an artifact classified upstream as source-map-like within the same window | `REVIEW_REQUIRED` only |

Inputs to the pure detector contain only `{at, actor, kind}` with a fixed set
of action kinds and `synthetic-host://` actors. The detector is **not** a
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

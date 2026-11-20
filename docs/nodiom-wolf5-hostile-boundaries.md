# Wolf #5 — Hostile Nodiom state and MCP boundary review

## Research scope

Only public open-source code at pinned source commits, using fabricated local Markdown files inside disposable, network-disabled containers. No Synexiom Cloud, accounts, OAuth, hosted APIs, customer data or live systems were contacted. The outcome does not establish exploitation of a deployed service.

The two source pins remain:
- Nodiom core: 335de4d79ed9b64e8f679fe13a088c7c503525f0
- Nodiom MCP: 469aa971ea0d836d4428f977bd05790168a1fc5f

The suite is stacked on WolfTrap draft PR #18 and leaves Codex's parallel integration work, main and the independent public guard untouched. All changes are draft and unmerged.

## Adversarial controls

11 core library checks cover mixed locked/unlocked writers, symlink redirection after lock acquisition, lock handling on load/save errors, positional selectors retargeted after deletion, content-selector marker reassignment, ambiguity rejection, frontmatter fidelity, editable headings, and versionless stale-snapshot saves.

10 genuine MCP checks cover repeated identical appends, caller-supplied absolute paths and symlinks, acceptance of Markdown syntax in files with arbitrary extensions, error response content, preservation of untrusted text, review-named section deletion, duplicate-heading rejection, cross-agent stale positional selectors and structural heading introduction.

A separate stratified stress matrix uses two, four and eight local MCP server processes for eight rounds each (24 rounds per build). Both the pristine upstream server and the experimental test-only locked build run the same matrix. Every agent writes a unique marker. The reports retain each round's successful calls, retained markers and final document digest. A fully successful call whose marker disappears is a proven local lost update for that particular revision and schedule; no Cloud claim is warranted.

## Interpret carefully

- Local file-path access is a documented property of the stdio adapter, not itself proof of a sandbox escape.
- File symlink swapping requires the adversary to possess local control of the linked pathname; the test does not grant that capability to a remote user.
- A Markdown document's embedded approval text and content selectors are not independently authenticated authority.
- Duplicate appends show non-idempotent retry behavior, not necessarily a vulnerability.
- The local MCP adapter is not the Nodiom Cloud service. A host might implement its own authorization and review gates.
- A successful advisory-lock regression does not establish crash atomicity, authenticated identity or multi-machine consistency.
- Local error paths and fixture strings are synthetic. The suite never prompts a model; it cannot establish successful prompt injection.

## Evidence gate

Require completed exact-head hosted qualification, pinned source hashes, all JSON report files, integrity digest manifest, positive controls and no inconclusive cases before making claims. Review any security-significant findings and disclose privately before publishing reproduction details.

The pre-existing WolfTrap public-source guard flagged the npm install in this research CI as unreviewed. This is a genuine guard finding, not an excuse to disable it. PR #18 and this stacked research PR must remain drafts while that policy gate is unresolved.

# Go authority-boundary inspection — bounded offline preview

This is a **read-only lexical triage** mode for local Go source. It highlights
four recognizable tool-authorization and egress patterns so a human can inspect
the actual trust chain. It does not run or compile Go, contact an LLM or network
target, or execute a test against the inspected application.

## Use

With Python 3.11+ and an authorized local checkout:

```bash
wolftrap scan-go-authority --root /path/to/authorized-repo \
  --file server/tool.go --file guard/hooks.go \
  --output-dir /tmp/wt-go-review
wolftrap verify-go-authority --evidence-dir /tmp/wt-go-review
```

Use an initially empty output directory outside the inspected tree. Without
`--file` the scanner walks supported `.go` inputs within fixed limits: at most
64 files, 1,024 directory entries, depth 12, 256 KiB per file and 2 MiB total.
Large Go repositories will often need explicit selection or a smaller root.
Out-of-bounds, missing, symlinked, corrupt or unstable input is `INCONCLUSIVE`,
not a clean result.

The inspected repository and its test code are **never executed**. Go itself is
not required. The scanner uses Python's standard library, descriptor-relative
no-follow reads, fixed bounds and atomic evidence publication.

## Four conditional review patterns

| Rule | What it recognizes | What it cannot establish |
| --- | --- | --- |
| `WT-GO-001` | A `Permissions: func(...)` callback consisting solely of `return permission.Allowed()` | Whether independent host authority is enforced elsewhere |
| `WT-GO-002` | A named Go function using `exec.Command`/`CommandContext`, assigning a child's environment from `os.Environ()`, then invoking it | Whether OS/container sandboxing, capabilities or egress filtering constrain that child |
| `WT-GO-003` | A named function returning an HTTP proxy transport before later configuring a pinned direct dialer | Whether that proxy independently validates the actual upstream connection |
| `WT-GO-004` | An intercept/guard-like named function returning an empty `hook.Result{}` when two gate/rule conditions are disabled | Whether the empty result means approval in the consuming runtime, or whether a mandatory outer gate exists |

Each pattern has positive and benign negative controls. Comments and quoted
strings are masked before source matching. Go function and callback grouping is
bounded and incomplete; complicated signatures and indirect aliases may evade
these patterns. A rule may be a deliberate, benign design choice. Conversely,
no match cannot prove that a protected effect is controlled.

This mode does **not** detect malicious ARTEX deployments, assert an attacker
has access to a given tool, determine scopes for private networks, verify the
identity of an approving human, or prove revocation/replay behavior. Testing
these properties requires an authorized independent runtime effect ledger and
network-isolated conformance harness.

## Evidence and interpretation

`scan-go-authority` creates four files:

- `go-authority-scan.json` — conditional signals and declared coverage;
- `go-authority-scan.md` — review summary;
- `go-authority-scan.sarif` — source-alias/line-based warnings;
- `go-authority-scan.manifest.json` — unsigned SHA-256 byte bindings.

Original source text, credential values, target URLs and actual paths are
excluded. Locations are root-relative **path hashes** plus line numbers;
the person holding the checkout can map them locally. Every scanner report says
that zero vulnerabilities have been confirmed.

| Status | Exit code | Meaning |
| --- | ---: | --- |
| `NO_PATTERN_MATCH` | 0 | Supported inputs inspected; no supported rule matched, **not safety certification** |
| `REVIEW_REQUIRED` | 1 | Conditional pattern(s); investigate the authority/egress chain |
| `INCONCLUSIVE` | 2 | Unsupported, incomplete or unsafe input; cannot issue an all-clear |

`verify-go-authority` returns 0 only after validating the closed manifest,
report schema, SHA-256 hashes and deterministic Markdown/SARIF rendering. A
matching unkeyed digest is not publisher authenticity. Scanning a frozen
source revision again into a fresh directory provides the separate saved-input
replay control.

The public GitHub Action continues to run **only** the existing CI/build scan;
Go inspection is an opt-in local command. There is no automatic protected-effect
blocking or production agent connection.

For a potentially novel upstream vulnerability, follow the project's private
responsible-disclosure policy. Do not publish third-party exploit details.

# WolfTrap Stage 5.2 — conditional protected-effect inspection

## Qualification boundary

`scan-effects` is a **separate, offline, read-only lexical source reviewer**.
It does not start an agent, execute a tool, access live secrets, test a target,
or determine runtime authorization. Every signal is `REVIEW_REQUIRED`, with
`CONDITIONAL_STATIC` confidence. No match means only `NO_PATTERN_MATCH` for the
supported grammar. Unsafe/unknown/incomplete input means `INCONCLUSIVE`.

Stage 5.2 was informed by three **authorized, read-only** source reviews:

| Source checkpoint | Observed, conditional design boundary | Stage 5.2 review area |
| --- | --- | --- |
| `GoogleChrome/modern-web-guidance-src` `5e5cd33a7738f21281e3027732bcbd58cfa82bf1` | Agent `--yolo`, host `.codex` copy, explicit unsafe sandbox bypass; broad Linux host mounts and unresolved network isolation | Launch, host secrets, bypass, filesystem/network |
| `deepseek-ai/chat-demo` `5d5dd754ebc1948e977ddb880a9eb5aa25f37b4c` | Documented browser BYOK design, `localStorage` key and browser-origin auth headers | Browser key persistence and transmission |
| `google-labs-code/stitch-skills` `0337446dadde6f8c94210444e2aa9d546126480f` | Skill asks agent to extract MCP config keys and upload; wildcard tools; variable API origin and CLI secret; limited URL filtering and response-size checks | Agent instructions, upload, SSRF/resource review |

These reviews are **not** exploit verification. For example, Stitch's upload
skill explicitly requires user confirmation, a positive documented step.
An instruction to ask is not an enforceable authority gate by itself. DeepSeek's
browser key is an explicit bring-your-own-key design choice. Chrome's harness
has other sandbox safeguards not modeled by this lexical scanner.

## Conditional pattern catalogue

| Rule | Review condition, not a proved vulnerability |
| --- | --- |
| `WT-EFFECT-001` | Recognized unrestricted flag (`--yolo`, `--dangerously-skip-permissions`, etc.) in bounded JS/TS, Python or shell command construction |
| `WT-EFFECT-002` | Host agent credential directory/file name correlated with a filesystem copy source in JS/TS, Python or shell |
| `WT-EFFECT-003` | Explicit environment-controlled sandbox bypass in JS/TS, Python or shell |
| `WT-EFFECT-004` | `--dev-bind / /`-style whole-root bind with no local network namespace marker; network isolation elsewhere is unknown |
| `WT-EFFECT-005` | API credential key or `KEYS.apiKey` correlated with browser `localStorage` read/write, not just appearing elsewhere in the file |
| `WT-EFFECT-006` | Browser fetch plus API key in a named auth header value (including quoted keys or `Headers.set`) |
| `WT-EFFECT-007` | URL host safety checker, literal private-host filtering, and HTTP fetch without a recognized hostname-linked DNS lookup marker |
| `WT-EFFECT-008` | Response chunk aggregation without a recognized byte ceiling |
| `WT-EFFECT-009` | `SKILL.md` instructs MCP config key extraction and upload; evidence notes recognized user confirmation |
| `WT-EFFECT-010` | `SKILL.md` tool frontmatter declares wildcard scope and Bash |
| `WT-EFFECT-011` | `SKILL.md` imperatively claims to override trusted instructions or suppress approval |
| `WT-EFFECT-012` | Python outbound uploader combines CLI `--api-key`, selectable `--api-url` and auth header without a recognized host allowlist |
| `WT-EFFECT-013` | Shell `curl -L` / `--location` with output to a variable destination and no recognized `--max-filesize` byte bound. A timeout or redirect-protocol rule alone is not a byte cap |

Every rule is a conservative lexical correlation. Naming or syntax variants,
split-file effects, permission handling in another module, DNS resolution
outside the scanned file, and complex control flow can be missed. A rule match
does not prove the action is callable, reachable, unapproved, or exploitable.
Agent instructions cannot grant themselves capability or override owner policy.

## Use

```bash
wolftrap scan-effects --root /path/to/authorized-source \
  --output-dir /tmp/wolftrap-effects
wolftrap verify-effects --evidence-dir /tmp/wolftrap-effects

# Or select exact source files to stay inside bounded inspection:
wolftrap scan-effects --root /path/to/authorized-source \
  --file src/agents/runner.ts --file plugins/upload/SKILL.md \
  --output-dir /tmp/wolftrap-effects-selected
```

- Inputs: `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs`, `.cjs`, `.py`, `.sh`, and
  **only `SKILL.md`** for Markdown. Unsupported files do not silently receive
  security coverage. Source roots and file components cannot be symlinks.
- Limits: maximum 64 files; 256 KiB per file; 2 MiB aggregate; 1,024 directory
  entries; depth 12; at most 256 findings. Exceeding a bound is inconclusive.
- Evidence: `effect-scan.json`, `.md`, `.sarif`, and `.manifest.json`, written
  to a fresh directory outside the target. Reports contain only fixed labels,
  line numbers, and SHA-256 root-relative path aliases, never source text or
  credentials. Manifest hashes are **unsigned consistency checks**, not
  provenance authentication.
- Exit statuses: `0` no recognized pattern, `1` conditional review needed,
  `2` incomplete/unsafe/unknown. `verify-effects` checks saved evidence
  consistency without reading the original source.

## CI location repair

The Stage 3 build scanner now uses YAML scalar source marks to locate each
`uses:` action step and `jobs` key. Repeated `actions/checkout@v4` and
`actions/setup-node@v4` in multiple jobs yield distinct locations and findings.
The repair does **not** imply comprehensive source attribution for every other
Stage 3 factor, some of which still use first-occurrence text lookup. The
existing Stage 3–5 and Stage 5.1 semantics remain separate.

## Review questions after a finding

1. What is the trusted authority controlling the action, and is it enforced
   outside any agent-generated instructions?
2. Can the agent access host credentials or unscoped filesystem/network
   capabilities while executing this action?
3. Does outbound upload/download bind approved destination, payload identity,
   maximum bytes, and explicit user authorization?
4. Can a denial, revocation, crash, retry, or competing agent cause a protected
   effect anyway? Verified computation **does not** itself mean authorized.

No live target was exploited, and neither the new lexical rules nor unit tests
replace an independently authored hostile holdout corpus or live qualification.

### Local hostile regression, 2026-11-15

A separately stored, **author-created** synthetic corpus challenged exact
Stage 5.2 checkpoint `451230128a615e501457910453dfa6e4a697aee4`.
The original 50 cases exposed 18 pattern misses; an additional 12 cases exposed
eight false positives. This local repair addresses the demonstrated cases;
both frozen corpora later matched **62/62** labels (37 positive signals,
25 benign negatives). This is a finite self-review, **not independent hostile
qualification** and not an empirical real-world exploit-detection rate.

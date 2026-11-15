# WolfTrap Stage 5.3 — untrusted prompt-document inspection

Stage 5.3 adds `scan-prompts` and `verify-prompts` without changing the Stage 5.1
`scan-agent` or Stage 5.2 `scan-effects` contracts. It is a **read-only lexical
triage** of local text documents, not a model, prompt interpreter, runtime
attack, source attribution service, or authority broker.

## Usage

```bash
python -m wolftrap scan-prompts --root /path/to/authorized/source \
  --output-dir /path/to/new/evidence
python -m wolftrap verify-prompts --evidence-dir /path/to/new/evidence

# To limit scope to one known file:
python -m wolftrap scan-prompts --root /path/to/source \
  --file README.md --output-dir /path/to/new/one-file-evidence
```

Use a pinned target repository revision. The evidence directory must be fresh
and outside the source. Paths are read through directory descriptors with
`O_NOFOLLOW`; symlinks and changed inputs fail closed. No target code or agent
tool is run. No source text, path names, prompt excerpts, API keys or URL values
are saved in evidence.

## Supported documents and fixed bounds

- `.md`, `.txt`, `.mkd`, `.json`, and extensionless regular UTF-8 text.
- JSON parsing must be valid. JSON **string values** are decoded for inspection;
  JSON keys, numbers and structural syntax are not scanned as instructions.
  Escaped newlines within a JSON string report that string's physical source line.
- Maximum **128 supported documents**, **2 MiB** each, **24 MiB** total.
- Maximum **2,048 directory entries**, depth **12**, **1,024 findings**.
- Unsupported extensions and the excluded `.git`/`node_modules` directories
  are counted as excluded/unsupported, not interpreted. A claim of complete
  input applies **only to the declared supported scope**.
- Binary/NUL content, invalid UTF-8, limits, source changes and symlinks produce
  `INCONCLUSIVE`, never a silent pass.
- Markdown fenced blocks, blockquotes, inline quotes and certain labelled
  examples are intentionally skipped to reduce alert noise. That creates
  known opportunities for false negatives. No grammar can classify whether
  quoted instructions are dangerous when the consuming agent's trust boundary
  is unknown.

## Fixed rule vocabulary

| Rule | Conditional source-text signal |
| --- | --- |
| `WT-PROMPT-001` | Direct attempted override of higher-priority instructions |
| `WT-PROMPT-002` | Request to disclose the reader's governing instructions |
| `WT-PROMPT-003` | Untrusted document claiming higher instruction priority |
| `WT-PROMPT-004` | Correlated credential extraction and outbound transfer request |

Findings mean **REVIEW_REQUIRED**, not a vulnerability or exploit. In particular,
a public collection of allegedly leaked system prompts can contain ordinary
instructions and defensive examples that resemble attacks. No filename,
line count, purported role marker or GitHub publication authenticates the
content as a vendor's genuine full system prompt. Human context review remains
necessary before any external claim.

## Provenance and regression target

The new mode was motivated by a read-only observation in the public repository
[`elder-plinius/CL4R1T4S`](https://github.com/elder-plinius/CL4R1T4S),
commit `93a584765460c2fb0ad58380bba476f2149df138`, tree
`e212b165a83321d59a716be594e11f8df46bde9f` (2026-11-15 observation).
Its `README.md` lines 39–43 contain obfuscated, self-elevating instructions
requesting the reader's own instructions. The earlier Stage 5.2 scanner
correctly returned `INCONCLUSIVE` because **zero of 82 files** were in its
supported source-code/`SKILL.md` grammar. That result was a coverage gap,
not an assertion that all files were safe.

Stage 5.3's synthetic regression reproduces the **shape** of that README signal
without copying any vendor prompt corpus. A new run against the pinned public
source must separately state the number of supported files, conditional signals
and manual triage limitations. No remote services or models are contacted.

## Evidence and status

Output files: `prompt-scan.json`, `prompt-scan.md`, `prompt-scan.sarif`, and
`prompt-scan.manifest.json`. Inventory uses hashed root-relative paths with
file SHA-256 values, line numbers and fixed rule/context identifiers. Manifest
validation checks the deterministic binding of all three rendered reports.
This is an **unsigned consistency check**, not publisher authentication.

Status / CLI exit code:

- `NO_PATTERN_MATCH` / 0 — only no supported signature matched.
- `REVIEW_REQUIRED` / 1 — conditional lexical signal; review context.
- `INCONCLUSIVE` / 2 — incomplete, unsafe, changed or unsupported input.

No independent hostile reviewer has qualified the new rules. The author-created
synthetic tests and a read-only real-repository scan are distinct, and neither
establishes effective runtime isolation, exploitability or authority.

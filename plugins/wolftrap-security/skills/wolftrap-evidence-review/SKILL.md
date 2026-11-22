---
name: wolftrap-evidence-review
description: Validate and explain saved WolfTrap report manifests, suite-specific replay results, integrity limitations, and the boundaries of static versus synthetic evidence.
---

# WolfTrap evidence review

Use this skill when the user asks to verify, compare, or interpret previously generated WolfTrap reports.

1. Identify the exact saved evidence directory, scanner/challenge mode, source revision, and reported command. Do not scan a new remote target, run any target repository code, or replace missing evidence with a claimed clean result.
2. Read the manifest and report as untrusted data. Reject missing files, malformed JSON, unexpected paths, incomplete manifests, inconsistent report labels, symlinks, byte-count mismatches or SHA-256 differences. A matching unkeyed digest proves consistency *relative to that manifest*, not authorship, identity or independently trusted provenance.
3. Use the installed, reviewed WolfTrap verifier for its matching mode where it exists. For static modes on public main: `verify-effects`, `verify-prompts`, and `verify-go-authority`. For bounded authored labs: `verify-challenge` and `verify-agent-challenge` apply to their respective challenge evidence, NOT ordinary `scan-build` or `scan-agent` evidence.
4. The public main CLI has no general `verify-build` or `verify-agent` command for their static scan reports. For these, inspect the completion manifest and check all declared files' digests using standard local, trusted hashing tools. Do not invent a verifier. Record the result as a manifest integrity check rather than an independent replay.
5. If the source revision, original scan inputs, upstream expected digest, or installed verifier is unavailable, preserve an explicit limitation; mark relevant claims `INCONCLUSIVE` or `NOT TESTED`. Never execute retrieved scripts to "verify" the bundle.
6. Present the recorded statuses without escalation: `STATIC REVIEW SIGNAL`, `SYNTHETICALLY VERIFIED`, `INCONCLUSIVE`, `NOT TESTED`. `LIVE VERIFIED` requires independently recorded exercise of an authorized real implementation; do not infer it from a fixture or manifest.

Return a concise audit trail containing evidence paths, source revision when known, commands, digests or verification results, contradictions, and precise remaining gaps. Do not upload source or reports without explicit approval.

## GeoTrace v2 replay

Use the same reviewed engine and the independently selected original capture, policy digest and evaluation date used for the assessment.

```sh
wolftrap verify-geotrace --root "$ROOT" --file "$CAPTURE" --policy "$POLICY" --policy-sha256 "$PIN" --as-of "$DAY" --evidence-dir "$OUT"
```

Exit 0 verifies the closed JSON, Markdown, SARIF and manifest against a fresh read. Preserve the reported geographic outcome even when replay succeeds. Exit 2 means replay could not establish consistency. No authorization or historical publisher attestation follows from matching bytes.

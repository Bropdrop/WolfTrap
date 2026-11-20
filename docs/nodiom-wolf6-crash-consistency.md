# Wolf #6: Nodiom local crash consistency and Markdown fidelity

## Evidence boundary

This is a local defensive qualification of the genuine public Nodiom core and MCP repositories, run at immutable source revisions in a disposable Docker environment with runtime network access disabled. No Synexiom Cloud service, third-party user data, account, credential, or production endpoint is touched.

- Nodiom core: 335de4d79ed9b64e8f679fe13a088c7c503525f0
- Nodiom MCP: 469aa971ea0d836d4428f977bd05790168a1fc5f
- Parent Wolf #5: feat/nodiom-wolf5-hostile-boundaries
- This work is a stacked draft research branch and MUST NOT MERGE while WolfTrap's independent public policy guard remains red on the unreviewed npm research installation.

## Test categories

1. **Truncate-before-error:** Replace only the synthetic fixture's Node file-write implementation with a deterministic failing writer that truncates the file and returns an injected EIO to the genuine Nodiom save path. Measure the original and resulting digests.
2. **Partial-write-before-error:** Inject a short write followed by EIO at the same file-operation boundary. Record whether the old document is recoverable without a backup.
3. **Process SIGKILL after partial write:** Start a genuine Nodiom child writer, deliberately halt itself after an instrumented truncated write, inspect partial bytes and any abandoned advisory lock. This is process termination with fault injection, **not power-loss qualification**.
4. **Independent atomic-write reference:** Compare before-rename, after-rename and fully completed reference replacement using temporary file, per-file sync, rename and parent-directory sync. This reference is not a Nodiom patch and cannot establish behavior across a hardware power cut.
5. **Source-level durability review:** Record the exact save implementation digest, direct in-place write, and absence/presence of explicit sync and revision checks in the pinned source. Source scanning alone cannot establish filesystem guarantees.
6. **Reload after interrupted save:** Observe whether the source parser can load a truncated synthetic document; parser acceptance is not evidence of semantic recovery.
7. **Metamorphic Markdown corpus:** 512 deterministic fictional documents varying CRLF, frontmatter, content types, code fences, Unicode, trailing whitespace and empty sections. Check the documented read/write no-op fidelity claim, unaffected sibling sections, and frontmatter preservation, with SHA-256 mismatch samples instead of raw payloads.

## Interpretation and claims

A successful RPC response does not imply crash-safe persistence, but our tests do not perform actual disk power failure. A forced SIGKILL interrupts only the process, not the host kernel, filesystem journal or disk cache. The special instrumented failure points model what a partial OS write could expose; they are **not** spontaneous failure reproduction on ordinary Nodiom installations.

The separate atomic reference tests demonstrate one repair design, not a verified vendor patch. Final severity depends on deployment constraints, data criticality, backup and restoration mechanisms, and whether Synexiom Cloud provides stronger transactions.

WolfTrap main, Codex's active work, existing research evidence and the source guard must remain unchanged. No public vendor disclosure should be inferred from this draft.

# WolfTrap Security plugin upgrade policy

WolfTrap Security is one stable plugin identity with a separately governed security engine.

## Independent release tracks

- Plugin identity: wolftrap-security. Bump the version in plugin.json when publishing changed skills, instructions, or metadata. Upload the complete replacement ZIP to the **same** existing listing; run automated checks and any required review before publishing.
- Engine identity: an explicitly qualified WolfTrap commit/release and its reviewed dependencies. A scanner-rule update that retains the exact compatible CLI and evidence format does not necessarily require new plugin skills. A new command, new verifier, changed input/output schema, or new security permission DOES require updated skill instructions and tests.
- Always pin and record the exact engine source and package release; never silently switch to the newest draft branch. Preserve rollback to the previous independently qualified version.
- Status labels remain scoped: STATIC REVIEW SIGNAL, SYNTHETICALLY VERIFIED, INCONCLUSIVE, NOT TESTED. Passing synthetic tests does not certify live attack prevention.

## Upgrade gates

1. Qualify new modules independently against a precise source SHA, including adversarial fixtures and negative controls.
2. Integrate them into a governed, versioned engine candidate. Preserve existing CLI contracts or write an explicit migration.
3. Extend plugin skills and compatibility tests only for capabilities actually present in that qualified engine.
4. Run the existing offline fixture suite, evidence-verifier and tamper tests, permissions/path tests, and clean installation test.
5. Increment the plugin manifest version as needed, build and review a complete ZIP, submit it to the **existing** plugin, resolve findings, and publish the approved replacement. Do not replace a published version until review succeeds.

## Supported upgrades

Re-run the clean desktop installation and the five public CLI mode checks before adopting a different engine revision. The current package and verifier pins are in the plugin README.

[OpenAI submission](https://developers.openai.com/plugins/deploy/submission) · [Desktop-only plugins](https://developers.openai.com/plugins/deploy/desktop-only)

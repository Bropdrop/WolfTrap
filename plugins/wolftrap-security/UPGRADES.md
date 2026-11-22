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

## Critical MCP decision

As of November 2026, OpenAI's submission guidance says you cannot add an MCP server to a plugin already submitted as skills-only. PR #28 is still a draft and has NOT been submitted, so adding a local or remote MCP adapter before first submission remains an option. Local MCP submission has an eligibility and review process. Alternatively, publish the skills-only plugin and later distribute MCP as a separate plugin.

For hosted MCP plugins, eligible tool-server updates can pass through continuous scanning without a new plugin ZIP; changes to bundled skills and metadata still require an updated ZIP, review, and publication. Server-origin changes have additional restrictions.

## Candidate versions and deferred work

- 0.1: Public-main offline scanners and evidence review
- 0.2: R01 offline GeoTrace v2 scan and evidence replay with the separately pinned 0.6.0 engine. MCP Bloodhound remains deferred pending its independent release gate.
- 0.3: Cursorial and WolfPrint after integration tests
- 0.4: WolfNet signed registry after qualification
- 0.5: WolfAlibi receipt review through a separate trust boundary
- 1.0: Fully qualified composition, only if demonstrated by evidence

No future version number guarantees an implementation, funding, acceptance, or security certification.

Official references:
https://developers.openai.com/plugins/deploy/submission
https://developers.openai.com/plugins/deploy/desktop-only
https://developers.openai.com/plugins/deploy/app-review

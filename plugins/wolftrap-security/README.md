# WolfTrap Security plugin v0.1.0 (candidate)

A skills-only, **desktop/local-executor-required** Agent Plugins package for supported Codex and ChatGPT desktop environments. Cloud-only sessions cannot be assumed to access local files or execute this CLI. It orchestrates WolfTrap's *existing* CLI. It does not contain an MCP server, grant remote access, install the WolfTrap engine, or publish anything to the public Plugins Directory.

## Contents

- `plugin.json`: portable Agent Plugins 1.0.0 manifest and OpenAI presentation metadata.
- `skills/wolftrap-audit/SKILL.md`: authorized local offline scans and status reporting.
- `skills/wolftrap-evidence-review/SKILL.md`: evidence integrity/verification review.
- `../../.agents/plugins/marketplace.json`: a repository-local plugin directory entry.
- `tests/test_package.py`: dependency-free package contract tests.

## Requirements and security model

Python 3.11+ and a separately installed **reviewed and commit-pinned** WolfTrap CLI from this repository are required to execute scans. The CLI's `scan-build` mode may require the documented optional PyYAML dependency. Installation of the scanner is a separate conscious step; never install or execute dependencies from an untrusted scanned project.

The portable manifest declares `extensions.com.openai.requires_local_executor: true` because this workflow calls a trusted local CLI. The plugin itself has **no network tools, no credentials, no lifecycle hooks and no MCP server**. Scans are limited to local source directories the user is authorized to inspect. They write evidence outside the inspected tree and do not execute that tree's project code.

The public main CLI offers `scan-build`, `scan-agent`, `scan-effects`, `scan-prompts`, and `scan-go-authority`. Draft-branch capabilities like MCP Bloodhound, Cursorial, WolfPrint, WolfNet, and offline-product convenience commands are *not* automatically included. Refer to their own independent qualification and integration gates before advertising them.

## Try as a repository-local plugin

For a supported Codex CLI environment:

```bash
codex plugin marketplace add Bropdrop/WolfTrap --ref feat/wolftrap-codex-plugin-v0-1
codex plugin marketplace list
```

In a supported ChatGPT desktop app, open Plugins, choose the WolfTrap repository marketplace, install `wolftrap-security`, and refresh the client if needed. The CLI command registers the marketplace source; it does not prove the plugin was installed or loaded. Review the branch content before enabling the plugin. For longer-lived use, pin the marketplace to an audited immutable commit instead of following this moving development branch.

The test workflow uses Python's standard library only and does not require secrets or call the WolfTrap scanner. To validate packaging locally:

```bash
python3 -m unittest discover -s plugins/wolftrap-security/tests -p 'test_*.py' -v
```

Separately run a documented `wolftrap scan-build` command against a harmless local authorized fixture to validate the installed CLI. Validate each additional mode against its own documented fixture before claiming it is functional.

## Intended prompt

> WolfTrap this *authorized local* repository, with offline CI/build and agent trust-boundary review. Keep evidence outside the source tree and distinguish review signals from inconclusive and untested results.

## Release gates

This is a draft and not a security certification. Public distribution remains blocked pending (1) independent package review and clean install test, (2) each supported CLI mode's fixture-backed results, (3) evidence-verifier qualification, (4) input and output path abuse tests, (5) Windows/Linux client compatibility, and (6) confirmation of plugin-directory review requirements. No production deployment, public listing, or billed provider integration is performed by this change. A clean desktop client installation is still **NOT TESTED**. Publishing requires developer or business verification and platform review. OpenAI currently does not support adding MCP capability to an already-submitted skills-only plugin; a later MCP distribution would require an independently planned submission or a different initial packaging decision.

Documentation: https://developers.openai.com/plugins/build/plugins
License: Apache-2.0 (repository root).

## Offline integration qualification (second gate)

The CI job additionally invokes the exact checked-out WolfTrap public-main CLI
using harmless local fixtures, *inside a Linux network namespace* after its
reviewed, SHA-256-pinned PyYAML wheel is installed. The seven test methods
exercise the supported build, agent, effects, prompt, and Go static modes,
their applicable CLI evidence verifiers, retained report digests, conditional
positive controls, empty/unsupported input, evidence tampering, file traversal,
symlink selection, and attempted in-source evidence output. These are bounded
developer acceptance tests, not hostile penetration testing of third parties.

To reproduce the fixture checks on a trusted Linux checkout (Python 3.12):

```bash
python -I -m pip --isolated install --no-cache-dir --no-deps \
  --only-binary=:all: --require-hashes \
  -r .github/qualification-requirements.txt
PYTHONPATH=src python -m unittest discover \
  -s plugins/wolftrap-security/tests -p 'test_integration.py' -v
```

The scanner must stay separate from untrusted inspected code. A passing run
does **not** demonstrate that Codex or ChatGPT installed or activated the
plugin, or that unpublished draft-branch security modules are shipped.

## Upgrades and compatibility

See [UPGRADES.md](UPGRADES.md). Keep plugin and engine releases independently pinned and qualified. A new scanner rule with unchanged CLI can be an engine-only update; new commands or evidence schemas require plugin compatibility changes. This candidate is deliberately unsubmitted until the skills-only versus MCP-initial choice is reviewed.

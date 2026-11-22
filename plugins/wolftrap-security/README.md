# WolfTrap Security plugin v0.1.0 (candidate)

A skills-only, local-first Agent Plugins package for Codex and supported ChatGPT desktop/Work plugin environments. It orchestrates WolfTrap's *existing* CLI. It does not contain an MCP server, grant remote access, install the WolfTrap engine, or publish anything to the public Plugins Directory.

## Contents

- `plugin.json`: portable Agent Plugins 1.0.0 manifest and OpenAI presentation metadata.
- `skills/wolftrap-audit/SKILL.md`: authorized local offline scans and status reporting.
- `skills/wolftrap-evidence-review/SKILL.md`: evidence integrity/verification review.
- `../../.agents/plugins/marketplace.json`: a repository-local plugin directory entry.
- `tests/test_package.py`: dependency-free package contract tests.

## Requirements and security model

Python 3.11+ and a separately installed **reviewed and commit-pinned** WolfTrap CLI from this repository are required to execute scans. The CLI's `scan-build` mode may require the documented optional PyYAML dependency. Installation of the scanner is a separate conscious step; never install or execute dependencies from an untrusted scanned project.

The plugin itself has **no network tools, no credentials, no lifecycle hooks and no MCP server**. Scans are limited to local source directories the user is authorized to inspect. They write evidence outside the inspected tree and do not execute that tree's project code.

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

This is a draft and not a security certification. Public distribution remains blocked pending (1) independent package review and clean install test, (2) each supported CLI mode's fixture-backed results, (3) evidence-verifier qualification, (4) input and output path abuse tests, (5) Windows/Linux client compatibility, and (6) confirmation of plugin-directory review requirements. No production deployment, public listing, or billed provider integration is performed by this change.

Documentation: https://developers.openai.com/plugins/build/plugins
License: Apache-2.0 (repository root).

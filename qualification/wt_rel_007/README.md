# WT-REL-007 skills-only submission candidate

## Distributions and evidence

The WolfTrap Security v0.2.0 skills ZIP is a portable Agent Plugins package for desktop execution. The pinned protected Linux MCP evaluation remains a separate product.

The reviewed WT-REL-006 commit `ff423e3f264b784bb4b495249b90538bca7b671c` is a direct child of PR #35 head `8a33bc6d2230bff0a05aff77648a8362ed8e84eb`. Git object validation and ancestry checks passed. Two rebuilds using the reviewed driver reconstructed the 205,923-byte MCP ZIP at SHA-256 `f4d6188d47bb6c4fdcde3c76b54cb5ac0430c927d3d43b82b15b79c427c535dd`. The adapter still uses PR #34 source `4d39dbee2aca4a680cd1a916bc4beb0f54cccb30` and tree `a04d65fd3535c74ea8991e557b14d1e6899caa8e`.

The [WT-REL-006 review](../wt_rel_006/README.md) and [unsigned evidence](evidence/) concern only that frozen MCP ZIP. Their regenerated SBOM, rebuild Statement, and manifest exactly matched the WT-REL-006 copies. The manifest binds the rebuild Statement and SBOM to the frozen ZIP. No production signer or publisher authentication is asserted.

The operator confirmed that the sanitized Chromebook export used an explicit field whitelist that omitted `mcp_outcomes`. This accounts for the exported runtime summaries. Preserve all three summaries as received. The original SQLite and protocol logs stay with the custodian. No omitted values were reconstructed, and raw evidence review remains pending. Existing qualification scope and both historical Zero Trust **SURVIVED** results remain as stated in WT-REL-006.

## Build and verify

| Skills ZIP | Pin |
| --- | --- |
| Name | `wolftrap-security-0.2.0.zip` |
| Size | 30,626 bytes |
| SHA-256 | `418a88d4ba3a069662d0731aff924ac17938882303e3b2c94a2365836d0b3350` |
| Schema | Agent Plugins 1.0.0, SHA-256 `0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883` |
| External CLI | WolfTrap 0.5.3, Git commit `ec6c3c1b2a50d702d202bd9b4e40842ba6e395f2` |

Select the reviewed commit explicitly. In a separate review environment with Python and `jsonschema` available, obtain the official manifest schema and use fresh output paths outside the checkout.

```bash
schema="$review_dir/agent-plugin.schema.json"
curl -fsSL https://agent-plugins.org/schemas/1.0.0/plugin.schema.json -o "$schema"
pkg="$review_dir/wolftrap-security-0.2.0.zip"
builder=qualification/wt_rel_007/skills_package.py
python3 -B "$builder" build "$pkg" --commit "$reviewed_commit" --schema "$schema"
python3 -B "$builder" verify "$pkg" --commit "$reviewed_commit" --schema "$schema"
printf '%s  %s\n' 418a88d4ba3a069662d0731aff924ac17938882303e3b2c94a2365836d0b3350 "$pkg" | sha256sum --check -
```

The builder uses a fixed Git inventory, sorted stored ZIP members, Unix regular-file mode 0644 and a fixed timestamp. The five root-relative files are:

- `LICENSE` from the repository's Apache-2.0 license.
- `assets/wolftrap.png`, original 192×192 PNG artwork covered by the same license and referenced as both listing and composer icon.
- `plugin.json`, version 0.2.0 with `extensions.com.openai.requires_local_executor: true`.
- `skills/wolftrap-audit/SKILL.md` and `skills/wolftrap-evidence-review/SKILL.md`.

The verifier checks the closed inventory, official schema, identity, listing constraints, icon references, frontmatter and license bytes. The byte comparison rejects any changed or extra ZIP member. The ZIP contains no CLI, dependency, executable hook, app reference or MCP configuration.

## Qualification

Five existing package-contract methods and four archive test methods passed locally. Negative cases covered missing license, skill or icon, extra MCP configuration, app reference or hooks, traversal inventory, wrong version, disabled local execution requirement, invalid icon path, overlong subtitle, duplicate manifest keys, truncated ZIP and substituted content. The PNG passed image verification. The manifest passed the official Agent Plugins schema.

The seven public-mode fixture methods passed with the actual installed 0.5.3 console command on Linux x86-64 using Python 3.12.14 and the hash-pinned PyYAML 6.0.3 wheel. All five scan and three verifier help commands passed. The suite checked supported output and completion digests, conditional static signals, unsupported input returning inconclusive, a changed evidence file being rejected, and traversal, symlink and in-tree output restrictions. The repository's existing libseccomp offline wrapper denied socket creation during fixture execution. This was CLI qualification, with desktop activation still unexecuted.

To reproduce, use the pinned public-main checkout as `$engine`. Build and install in a private external prefix using reviewed setuptools (engine build requirement is 68 or later), and stage the reviewed CPython 3.12 Linux x86-64 wheel in `$wheels`. Use fresh directories. The wheel SHA-256 is pinned in `.github/qualification-requirements.txt`.

```bash
python3 -m pip --isolated install --no-index --no-deps --no-build-isolation --target "$prefix" "$engine"
python3 -m pip --isolated install --no-index --no-deps --only-binary=:all: \
  --find-links "$wheels" --require-hashes -r .github/qualification-requirements.txt --target "$prefix"
python3 -B qualification/wt_zt_001/offline.py "$(command -v python3)" -IB \
  qualification/wt_rel_007/check_cli.py "$engine" "$prefix"
```

## Listing and reviewer notes

- **Listing.** WolfTrap Security uses the subtitle “Offline static review,” the Productivity category, and the Read capability label. The local workflow also writes reports to an explicitly approved directory outside the target.
- **Audience and scope.** The candidate supports developers reviewing explicitly authorized local workflows, Dockerfiles, agent source, prompt documents and Go permission patterns. Static matches are review signals. The verifier checks supported saved evidence. The skills neither grant authority nor infer live exploitability or security from clean results.
- **Installation.** A supported desktop local execution session is required. Install the separately reviewed CLI and its optional build parser according to the fixture pin. Use synthetic or authorized local fixtures. Review instructions require no credentials, network server or cloud data.
- **Support.** Provide the plugin and CLI versions, platform/client version and a sanitized fixture reproduction through the repository's issues page. Use the repository security reporting channel for concerns about WolfTrap, and keep private evidence out of public issues. Publisher name in the manifest is the repository's declared developer name. Portal identity verification remains outstanding. [Support](https://github.com/Bropdrop/WolfTrap/issues) · [Security reporting](https://github.com/Bropdrop/WolfTrap/security)

### Clean desktop checklist

- [ ] Use a clean profile on a currently supported ChatGPT desktop client. Record operating system, architecture, client version and ZIP digest. Use an authorized local install or review path, and verify the display name, icon, version, Desktop only classification and both loaded skills. Record the exact workflow used.
- [ ] In a local session with the CLI absent, ask for an authorized fixture scan. Require an explicit unavailable result, with zero target execution or dependency installation. Confirm the remote-only and unauthorized-target prompts cause no scan, clone or upload.
- [ ] Install the pinned CLI from a trusted path and approve only the test source and fresh external evidence destination. Run each applicable mode on the fixture suite and compare exit codes, evidence inventory and conditional/inconclusive reporting. Confirm the source tree is byte-unchanged and no target code executes.
- [ ] Invoke evidence review on a valid report, then on a separate copied fixture with a changed report and on a missing or wrong-mode bundle. Require integrity rejection or a precise limitation. Verify a directory traversal, symlink and an in-source output request produce no external read or write beyond the approved scope.
- [ ] Uninstall the plugin and confirm it no longer loads, reinstall the same digest, and repeat the key local and denied cases. Capture sanitized evidence from the exact client. Track environment, owner and result for each row.

Desktop install, local executor behavior in the exact client, and portal checks are **NOT TESTED**. Current public rules require the Desktop only marker for local executors, a primary icon for submission, and both icon references for Codex packaging. Submission access and verified developer/business identity must be established through an authorized organization. Portal results and publisher approval are separate. [Package structure](https://developers.openai.com/plugins/build/plugins) · [Desktop-only requirements](https://developers.openai.com/plugins/deploy/desktop-only) · [Submission requirements](https://developers.openai.com/plugins/deploy/submission)

## Decision

| Product | GO | BLOCK |
| --- | --- | --- |
| WolfTrap Security v0.2.0 skills-only | Review candidate packaging, schema, local CLI fixture compatibility | Clean supported desktop installation and functional run, publisher identity and authorized organization/project access, portal validation and approval to submit |
| Frozen Linux MCP evaluation | Reproducibility and the previously reported Crostini fixture scope | Independent private runtime evidence review, compatible protected CI, production provenance/signing authority, exact client compatibility and approved-partner/organization allowlisting for local MCP distribution |

The local MCP adapter requires a separately conforming initial package and partner approval. The skills-only candidate makes no local-MCP eligibility claim. Neither product is approved here for submission, production signing, or distribution.

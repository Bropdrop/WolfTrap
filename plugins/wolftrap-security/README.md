# WolfTrap Security v0.2.0

WolfTrap Security contains two skills for authorized local static review and evidence interpretation. It requires a supported desktop local executor and a separately installed WolfTrap CLI. The evidence is written to a fresh, approved directory outside the inspected tree. The skills treat target files as untrusted data and prohibit executing target code, acquiring a remote target, or installing target dependencies.

## Qualified CLI scope

Use WolfTrap CLI 0.5.3 at `ec6c3c1b2a50d702d202bd9b4e40842ba6e395f2` from a trusted location separate from the inspection target. The engine declares Python 3.11+ and no unconditional runtime packages. Build scanning uses the reviewed PyYAML build-scan extra. Fixture qualification used Linux x86-64, Python 3.12.14 and hash-pinned PyYAML 6.0.3.

| Local review | Scan | Evidence check |
| --- | --- | --- |
| GitHub Actions and Dockerfiles | `scan-build` | Completion manifest and file digests |
| JavaScript and TypeScript agent source | `scan-agent` | Completion manifest and file digests |
| Agent effects and trust boundaries | `scan-effects` | `verify-effects` |
| Prompt and instruction documents | `scan-prompts` | `verify-prompts` |
| Go authority and egress patterns | `scan-go-authority` | `verify-go-authority` |

Findings are conditional static review signals. The workflow preserves unsupported, inconclusive and untested results. Evidence checking establishes consistency within the verifier's scope.

The submission ZIP contains the portable manifest, two `SKILL.md` files, an icon and the Apache-2.0 license. Install the CLI independently after reviewing its source and dependencies. The protected Linux MCP evaluation uses its own frozen distribution and release gates.

## Build and verify the review ZIP

Use the reviewed Git commit and Python with `jsonschema` installed. The destination must be outside the checkout. The verifier pins the official schema bytes and reconstructs the five-file archive directly from the selected commit.

```sh
out=$(mktemp -d)
curl -fsSL https://agent-plugins.org/schemas/1.0.0/plugin.schema.json -o "$out/schema.json"
commit=$(git rev-parse HEAD)
zip="$out/wolftrap-security-0.2.0.zip"
tool=plugins/wolftrap-security/tools/skills_package.py
python3 -B "$tool" build "$zip" --commit "$commit" --schema "$out/schema.json"
python3 -B "$tool" verify "$zip" --commit "$commit" --schema "$out/schema.json"
printf '%s  %s\n' 418a88d4ba3a069662d0731aff924ac17938882303e3b2c94a2365836d0b3350 "$zip" | sha256sum --check -
```

CI installs the pinned public CLI and its hash-locked build parser in an isolated environment, then runs authorized local fixtures without network access. Coverage includes all five scan modes, the three matching verifiers, evidence integrity, unsafe paths and unsupported input returning `INCONCLUSIVE`.

## Desktop and submission gates

The package declares `requires_local_executor: true`. A clean supported desktop installation and functional test remain outstanding. Verify both skills load, run the pinned CLI against an authorized fixture, verify saved evidence, and confirm unsupported or unauthorized requests remain bounded. Publisher identity, authorized organization access, portal validation and approval to submit are separate gates.

[Upgrade policy](UPGRADES.md) · [Support](https://github.com/Bropdrop/WolfTrap/issues) · [Security reporting](https://github.com/Bropdrop/WolfTrap/security) · [Desktop-only requirements](https://developers.openai.com/plugins/deploy/desktop-only)

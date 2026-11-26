# WT-MCP-002 local evaluation, version 0.2.0

This separate adapter exposes the three WT-MCP-001 tool names for operator-selected synthetic GeoTrace v2 captures. The skills plugin is version 0.2.0 and the engine is version 0.6.0. The release package has its own inventory and contains the engine modules required for this profile. A side-by-side install leaves the existing CLI and plugin under their existing pins.

## Trust boundary

| Component | Authority and evidence |
| --- | --- |
| Operator and private stdio session | A trusted supervisor selects the owner approval digest, session, measured client and qualified installation. Possession of that session allows use of outstanding matching approvals. Multiuser caller authentication is unsupported. |
| Transport and frontend | The broker parses bounded UTF-8 JSON-RPC frames. Discovery negotiates MCP 2025-11-25. Identifiers have a session budget. Unknown notifications have no effect. The frontend runs in a separate worker and can only propose the original call or catalog. The broker discards transport metadata before authorization. |
| Host broker | The broker matches canonical typed arguments to the pinned per-request grant. An approval binds tool, operation, tenant, principal, session, task, resource, source, destination, generation, expiry and policy. An operator-supplied digest anchors the separate GeoTrace policy. |
| OS and engine | The outer namespace exposes an allowlisted runtime, reviewed installation, read-only control and sources, and private effect slots. The inner worker sees selected files and a private writable staging directory only where the scan needs it. The inherited network filter precedes a second filter that prevents process creation and replacement before loading the worker role. |
| Slot and external verifier | Each destination is a private SQLite database. A durable dispatch reservation precedes work. One local transaction inserts all four artifacts and the commitment journal event. Independent observers read the database through a read-only connection. The external verifier derives the expected phase sequence, grant digest and file inventory separately. |

The earlier adapter used a prebound grant and one fixed capture. Its launcher, host, six historical mutations and original evidence verifier are preserved in `qualification/wt_mcp_001`. Its direct app-server run exercised client-selected calls without model inference. The new profile reuses its Linux mount builder and reviewed GeoTrace entry point. Its existing filesystem-based receipt semantics remain reproducible at PR #32.

## Owner workflow

The supervisor supplies a canonical local captures directory, a GeoTrace policy, a selection document and the expected SHA-256 of that document through an independently controlled channel. The selection schema and full fictional grant examples are in `fixtures.py` and the validation contract is in `owner.py`. Commissioning snapshots up to eight explicitly named JSON files, checks source hashes against the owner's selections, and records each resulting local inode and change time. The external examples use two distinct captures with different review outcomes. Owner approval of a digest assumes trusted local provisioning. Publisher identity is unverified.

Keep a reviewed supervisor copy of `launch.py` and `reference_pin.py` in an owner-controlled directory separate from the package. It independently measures the candidate, places the accepted application bytes in sealed memory files, and mounts those bytes read-only before any candidate code executes. Start the supervisor from this trusted directory. Use a fresh state path in a private operator directory. All path arguments below are absolute. Keep control and storage under the same supervisor, protect them from other writers and use the supplied revocation command.

```bash
q=qualification/wt_mcp_002
/usr/bin/python3.13 -IBS "$q/owner.py" provision --selection "$selected_plan" \
  --selection-pin "$approved_selection_sha256" --captures "$captures" --geo "$geo_policy" --state "$state"
/usr/bin/python3.13 -IBS "$trusted_supervisor/launch.py" "$state" --install "$installed_package" --owner-pin "$owner_pin" \
  --qualified-pin "$reviewed_runtime_pin" --session "$session" --client "$qualified_client"
/usr/bin/python3.13 -IBS "$q/owner.py" revoke --state "$state"
```

Provisioning prints the digest of the commissioned owner document. The supervisor retains it. The launcher requires the separately reviewed runtime/configuration pin. A model or harness identifier is supplied by the supervisor. MCP clients cannot select these launch arguments. The revoker acquires the same lock as final commitment, increments the generation and syncs it to disk. A new task requiring a fresh generation receives a new commissioned state and independently approved pins.

A dispatch reservation without a matching commitment yields `HOLD` on retry. A lost reply after a successful transaction yields `ALREADY_COMMITTED` only if current authorization, expected artifacts and prior journal agree. Verification can substantiate historical effects after revocation through the independent read-only auditor. New scans remain subject to current authorization. Rollback of the entire owner directory, simultaneous compromise of the host and evidence store, power-loss behavior of real storage, clock rollback and distributed exactly-once execution remain unqualified.

## Reproduce and verify

Use a clean checkout and an existing Debian 13 x86-64 environment with Bubblewrap, Python 3.13, libseccomp, SQLite and strace. The client exercises use the existing Python MCP SDK 1.29.0 and Codex CLI 0.172.0-alpha.2. No dependency installation is part of the harness.

```bash
out=$(mktemp -d)
q=qualification/wt_mcp_002
unshare --user --map-current-user --net python3 -B "$q/qualify_release.py" --output "$out/run"
python3 -B "$q/package.py" verify --zip "$out/run/wolftrap-local-evaluation-0.2.0.zip" \
  --commit "$expected_commit" --tree "$expected_tree" --sha256 "$expected_package_sha256"
python3 -B "$q/audit.py" --state "$out/run/trials/state" --handle alpha \
  --owner-pin "$approved_owner_pin" --reference-pin "$reviewed_reference_pin"
```

The package verifier checks each file against an object from the selected commit, the expected tree, exact ZIP bytes and an externally supplied digest. Use `package.py install` with the same arguments and a new private `--destination`. Retain the previous verified installation and separately review a launch-profile change to switch versions. Rollback selects a retained installation with its original pins. The two versioned profiles have different state formats. Retain the corresponding state and audit records. Never restore a spent approval for use in a new session.

The safety case records actual protocol decisions, journal and artifact observations, installed client traces, per-case mutation/restoration records, package contents, commands and configuration identities. Qualification creates its output outside the checkout. Cases use disposable sources and state. Hosted CI attempts the exact OS profile after network isolation. Unavailable facilities block that job. A real-model run needs a separate, authorized local inference runtime.

## Distribution decision

Use the skills-only candidate with a separately distributed Linux evaluation adapter for review. A combined local-MCP submission requires approved partner status, an allowlisted organization and a clean desktop installation. OpenAI also requires an MCP server to be included in the initial plugin ZIP when that submission path is chosen. Adding MCP to an already submitted skills-only plugin is unsupported. Organization eligibility and ChatGPT desktop installation have not been established here. Combined submission remains **BLOCKED**. [OpenAI submission guidance](https://developers.openai.com/plugins/deploy/submission) · [Desktop-only plugins](https://developers.openai.com/plugins/deploy/desktop-only)

The supported evaluation boundary is direct SDK and Linux Codex app-server calls. CLI registration, removal and re-registration are separate checks. Linux GUI, ChatGPT desktop, macOS, Windows, remote transport and real model-selected behavior require their own qualification. No approval or confidence signal from a model changes any gate.

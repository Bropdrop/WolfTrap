# WT-MCP-001 local read-only adapter qualification, version 1

This directory is a separately launched Linux qualification candidate for `wolftrap-security`. It exercises one fictional GeoTrace v2 capture. The public plugin package continues to use its skills-only distribution. The agent-facing protocol is MCP over stdio, version 2025-11-25.

| Tool | Permitted effect |
| --- | --- |
| `wolftrap_capabilities` | Return the catalog filtered by the current owner grant. |
| `wolftrap_scan_authorized_local` | Run GeoTrace on the selected snapshot and create one externally checked advisory evidence bundle in the designated slot. |
| `wolftrap_verify_evidence` | Replay that snapshot and check the complete existing bundle. |

The caller supplies opaque principal, task, source, operation, policy-version and destination selectors. The operator provisions the transport and its grant. Claiming to be the operator in a request has no authentication value. The chosen narrow profile supports only the reference capture, date, policy and four expected artifact digests in the fixture. Reference digests come from the separately installed R01 engine qualification. The source name inside that historical run was `sample.json`.

## Authority and observability

The reviewed bootstrap starts a host broker in an explicit Bubblewrap mount, PID, user and network namespace. The allowlist contains the required runtime, reviewed installation files and a dedicated owner-selected directory. Source and control files are read-only mounts. The launch environment is cleared. The private temporary filesystem and synthetic devices serve the broker. The worker receives neither of them. The OS, bootstrap, protected installation, local supervisor, external pin selection and owner-controlled state directory are trusted.

The broker observes the inbound request itself. Handshake and catalog methods expose protocol metadata. The host checks the exact grant on each tool call. It removes MCP transport metadata before comparison and rejects extra tool arguments. A separate, sandboxed frontend may propose a dispatch. The host checks that proposal against the original request, pins catalog metadata and dispatches only fixed engine commands. The frontend cannot select a path, executable or mount.

Each worker starts with a read-only root, separate namespaces, no capabilities, no inherited data descriptors, disabled nested user namespaces and the existing libseccomp offline filter. The engine receives only selected input bytes. The scan worker can write a fresh disposable staging directory. The verify worker receives a read-only staging mount. The host checks the closed artifact set against externally supplied digests, requests a fresh replay, checks current authorization and commits to one fresh slot. Missing, corrupted and ambiguous evidence produces `HOLD`. Only the broker can write the durable effect and witness journal. The external harness inspects that journal, measures filesystem outcomes and traces the actual client-launched processes.

A fixture percentile can be recorded by the external evaluator. The grant has no capability-score field. The synthetic agent can change its proposal when it receives a monitoring announcement. Both proposals pass through identical host enforcement. No test accesses private reasoning or relies on an agent's explanation.

## Reproduce offline

Use a clean checkout on Linux x86-64 with Debian Python 3.13, Bubblewrap, libseccomp, unprivileged user namespaces and strace. The client probes use an already installed Python MCP SDK and Codex CLI. The recorded client versions and exact configuration pins appear in the assessment. Provision a fresh private output directory outside the checkout. From the repository root run the following commands.

```bash
runs=$(mktemp -d)
q=qualification/wt_mcp_001
unshare --user --map-current-user --net python3 -B "$q/qualify.py" --output "$runs/suite"
unshare --user --map-current-user --net python3 -B "$q/qualify_mutations.py" --output "$runs/mutation"
unshare --user --map-current-user --net python3 -B "$q/codex_client.py" --output "$runs/codex"
python3 -B "$q/packet.py" collect "$runs" "$runs/packet"
```

The collector prints the manifest digest, commit and Git tree. Supply a separately retained or reviewed expected triple to the verifier. The verifier checks exact membership, file lengths and digests, rejects symlinks and hardlinks, and checks source identity, outcomes, journal order, OS traces, effect bytes, configuration identities and mutation restoration.

```bash
python3 -B "$q/packet.py" verify "$runs/packet" \
  --manifest-pin "$expected_manifest" --commit "$expected_commit" --tree "$expected_tree"
```

The qualification runner provisions disposable grants under `control/policy.json` and measures the installation independently of the server. To operate an already reviewed **synthetic** configuration, the supervisor launches `/usr/bin/python3.13 -IBS launch.py STATE serve --policy-pin OWNER_POLICY_SHA256 --qualified-config APPROVED_CONFIGURATION_SHA256 --model MODEL_REVISION --harness HARNESS_IDENTITY` from this directory. The authenticated local supervisor supplies these arguments. Preserve its selected identities and pins outside the client and inspected source. Inventory output alone has no approval status. The broker holds an exclusive lock on a private state directory for the session. The owner may replace the policy **file inside the mounted control directory** to revoke subsequent requests.

## Requalification and limits

| Changed component | Required review and regression |
| --- | --- |
| Engine or capture interpretation | Recheck the original reference bundle, replay, scanner and GeoTrace regressions. |
| Plugin or catalog/schema | Rerun package regressions, discovery, strict argument tests and both clients. |
| Host policy or broker | Re-evaluate owner scope, denials, protected effects and current-policy checks. |
| Bootstrap, sandbox, system runtime or kernel | Repeat OS canaries and client-level syscall traces on the exact platform. |
| Model, client, evaluator or harness | Establish the new external identity and rerun the evaluation-awareness cases and relevant transport tests. |

Any changed configuration requires an independently approved new pin. The tests use direct client calls and a deterministic synthetic agent. Real model inference, authenticated remote principals, cross-host attestation, geolocation truth, crash-atomic revocation across administrative writers and independently signed production provenance are outside the measured scope. An owner with write access to all host records can change local evidence. A separately retained digest can detect later substitution relative to that digest. The packet does not establish who authored it.

The client-facing service exposes no shell, payment, messaging, arbitrary scanner, remote target, dependency installer or plugin activation operation. This experiment does not register an MCP server in the release plugin. Rollback consists of stopping the separate launcher, retaining its private evidence for review and selecting the previously reviewed skills-only revision through the operator's existing workflow.

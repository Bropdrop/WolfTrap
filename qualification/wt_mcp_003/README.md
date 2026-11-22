# Chromebook nested sandbox compatibility

PR #33 at `7522d75c0c258f79a2f35b46a9afb72083a19c67` (tree `31bdb25120bba8881c5b9adee31576446153d348`) launched a broker inside Bubblewrap. Discovery asked an inner Bubblewrap to launch the proposal worker. Crostini on Debian 13 with Python 3.13.5 and Bubblewrap 0.11.0 reportedly rejected the inner UID map. The operator reported 21 GeoTrace v1, 22 v2, 13 plugin, three worker confinement and ten commissioning controls passing. Those device results apply to the original revision.

On a separate Debian x86-64 Linux host, a single-ID rootless mapping reproduced successful initialization, rejected discovery, the same Bubblewrap diagnostic and an empty effect slot. Preserving the current UID allowed discovery on the same code and kernel. These observations locate the failure before the worker executes. They leave the Chromebook's kernel and container-manager policy undetermined.

## Sibling launch contract

The trusted operator runs the measured supervisor outside the broker as their ordinary user. It launches the broker and each single-use frontend, scanner or verifier directly. Each launch requires a fresh user, mount and network namespace, drops capabilities, clears the environment and disables further user namespace creation in the workload. The broker installs its irreversible process and socket filter before accepting requests. Workers install the offline and process filters before loading their role. Worker launch failure closes the operation. A machine that denies even the first required sandbox cannot use this adapter.

Two anonymous one-way pipes connect the broker to the supervisor. Only the broker has session grants, read-only sources and write access to the effect slots. Only the supervisor constructs launch commands. The job protocol accepts three fixed roles with bounded typed-by-position byte fields. Every executable, mount destination and output filename is fixed by the reviewed launcher. The supervisor passes sealed input snapshots and measured code to each worker and collects bounded stdout. The frontend receives a proposal over stdin. Scan scratch is a disposable 16 MiB tmpfs. Verify receives a read-only copy of the selected four artifacts. Neither worker receives host source paths, control mounts, effect slots, client descriptors or the private dispatch channel.

The broker checks the returned proposal, compares all artifacts with the selected reference, runs verification in a fresh worker, rechecks the source and grant, and commits to the local SQLite journal and slot in one transaction. The external auditor checks the slot separately. A missing acknowledgement can be reconciled from that state. An unfinished reservation remains on hold. The host supervisor, kernel, runtime, owner pins and operator-controlled storage are trusted. Prior qualifications are bound to their original configuration digests.

## Reproduce

Use a clean reviewed checkout and an external private temporary directory. The diagnostic accepts the independently selected commit. It provisions only fictional local data and runs real MCP frames followed by a separate read of the journal and artifact hashes. An unresolved catalog exits 2 and writes its diagnostic. Raw stderr traces stay in temporary storage.

```bash
out=$(mktemp -d)
probe="$PWD/qualification/wt_mcp_003/catalog_check.py"
python3 -B "$probe" --expected-commit "$reviewed_commit" --output "$out/device"
```

On Crostini, run this directly as the ordinary Linux user with the existing security settings. Run the same probe from a separate clean PR #33 checkout for the paired baseline, retaining the candidate's absolute probe path. On a Linux surrogate supporting rootless user and network namespaces, the commands below vary the enclosing UID map. Neither command gives host-root privileges.

```bash
unshare --user --map-current-user --net python3 -B "$probe" --expected-commit "$reviewed_commit" --output "$out/same"
unshare --user --map-root-user --net python3 -B "$probe" --expected-commit "$reviewed_commit" --output "$out/root"
unshare --user --map-root-user --net python3 -B qualification/wt_mcp_002/qualify_release.py --output "$out/full"
```

The full suite additionally exercises hostile requests, independent slot audits, fault injection, restored mutations, commissioning and direct SDK and Codex calls. It requires the already installed client dependencies. The external process trace must witness all Bubblewrap launchers as direct children of one supervisor, successful user/mount/network namespace creation and both filters before every worker role. The standalone catalog probe covers a narrower path.

**Chromebook full MCP remains BLOCKED** pending a device run of the sibling candidate, including the affected security, recovery and client controls. Linux surrogate results are scoped to the recorded configuration. Real model-selected behavior, desktop plugin installation and production release require separate evidence.

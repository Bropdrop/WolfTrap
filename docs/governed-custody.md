# Recovering a disposable awooo release archive

The evaluation archive keeps the exact signed capsule, including the wheel, SBOM and provenance, for each admitted release. Admission uses the standalone pre-install verifier. An archive audit answers whether the complete stored history still matches a separately held checkpoint. A recovered historical capsule needs a fresh subscriber-policy verification before anyone installs it. Production custody is **BLOCKED** pending separately controlled storage and an independently verified retention and recovery exercise.

## Operators and independent inputs

The subscriber policy operator authenticates the test roots, policy digest, policy generation and release sequence over a channel independent of artifact distribution. The archive custodian operates the primary. A separate checkpoint custodian retains each approved sequence and index digest, including the highest acknowledged sequence. The recovery operator obtains the expected checkpoint from that custodian and retrieves the bytes from a replica. All roles run on one machine in the exercise.

The directory containing the verifier and the custody tool must itself come from an independently trusted source. Acquire the capsule and policy from separate locations. Use existing private directories on Linux local storage with working descriptor locks, same-filesystem atomic directory renames, hard links and file/directory fsync. The adapter uses CPython, the pre-install verifier's OpenSSL dependency and Linux procfs. No Docker, core installation or target execution is required. Commands below run from the reviewed source tree.

## Admit and replicate

1. Create three separate private directories for the primary, replica and restored files. This example uses evaluation scratch space.

   ```sh
   umask 077
   work=$(mktemp -d)
   mkdir "$work/primary" "$work/replica" "$work/restored"
   python3 -I release/custody genesis
   ```

2. Start with independently confirmed empty history, sequence zero and genesis digest `4d105f32f0c0872ad98c070e2b99f4b44c36d240e228ff1338b0f583206ff74a`. For an existing archive, use its latest independently retained sequence and index digest. A stale checkpoint, a missing slot or a changed historical capsule stops verification. In the commands, set the uppercase shell variables to the operator-supplied inputs.

   ```sh
   python3 -I release/custody admit --vault "$work/primary" \
     --sequence "$PRIOR_SEQUENCE" --index-sha256 "$PRIOR_INDEX_SHA256" \
     --bundle "$CAPSULE" --trust-dir "$SUBSCRIBER_TRUST" \
     --policy-sha256 "$POLICY_SHA256" --minimum-policy-generation "$GENERATION"
   ```

   The governed evaluation profile uses subscriber policy v2 and its independently obtained minimum generation. Admission checks current policy, signed bytes, manifest, source identity and revocation. Legacy evaluation fixtures using policy v1 omit the generation argument. Supplying a generation floor to v1 rejects the downgrade.

3. Retain the resulting sequence and index digest in independently administered checkpoint storage. An operator should confirm the receipt against the approved inputs before acknowledging the new head. Someone able to replace both a capsule and its only checkpoint can present a different history. The public receipt contains source and archive digests only as referenced by the index. No secret signing material is needed for recovery.

4. Audit, replicate and compare readback from the second location.

   ```sh
   python3 -I release/custody audit --vault "$work/primary" \
     --sequence "$HEAD_SEQUENCE" --index-sha256 "$HEAD_INDEX_SHA256"
   python3 -I release/custody replicate --vault "$work/primary" --replica "$work/replica" \
     --sequence "$HEAD_SEQUENCE" --index-sha256 "$HEAD_INDEX_SHA256"
   python3 -I release/custody audit --vault "$work/replica" \
     --sequence "$HEAD_SEQUENCE" --index-sha256 "$HEAD_INDEX_SHA256"
   ```

   A replica may contain a verified prefix. Replication rejects conflicting slots and a replica ahead of the supplied checkpoint. The digest chain begins with a domain-specific genesis digest. Each canonical `awooo.local-evaluation-custody/v1` index binds the previous index digest, release sequence and version, source commit and tree, policy, wheel, SBOM, manifest and exact capsule size and digest. Each slot contains exactly `index.json` and `capsule.zip`. Guarantees apply to the bytes read during the audit. An offline observer with an old checkpoint cannot independently discover an unseen later head.

## Recovery, withdrawal and suspension

On primary loss or corruption, preserve the affected medium and acquire the independent head checkpoint. Run the full audit on another copy. Restore the chosen sequence under a fresh filename in a separate private directory.

```sh
python3 -I release/custody restore --vault "$work/replica" \
  --sequence "$HEAD_SEQUENCE" --index-sha256 "$HEAD_INDEX_SHA256" \
  --release-sequence "$AUDITED_RELEASE" --output "$work/restored/recovered.zip"
```

The receipt reports the restored release sequence, index and capsule SHA-256 after byte readback. Compare the recovered capsule digest with the checkpointed release index. To rebuild a complete primary, create a fresh empty private directory and replicate from the verified secondary. If every copy is corrupt or the independent checkpoint is lost, retain the evidence and leave recovery unverified. For previously archived evaluation receipts, the separately documented build-based recovery path can restore exact historical bytes where its inputs still exist. [Release trust guide](release-trust.md)

When a signer or publisher is lost or compromised, suspend release admission through the subscriber incident policy and retain existing evidence under the original identifier. Record withdrawals by exact manifest digest and distribute a freshly authenticated bulletin and generation through the subscriber trust channel. Historical byte restoration remains available for investigation. Installation requires a separate evaluation through the standalone verifier with a current bulletin. For a lower-sequence installation use only a live, explicit rollback authorization bound to origin, destination, digest and expiration. [Subscriber incident procedure](subscriber-incidents.md)

## Interrupted or concurrent operations

One custodian per vault can write at a time. The nonblocking Linux directory lock returns `custody-busy-retry` while another participant holds the lock. A second writer using a previously acknowledged head fails after a successful advance. Publishers sync both files and the staging directory, rename the populated slot, then sync its parent. An incomplete `pending-<32 hex characters>` directory has no release identity. Audits count pending stages while excluding their contents from the committed history. At the bound of four stages, writes stop. Operators can preserve the failed storage and replicate its verified committed prefix into a fresh private directory.

If the process loses its reply after a complete slot became visible, run `reconcile` with the same arguments as `admit`. It independently validates the original capsule and current policy, computes the only acceptable new head from the supplied prior checkpoint and reads back the committed history. It cannot repair a divergence. A later revocation or changed policy digest prevents reissuing that receipt. Use separately authenticated custody evidence for historical recovery. An interrupted replica catches up on retry by verifying its complete prefix. A failed recovery that left an output file must be retried with a fresh filename. Recheck exact bytes before use.

The adapter admits up to 16 contiguous releases starting at one, each bounded to 6 MiB. Full preflight and replication read the whole history with bounded work. Directory scans allow at most 20 entries including four pending stages. Directory and member access uses no-follow file descriptors. Regular members must have exactly one hard link and retain stable identity while read. The private owned vault and trusted ancestors exclude untrusted local writers. Locks coordinate cooperating processes on a supported local filesystem. Root, a same-UID adversary, a compromised kernel or dishonest storage hardware can still delete, withhold or replace local data. The external checkpoint detects divergent replayed bytes at the next audit. Private mode and fsync alone cannot guarantee remote retention, detect suppression of an unknown update or prove crash persistence on every device.

## Independent exercise and production gate

```sh
python3 -I release/custody exercise --output "$work/custody.json"
python3 -m unittest discover -s tests -p test_governed_custody.py -v
```

The exercise generates ephemeral CMS certificates, admits two fictional releases, derives the expected index using a separate byte-level oracle, injects an interruption before the atomic commit, resumes a replica, takes the primary offline and recovers historical bytes. It tests policy withdrawal, lost acknowledgement, storage corruption, divergent and missing history, symlink substitution and defective auditors. The JSON lists each expected and observed outcome and the cases that kill each mutant. Results omit temporary keys and randomized certificate bytes. Repeated runs compare report bytes independently. The hosted qualification binds the report digest to its tested revision and tree.

Production storage requires a named authorized provider, separately administered replica, enforced version retention with controlled deletion, durable authenticated checkpoint service with anti-rollback state, an approved retention period, monitored replication lag, outage escalation and tested restoration under lost-account and storage-failure conditions. The operators must run a recovery from the secondary, compare exact artifact and checkpoint identity and record independent review. No production storage destination, permissions or retention settings are configured by this adapter.

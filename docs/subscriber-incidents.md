# Current incident policy for offline subscribers

The standalone verifier supports a governed evaluation profile for organizations that can separately supply current subscriber policy. Production authorization remains blocked. An installed copy of WolfTrap, a hash copied from a download page, or a certificate in a capsule cannot establish this trust.

## Before verification

The subscriber security operator obtains the verifier, root certificate, signer certificate, approved policy digest, release-sequence floor and policy-generation floor through an independently authenticated channel. Record both floors and the exact policy pin in subscriber-controlled storage. Obtain the current time from a trusted clock. The verifier reads these inputs afresh for each invocation. It has no network connection to an incident service and cannot discover an incident published after the last bulletin.

The policy custodian starts with the complete PR #25 subscriber catalog, selects schema `awooo.subscriber-policy/v2`, and adds two fields. An example of just the additional fields follows. Timestamps are Unix seconds. Replace them with an authorized current interval when issuing a real evaluation policy.

```json
{
  "generation": 7,
  "incidents": {
    "observed_at": 1800000000,
    "next_update": 1800003600,
    "suspended": false,
    "publisher_status": "ACTIVE",
    "signer_status": "ACTIVE",
    "withdrawn_manifests": []
  }
}
```

Each authority status accepts `ACTIVE`, `REVOKED` or `LOST`. Incident status refers to the exact issuer, signer and certificate pins in the same policy. The bulletin must lie within the policy validity period, last at most 24 hours, and cover the subscriber's present time. Expiration is exclusive. The withdrawal register accepts at most 256 unique lowercase SHA-256 manifest digests. Preserve all withdrawals affecting retained releases when issuing new generations. Exceeding the supported bound requires a reviewed profile extension. Update the trusted pin atomically with the floors and keep the previous checkpoint under independent custody. An offline host unable to refresh its clock or checkpoint must suspend installation. The verifier cannot detect a dishonest policy custodian or restore subscriber storage by itself.

## Verify before installing

On an eligible installation host, from a separately reviewed verifier checkout, run the following with subscriber-supplied values. For an audit on Linux against a specific declared target, supply the existing `--platform` option.

```sh
python -I release/verifier verify --evaluation \
  --bundle "$CAPSULE" --trust-dir "$TRUST" --policy-sha256 "$POLICY_PIN" \
  --minimum-policy-generation "$POLICY_FLOOR" \
  --minimum-sequence "$RELEASE_FLOOR" --sequence "$RELEASE_SEQUENCE"
```

A verified response identifies the exact policy generation, pin, incident expiry, artifact digests and source revision. Use the same independently selected inputs with `install` and `--venv NEW_PRIVATE_PATH` to perform a fresh verification and install on a qualified host. The installer reopens trust material and checks time and signature again immediately before package installation. If it stops after creating an environment, discard that specific incomplete environment and retry using a fresh path. Then run the existing doctor, quickscan and verify-report commands. [Installation and evidence verification](release-verification.md)

Selecting a generation floor rejects v1 policy. Supplying v2 without a floor returns `INCONCLUSIVE`. Existing v1 evaluation commands remain available for historical PR #25 experiments. They omit the separately versioned incident bulletin.

## Incident actions

| Event | Responsible operator and action | Verifier behavior |
| --- | --- | --- |
| Suspected publisher or signing-key compromise | Incident commander suspends release. Trust custodian distributes a higher generation and new pin via a channel independent of the affected identity. Mark the authority revoked and retain affected manifest digests. | Current, rollback and historical verification fail on a suspended or revoked authority. Valid original signatures are insufficient for acceptance. |
| Loss of signing or publisher authority | Mark the affected authority `LOST`, rotate it under independent review, and reissue the subscriber checkpoint only after reviewing unaffected release records. | An unavailable authority blocks verification. Replacing the subscriber root or signer without updating the independent policy pin fails. |
| Withdrawal or supersession | Record a withdrawn digest in the bulletin and catalog. For a normal upgrade increment the release sequence and pin the new record. Retain the old approval and original signature for permitted historical audit. | A withdrawn manifest fails all purposes. A superseded, unwithdrawn release can be audited with `verify --purpose historical`. Historical audit cannot install it. |
| Approved rollback | Record the exact current and target sequences, target manifest and deadline in the pinned policy. Keep the current release high-water mark at the rollback origin. | `install --purpose rollback` requires exact approval, an unexpired permit, a current bulletin, an active signer and the target's archived signature. |
| Stale or conflicting subscriber state | Stop installation. Reconcile pin, generation, release floor and clock with independent operators. Reissue the checkpoint after resolving conflicting histories. | A stale or missing bulletin yields `INCONCLUSIVE` and a reason. A generation below the independent floor, a mismatched pin or an unauthorized release yields `REJECTED`. |
| Recovery from storage loss | Restore capsule and independent trust records from separately controlled custody. Compare original transport and manifest digests, refresh policy, and verify in the appropriate purpose before restoring operations. | A recovery receipt alone grants no authority. Keep withdrawn records visible in the subscriber catalog, including after restoration. |

A passing offline check establishes the selected evaluation policy at the sampled time. A later revocation can arrive during or after local pip execution. A compromised clock, stale independently provided floor or release mirror that also controls the trust channel defeats the corresponding assumption. The subscriber must bound propagation delay and stop pending installs during incident response. Production signing, governance, trusted checkpoint distribution and durable custody require separately verified infrastructure.

Replay the incident controls and inherited release-verifier cases from the reviewed revision with the following commands.

```sh
python -m unittest discover -s tests -p test_governed_subscriber.py -v
python -m unittest discover -s tests -p test_release_trust.py -v
```

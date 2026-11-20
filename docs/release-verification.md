# Verify a release before installation

The selected product name is **awooo**. The existing `wolftrap` CLI, package, license and evidence formats continue. This profile supports a fictional evaluation authority. The production verdict is **BLOCK — PRODUCTION RELEASE PROHIBITED**.

## Independent prerequisites

Obtain the reviewed `release/verifier/` directory from a trusted source independent of the download. Use an independently selected Git commit and tree, or a verified read-only copy from your organization's software custodian. Check the verifier with a trusted Git client before running it. Never run a verifier supplied by the same untrusted download as the sole source of trust. The separately distributed `reviewed-verifier.pyz` contains the same five Python files. Its SHA-256 and Git subtree must match an independently approved verifier revision before execution. It accepts the same commands as the directory. Use trusted CPython 3.12 and the system OpenSSL 3 CLI. Installation additionally requires CPython 3.12.14, venv and pip on a qualified Ubuntu 24.04 system. The verifier imports no WolfTrap application modules or downloaded software.

Your subscriber administrator supplies a small trust directory containing `policy.json`, `root.pem` and `signer.pem`, the SHA-256 of the exact policy bytes, the current monotonic sequence floor, the selected release sequence and its purpose. The administrator first establishes the repository identity, commit/tree, workflow bytes, signer and subject scope independently. The PIN and floor must come through an authenticated channel independent of the candidate or its mirror. A matching hash from an adjacent checksum file cannot establish that channel. An old policy and its old floor can be replayed together if the subscriber loses its trusted state. Evaluate an expiry or revocation update before choosing a new pin. Use a trusted clock.

The downloadable, bounded ZIP capsule contains a wheel, SBOM, manifest, provenance, detached CMS signature, platform matrix, license, security policy, notes and these instructions. Keep the capsule intact. Store the independently selected verifier and trust material elsewhere. Generated public fixture certificates may be redistributed for experiments; trusting them only exercises the evaluation profile. The pre-install verifier has no production trust profile.

## Current incident policy for governed evaluation

A subscriber using `awooo.subscriber-policy/v2` also obtains the minimum policy generation from its independently authenticated authority. Add `--minimum-policy-generation "$generation"` to each verification, installation or retention command below. The verifier checks the current bulletin for release suspension, loss or compromise of the signing authority, publisher revocation and withdrawn manifests. An expired bulletin, missing generation floor or downgrade stops the governed workflow. Release and policy-generation floors protect different histories. A v1 catalog remains supported for earlier evaluation receipts. [Governed installation walkthrough](governed-release.md) · [Incident policy and recovery](subscriber-incidents.md)

## Verify, install, doctor, scan and replay

Use Bash. Replace the paths and values with the ones selected by your subscriber. Run from a trusted directory with the verifier and Python environment outside the project to inspect.

```bash
verifier=/path/to/reviewed/release/verifier
capsule=/path/to/custody/awooo-evaluation-00000001.zip
trust=/path/to/subscriber/trust
read -r -p 'Independent policy SHA-256: ' policy_pin
floor=1
sequence=1
work=$(mktemp -d)
args=(--bundle "$capsule" --trust-dir "$trust" --policy-sha256 "$policy_pin"
      --minimum-sequence "$floor" --sequence "$sequence" --evaluation)
python3.12 -I "$verifier" verify "${args[@]}"
python3.12 -I "$verifier" install "${args[@]}" --venv "$work/venv"
wt="$work/venv/bin/wolftrap"
"$wt" doctor
"$wt" quickscan --demo --output-dir "$work/report"
"$wt" verify-report --demo --evidence-dir "$work/report"
"$wt" list-rules
```

`verify` and `install` emit JSON. Exit 0 means VERIFIED under the named evaluation policy. Exit 1 means REJECTED for a demonstrated policy, signature or integrity violation. Exit 2 means INCONCLUSIVE for missing evidence, an unavailable provider or an unsupported verification profile. Both failures stop installation. The installer independently repeats verification, uses a fresh private venv and passes the verified in-memory wheel to pip through a private copy with a required hash. Interrupted venv creation can leave an incomplete directory. Preserve it for inspection or remove it yourself, then retry under a fresh name. No installed code is needed for these checks.

For a cross-machine audit, select the intended `--platform ubuntu-24.04-x86_64-cpython-3.12.14` or `ubuntu-24.04-aarch64-cpython-3.12.14`. Installation also checks the actual OS, machine and interpreter. Explicit platform selection cannot override that check. The demonstration quickscan returns 1 for the documented review signal. Complete report replay returns 0. Select an authorized local project using the product guide. [Offline core](offline-product.md)

## Custody, upgrades and recovery

Use an existing caller-owned 0700 directory on a trusted local filesystem for `retain --vault DIR` with the same verification arguments. The verifier authenticates the entire snapshot before staging it. A write, fsync and exclusive hard-link publish one complete sequence. Concurrent attempts cannot replace it. A crash may leave a private `.pending-*` entry. It is never a release. After inspecting ownership, recover by verifying the final object or retrying under the original sequence if absent. Preserve previously recorded pins and never reassign a sequence to different bytes. A writer or administrator who can modify the underlying store can still remove or substitute data. Keep two independently managed offline copies, their authentication policies, certificates, receipts, withdrawal records and reviewed verifier. Periodically compare digests and run an offline restore. A production custodian must supply independently audited retention and immutable storage.

For an upgrade, obtain a fresh approved catalog and persist its current sequence floor through the subscriber's trusted channel. Use `--purpose historical` to verify an exact previously witnessed signature and manifest at the recorded observation time. Historical mode cannot install. It still enforces current policy validity, revocation and withdrawal. To reinstall an older version, the subscriber must supply a time-limited rollback authorization binding the exact previous manifest and current sequence. Use `--purpose rollback`; the signer must still be valid today. Withdrawal or compromised-key revocation takes precedence in every mode. A disconnected verifier cannot discover a newer revocation than its pinned policy. Uninstall with the venv's `python -I -m pip uninstall wolftrap`. Keep the evidence and custody copies.

An evaluation signing receipt can retain the exact public signature and metadata in Git. Follow the recovery procedure in the release trust guide to reconstruct the original capsule with a locally rebuilt wheel. Actions uploads are transport and diagnostics with a finite retention period.

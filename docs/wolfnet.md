# WolfNet v1

WolfNet lets a subscriber check who signed a fictional security advisory, what independent observations support it, and what a local policy would propose for one requested operation. Verification runs from explicit local files at a caller-selected UTC time. This release accepts fictional WolfPrint issuer records and Cursorial traces. It produces review evidence. The host retains exclusive authority to grant permissions and perform effects.

## Interpreting a finding

| Level | Meaning in the selected subscription | Evidence supported in v1 |
| --- | --- | --- |
| 0 · CLEAR | No applicable active adverse record for this principal, architecture, operation and scope at this time | Requires a verified feed, an issuer-bound presentation and a successful scope check. Gives no general security certification. |
| 1 · ADVISORY | Indicators merit monitoring or review | A separately signed static observation can corroborate a metadata indicator. Attribution remains unknown. |
| 2 · MODERATE | A credible concern calls for additional verification or limited capabilities | A separately witnessed and replayed fictional denied request with zero unauthorized effects can support this level. |
| 3 · HIGH | A serious boundary violation has independent support | V1 can reproduce a specific fictional host defect. An independent ledger records a write after both the host and reference oracle denied the operation. |
| 4 · CRITICAL | Severe unauthorized effects attributable to an authenticated principal require independent genuine-runtime verification | Reserved. A signed claim or a simulation at this level produces `INCONCLUSIVE`. |

The reported severity, confidence (`LOW`, `MEDIUM`, `HIGH`), identity assurance and verified evidence class are separate fields. A high confidence label is the publisher's assessment. It cannot remove an evidence gap. Reports carry both the submitted and effective severity.

* `STATIC REVIEW SIGNAL` records an independently observed indicator. A benign description or an authorized action can look suspicious.
* `SYNTHETICALLY VERIFIED` records agreement or independently reproduced disagreement among explicitly joined fictional witnesses.
* `AUTHORIZED RUNTIME VERIFIED` requires a separately qualified genuine-runtime witness. V1 leaves these claims inconclusive.
* `INCONCLUSIVE` covers missing, contradictory, disputed or unsupported attribution. An agent's statement of success, an architecture digest and behavioral similarity provide no independent evidence of execution.

## What is signed

The closed JSON Schema defines five input documents. A trust bundle identifies a subscription, clock origin, revision, signing identities, organizational roles, validity intervals and revocations. A subscriber checkpoint pins a specific feed history. A feed contains consecutively signed snapshot frames. A witness bundle contains separately signed observations. A local policy selects publishers, review requirements, responses, appeal holds and disputed instances. [Versioned JSON Schema](../src/wolftrap/schemas/wolfnet-v1.schema.json)

Each advisory carries a namespaced `WN-…` ID, publisher and serial, revision, subscription (realm, stream, issuer, trust domain, tenant), WolfPrint principal and architecture digests, optional instance and key revision, incident and provenance references, operation digest, resource scope, category, reported severity, confidence, identity assurance, evidence class and digest, recommendation, timestamps and review status. Publication includes an explicit redaction/fictional distribution designation, consent, review and appeal references. A correction or withdrawal links the exact prior advisory digest. The signed language accepts fixed labels, bounded numeric aliases, timestamps, digests and signatures. It has no field for prompts, logs, credentials, URLs, personal names or prose instructions.

Ed25519 signatures use the Linux distribution's libsodium ABI 23 (1.0.18 or later, x86-64 or AArch64). The loader requires a fixed distributor-controlled library location and non-writable system path components. Verification includes strict public-key point validation. Unsupported installations return exit 2 and `BLOCKED`. Records have no facility to select algorithms, libraries, keys or URLs. Qualification cross-checks publisher, reviewer, distributor, observer and withdrawal signatures with the system OpenSSL executable using the RFC 8410 public-key encoding. The verifier itself uses only libsodium for Ed25519. [libsodium signature documentation](https://doc.libsodium.org/public-key_cryptography/public-key_signatures) · [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)

The signing input is the ASCII prefix `wolftrap.wolfnet/v1`, a zero byte, `signature/` followed by the role, a second zero byte, then a canonical object containing `alg`, `body`, `key_revision` and `signer`. Schema-validated strings use a closed ASCII vocabulary. Objects use sorted keys, arrays preserve order, and UTF-8 JSON has no whitespace outside strings. Booleans and integers are distinct. Floats, negative zero and duplicate decoded keys are rejected. The published fixture signer is deliberately reproducible with publicly known seeds. Anyone can sign as a **fixture** publisher. Operators supply their own trusted pins outside the feed. The CLI has no publisher enrollment or production signing command.

### Log acceptance, reviews and recovery

1. Select the subscription, trusted evaluation time, trust bundle and previously accepted checkpoint through an independent channel. Both files require separate SHA-256 byte pins. Begin a new subscription at its configured, scope-bound genesis. Losing stored state also loses offline rollback protection.
2. Verify the complete ordered history. Each frame commits to the previous signed envelope, its sequence, time, validity window, subscription and every publication. Signer identity, role, organization, key revision and Ed25519 public key come from the pinned bundle. Duplicate key material, invalid points, ambiguous rotations and incompatible scopes fail verification.
3. An active publication needs publisher consent and at least one independently signed reviewer approval. Level 3 or 4, quarantine or denial recommendations, and corrections reopening a contest need two separate reviewer organizations independent of the publisher. The effect witness must come from a further independent observer. Operational independence of these organizations is a subscriber trust assumption.
4. Store the newly verified checkpoint and its pin using subscriber-owned storage. The verifier emits a candidate and never advances external state. By default an update must extend the checkpoint. Use `--use-accepted` to examine exactly the current pinned head. Lower sequence, inconsistent prefix, stale trust revision, changed trust contents under an accepted revision and clock rollback are rejected. A new pinned trust revision can authorize a legitimate key transition or declare compromise.
5. An independent reviewer or publisher can sign a contest. Subscribers can hold an appeal using the advisory ID in their local policy. A correction must link the current revision. The original publisher can withdraw using a signed terminal record. The history retains the tombstone and rejects replay or renaming the same incident under that publisher. A revoked signer invalidates an unanchored past signature. An already pinned prefix can preserve history during recovery, while any current record resting on the revoked signer becomes untrusted until resolved. A currently valid distributor must sign the latest frame.
6. Re-evaluate the requested scope after an appeal, correction, withdrawal, expiration, trust change or change of authority. A valid withdrawal restores the host's own proposal when there is no other applicable finding. Disputed, conflicting, untrusted or unsupported applicable findings suspend external restriction proposals. Subscribers can retain and replay earlier evidence with its original clock and pins.

Hashes in an evidence manifest detect changes to bytes. Authentication of a published advisory comes from its Ed25519 signatures and independently selected roots. Evidence verification regenerates all artifacts at the specified source commit.

## What a subscriber can propose

The default local mode is `advisory`. A corroborated applicable concern produces `MONITOR`. A valid clear scope produces `ALLOW` from the registry and leaves the separately evaluated host decision in control. When evidence is incomplete, the registry proposes no action. A host denial for lack of current authority still holds.

| Local setting | Effect on this fictional operation |
| --- | --- |
| `publishers`, `subscription`, `revision`, `since`, `expires` | Select the exact trust realm, stream, tenant and publishers. Pin this policy independently. |
| `mode: fictional-simulation`, `actions` | Explicitly enable a local severity-to-action mapping. The seven permitted proposals are ALLOW, MONITOR, REAUTHENTICATE, READ_ONLY, REQUIRE_HUMAN_APPROVAL, QUARANTINE and DENY. |
| `min_severity`, `min_confidence`, `min_reviewers` | Require local thresholds, fixture-issuer attribution, the same observed instance and a supported independently witnessed class. The publisher's recommendation bounds the proposal. |
| `permit_deny: true` | Adds explicit operator consent for a simulated denial. Quarantine and denial additionally require Level 3, HIGH confidence, a reproduced unauthorized effect and at least two independent reviewer organizations. |
| `appeal_holds`, `disputed_instances` | Suspend applicable registry proposals while an advisory is under local review or custody of a session is in dispute. The latter requests reauthentication and withholds attribution to a principal. |

The decision joins the exact trusted workload issuer, tenant and trust domain, principal, architecture, optional published instance, resource and operation digest. An instance-scoped record cannot transfer to a restart. A principal-scoped advisory may merit monitoring after a restart, while stronger proposals require the observed instance. Another principal using the same model, build or behavior receives its own independent evaluation. All outputs are scoped to one fictional operation and have `enforced: false`. Each audit binds the feed head, trust revision and digest, policy revision and digest, host authority epoch and digest, host audit, applicable advisory revisions, severity, confidence, identity assurance and earliest known expiry. An unchanged copied session with no custody warning can be indistinguishable from the legitimate holder. This prototype cannot identify a person controlling it.

## Reproduce the example

Run the following Bash commands in a clean Git checkout with Python 3.11+ and the supported system library. Use `python -m wolftrap` via `PYTHONPATH=src`, or the installed `wolftrap` entry point from the same checkout. The example pins below apply only to the public, fictional files at this revision. A subscriber supplies its own independently controlled pins, trusted clock and checkpoint.

```bash
export PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1
wn=examples/wolfnet
wp=examples/wolfprint
out=$(mktemp -d)
head=$(git rev-parse HEAD)
trust=813ac14f9e5a8c175bd8d67ea6dcc177f51f1fb19018d4362ae0e0325dabdc85
genesis=c12183112a311e64c1e56132c48052dda4f69b7ed4032b2526f97a3dd4ef7336
historical=a43fa88277b919740524c2c457da419286c0a3fd42ef022bdbad4482aa457950
current=5d7517fd9b15ad2ed73820b23d7907518ed7ac296f69b9697643b71c39668430
policy=0eaa86e478a3b2bce2c39497087ea4c6ad240f9fbece0e57205686b61b364bf2
common=(--expected-head "$head" --at 2030-01-01T00:01:00Z
        --trust "$wn/trust.json" --trust-sha256 "$trust"
        --witnesses "$wn/witnesses.json" --trace "$wn/incident-chain.json"
        --witness-registry "$wn/incident-registry.json" --witness-registry-sha256 "$historical")
first=("${common[@]}" --feed "$wn/feed.json"
       --checkpoint "$wn/checkpoint.json" --checkpoint-sha256 "$genesis")
subject=(--manifest "$wp/architecture.json" --request "$wp/request.json"
         --registry "$wp/fixture-registry.json" --registry-sha256 "$current")
python -m wolftrap verify-wolfnet-feed "${first[@]}" --output-dir "$out/feed"
python -m wolftrap verify-wolfnet-feed "${first[@]}" --evidence-dir "$out/feed"
python -m wolftrap evaluate-wolfnet "${first[@]}" "${subject[@]}" --verified-feed-dir "$out/feed" \
    --policy "$wn/policy.json" --policy-sha256 "$policy" --output-dir "$out/decision"
# The last command returns 1 for the supported advisory and proposes MONITOR.
python -m wolftrap challenge-wolfnet --expected-head "$head" --output-dir "$out/challenge"
python -m wolftrap verify-wolfnet-challenge --expected-head "$head" --evidence-dir "$out/challenge"
```

`evaluate-wolfnet` accepts `--evidence-dir` for byte replay of a previously written decision. It requires and replays the entire saved feed bundle first. If checking the same feed later, pass its original verification time using `--verified-at` and the new evaluation time using `--at`. The engine rechecks current record, key, observation, identity and policy validity at the new time.

To exercise opt-in denial, select the example `policy-opt-in.json` with pin `cd62f573b569bee948f27942b1a84bae5ab1bae22076d4defcdc844904a7c149`. The signed example `withdrawn-feed.json` extends the original feed. Select the previously verified `wolfnet-checkpoint.json` as the next checkpoint together with its independently retained byte pin, then replay and evaluate the withdrawn feed. It restores `ALLOW` for the current authorized fixture operation. The qualification runner demonstrates this whole sequence and independently reconstructs the checkpoint before use.

| Exit code | Feed or evaluation | Challenge |
| --- | --- | --- |
| 0 | Feed verified or no applicable active adverse record | Every authored expectation matched and each defective implementation failed qualification |
| 1 | Supported advisory or simulated local restriction requires review | Qualification mismatch |
| 2 | Incomplete, disputed, malformed, expired or unsupported evidence, bad pin, blocked crypto, unsafe path or replay failure | Unavailable or untrustworthy evidence |

Each complete bundle has `wolfnet.json`, `wolfnet.md`, `wolfnet.sarif` and `wolfnet.manifest.json`. A cryptographically verified feed includes `wolfnet-checkpoint.json`, even when particular advisories have evidence gaps. Such a checkpoint records signed history and grants no authority. An invalid feed signature yields no checkpoint. SARIF findings are review notes. The bundle contains sanitized fictional references, input byte digests, revision, scope, outcome and limits.

## Bounds and qualification

Each selected JSON file is limited to 96 KiB, nesting depth 12 and 4,096 nodes. Feed history is limited to 16 frames, four publications per frame, four reviewer approvals per publication, 24 trust keys, 16 observation receipts and four trace files. Snapshot validity is limited to seven days and advisory and observation validity to 30 days. The engine rejects unsupported schema versions, ambiguous signatures, malformed data, traversal, symlinks, hard-linked inputs, special files, unsafe output overlap and non-empty output directories. Inspection never follows references in submitted data, interrogates agents or launches a supplied program. Trust relies on the independently pinned local inputs, trusted checkout, OS library, evaluation clock and retained subscriber state.

The challenge crosses 96 authored registry and policy scenarios with four fictional workload/delegation profiles and adds 20 signature, 12 parser and 11 filesystem controls. All 427 cases have fixed expectations. Eleven deliberately defective verifiers and policies must each fail. Tests also cover tampered and rehashed manifests, changed verified files, resource limits and unsafe paths. From a clean exact checkout on Linux, run the qualification command below. It also compares 26 independently regenerated artifacts, checks seven distinct signatures and seven changed messages with OpenSSL, and independently joins the saved issuer, host and ledger evidence. The hosted job runs with read-only checkout permissions, no persisted checkout credentials and a loopback-only qualification namespace. [Qualification script](../scripts/qualify-wolfnet.py) · [Workflow](../.github/workflows/wolfnet-qualification.yml)

```bash
parent=$(readlink /proc/self/ns/net)
dest=$(mktemp -d)/qualification
unshare -Urn -- env -i PATH="$PATH" PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 \
    python scripts/qualify-wolfnet.py --expected-head "$(git rev-parse HEAD)" --parent-netns "$parent" --output-dir "$dest"
```

Known misses include compromised or colluding trust authorities, fabricated but internally consistent fictional source records, an undisclosed stolen session, and updates a distributor withholds within the current validity window. A static false positive can cause a monitoring proposal even when the host operation is authorized. A copied architecture, an honest upgrade, a rejected request or a host defect alone does not demonstrate malicious intent. Offline verification cannot establish actual organizational independence, physical key custody or complete incident coverage. A longer log requires an independently governed new subscription or out-of-band migration. V1 cannot silently truncate history or recover a lost high-water mark.

## Future interchange and publication

A future STIX 2.1 adapter could map a reviewed advisory to a Report with a stable STIX identifier, created/modified timestamps and redacted external references. A versioned extension would retain the signed WolfNet envelope, exact subject scope, separate severity/confidence/assurance, evidence class, approvals, supersession and withdrawal references. A principal digest or architecture match alone does not justify creating a Threat Actor object. Subscribers would verify the original signed envelope after import.

A future TAXII 2.1 collection could distribute these opaque signed snapshot histories to explicitly subscribed organizations. Distribution would require authenticated publisher enrollment, moderated submissions, independent evidence review, redaction and publication consent, transparent moderation and key-incident policies, secure transport, signed withdrawals, appeals and restoration, and subscriber-selected roots and checkpoints. This release ships offline files and commands. Public allegations would require independently qualified genuine evidence and a separately governed publication decision. [STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html) · [TAXII 2.1](https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html)

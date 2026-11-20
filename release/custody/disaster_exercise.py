"""Offline exercise with a separately calculated history and literal case expectations."""

from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
from unittest.mock import patch

from archive_store import admit, audit, locked, replicate, restore
from release_io import Verdict, encode, pack

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "qualification"))
from release_fixtures import TestIssuer, toy

EMPTY = "4d105f32f0c0872ad98c070e2b99f4b44c36d240e228ff1338b0f583206ff74a"


def digest(data):
    return sha256(data).hexdigest()


def checkpoint(files, approval, policy_bytes, previous):
    """Independent subscriber oracle: derive expected index bytes directly from fixture inputs."""
    (wheel,) = [name for name in files if name.endswith(".whl")]
    capsule = pack(files)
    record = {
        "archive_bytes": len(capsule),
        "archive_sha256": digest(capsule),
        "commit": approval["commit"],
        "manifest_sha256": digest(files["release.json"]),
        "policy_sha256": digest(policy_bytes),
        "previous_index_sha256": previous,
        "sbom_sha256": digest(files["core.cdx.json"]),
        "schema": "awooo.local-evaluation-custody/v1",
        "scope": "EVALUATION_ONLY",
        "sequence": approval["sequence"],
        "tree": approval["tree"],
        "version": approval["version"],
        "wheel_sha256": digest(files[wheel]),
    }
    return digest((json.dumps(record, sort_keys=True, indent=2) + "\n").encode("ascii"))


def observed(call):
    try:
        result = call()
    except Verdict as exc:
        return exc.status + "/" + exc.reason
    except OSError:
        return "INCONCLUSIVE/storage-io"
    return result if isinstance(result, str) else result["status"]


def audit_decision(vault, count, pin):
    return observed(lambda: audit(vault, count, pin)) == "VERIFIED_ARCHIVE_BYTES"


def local_pin_decision(vault, count, _pin):
    # Defective auditor accepts storage's own checkpoint instead of the subscriber pin.
    local_pin = digest((vault / f"release-{count:08d}" / "index.json").read_bytes()) if count else EMPTY
    return audit_decision(vault, count, local_pin)


def head_only_decision(vault, count, pin):
    # Defective auditor hashes just the newest index, skipping release bytes and earlier versions.
    index = vault / f"release-{count:08d}" / "index.json"
    return digest(index.read_bytes()) == pin if index.exists() else count == 0 and pin == EMPTY


def run():
    cases = []

    def check(name, expected, call):
        cases.append({"name": name, "expected": expected, "observed": observed(call)})

    with tempfile.TemporaryDirectory(prefix="awooo-disposable-custody-") as temporary:
        root = Path(temporary)
        vault, replica, recovered = (root / n for n in ("vault", "replica", "recovered"))
        for directory in (vault, replica, recovered):
            directory.mkdir(mode=0o700)
        issuer = TestIssuer(root / "issuer")
        now = int(time.time())
        one, first = toy(issuer, "0.1.1", 1, now)
        two, second = toy(issuer, "0.1.2", 2, now)
        trust1, trust2 = issuer.trust([first], now), issuer.trust([first, second], now)
        pin1 = checkpoint(one, first, trust1["policy.json"], EMPTY)
        pin2 = checkpoint(two, second, trust2["policy.json"], pin1)

        def first_admission():
            return admit(vault, pack(one), trust1, digest(trust1["policy.json"]), 0, EMPTY, now)

        def upgrade(files, trust, policy_pin):
            return admit(vault, pack(files), trust, policy_pin, 1, pin1, now)

        governed = root / "governed"
        governed.mkdir(mode=0o700)
        admit(governed, pack(one), trust1, digest(trust1["policy.json"]), 0, EMPTY, now)
        policy2 = json.loads(trust2["policy.json"])
        policy2.update(
            schema="awooo.subscriber-policy/v2",
            generation=11,
            incidents={
                "observed_at": now,
                "next_update": now + 600,
                "suspended": False,
                "publisher_status": "ACTIVE",
                "signer_status": "ACTIVE",
                "withdrawn_manifests": [],
            },
        )

        def governed_upgrade(*, reconcile=False, floor=11):
            trust = dict(trust2, **{"policy.json": encode(policy2)})
            return admit(
                governed,
                pack(two),
                trust,
                digest(trust["policy.json"]),
                1,
                pin1,
                now,
                reconcile=reconcile,
                minimum_generation=floor,
            )

        check("governed-current-upgrade", "ADMITTED_EVALUATION_BYTES", governed_upgrade)
        check(
            "governed-reconciliation", "RECONCILED_EVALUATION_BYTES", lambda: governed_upgrade(reconcile=True)
        )
        check(
            "governed-policy-replay",
            "REJECTED/replayed-policy-generation",
            lambda: governed_upgrade(reconcile=True, floor=12),
        )
        policy2["incidents"]["withdrawn_manifests"].append(second["manifest_sha256"])
        check(
            "governed-withdrawal-overrides-receipt",
            "REJECTED/manifest-withdrawn",
            lambda: governed_upgrade(reconcile=True),
        )
        check("empty-pinned-archive", "VERIFIED_ARCHIVE_BYTES", lambda: audit(vault, 0, EMPTY))
        with locked(vault, writing=True):
            check("concurrent-admission", "INCONCLUSIVE/custody-busy-retry", first_admission)
        check("authorized-first-release", "ADMITTED_EVALUATION_BYTES", first_admission)
        check("independently-computed-checkpoint", "VERIFIED_ARCHIVE_BYTES", lambda: audit(vault, 1, pin1))
        check("stale-writer-sequence", "REJECTED/custody-head-sequence-mismatch", first_admission)
        check(
            "self-selected-policy", "REJECTED/independent-policy-pin", lambda: upgrade(two, trust2, "0" * 64)
        )
        changed = dict(two, **{"RELEASE-NOTES.md": b"changed\n"})
        check(
            "substituted-admission",
            "REJECTED/manifest-or-payload-mismatch",
            lambda: upgrade(changed, trust2, digest(trust2["policy.json"])),
        )
        withdrawn = issuer.trust([first, dict(second, withdrawn=True)], now)
        check(
            "withdrawn-build-admission",
            "REJECTED/release-withdrawn",
            lambda: upgrade(two, withdrawn, digest(withdrawn["policy.json"])),
        )
        revoked = dict(trust2)
        policy = json.loads(revoked["policy.json"])
        policy["authority"]["revoked"] = True
        revoked["policy.json"] = encode(policy)
        check(
            "compromised-signer-admission",
            "REJECTED/authority-revoked",
            lambda: upgrade(two, revoked, digest(revoked["policy.json"])),
        )
        check(
            "authorized-version-upgrade",
            "ADMITTED_EVALUATION_BYTES",
            lambda: upgrade(two, trust2, digest(trust2["policy.json"])),
        )
        check(
            "lost-admission-reply",
            "RECONCILED_EVALUATION_BYTES",
            lambda: admit(
                vault, pack(two), trust2, digest(trust2["policy.json"]), 1, pin1, now, reconcile=True
            ),
        )
        check(
            "mismatched-reconciliation-predecessor",
            "REJECTED/independent-custody-pin-mismatch",
            lambda: admit(
                vault, pack(two), trust2, digest(trust2["policy.json"]), 1, "f" * 64, now, reconcile=True
            ),
        )
        check("independent-upgrade-checkpoint", "VERIFIED_ARCHIVE_BYTES", lambda: audit(vault, 2, pin2))
        check(
            "expired-subscriber-policy",
            "REJECTED/policy-not-current",
            lambda: admit(
                replica, pack(one), trust1, digest(trust1["policy.json"]), 0, EMPTY, now + 15 * 86400
            ),
        )
        check(
            "source-replica-overlap",
            "REJECTED/custody-path-overlap",
            lambda: replicate(vault, vault, 2, pin2),
        )

        # Simulate the interruption at the atomic namespace boundary, after durable member writes.
        with patch("archive_store.os.rename", side_effect=OSError):
            check(
                "interrupted-replication",
                "INCONCLUSIVE/storage-io",
                lambda: replicate(vault, replica, 2, pin2),
            )
        check(
            "interrupted-upload-invisible",
            "PENDING_REPORTED",
            lambda: "PENDING_REPORTED" if audit(replica, 0, EMPTY)["uncommitted_stages"] == 1 else "WRONG",
        )
        check("resume-replication", "REPLICATED_EVALUATION_BYTES", lambda: replicate(vault, replica, 2, pin2))
        check("repeat-replication", "REPLICATED_EVALUATION_BYTES", lambda: replicate(vault, replica, 2, pin2))
        check("replica-audits-independently", "VERIFIED_ARCHIVE_BYTES", lambda: audit(replica, 2, pin2))
        check(
            "reject-missing-recovery-version",
            "REJECTED/unknown-recovery-sequence",
            lambda: restore(replica, 2, pin2, 3, recovered / "unknown.zip"),
        )
        check(
            "wrong-recovery-receipt",
            "REJECTED/independent-custody-pin-mismatch",
            lambda: restore(replica, 2, "f" * 64, 1, recovered / "unknown.zip"),
        )

        os.rename(vault, root / "offline-primary")
        check(
            "recover-primary-from-verified-replica",
            "RESTORED_BYTES",
            lambda: restore(replica, 2, pin2, 1, recovered / "first.zip"),
        )
        check(
            "historical-byte-oracle",
            "MATCH",
            lambda: "MATCH" if (recovered / "first.zip").read_bytes() == pack(one) else "DIFFERENT",
        )
        check(
            "preserve-previous-recovery",
            "REJECTED/sequence-already-in-custody",
            lambda: restore(replica, 2, pin2, 2, recovered / "first.zip"),
        )

        def clone(name):
            return Path(shutil.copytree(replica, root / name))

        corrupt = clone("corrupt")
        (corrupt / "release-00000001" / "capsule.zip").chmod(0o600)
        (corrupt / "release-00000001" / "capsule.zip").write_bytes(b"substitute")
        missing = clone("missing")
        shutil.rmtree(missing / "release-00000001")
        symlink = clone("symlink")
        member = symlink / "release-00000001" / "capsule.zip"
        member.unlink()
        member.symlink_to(replica / "release-00000001" / "capsule.zip")
        fork = clone("fork")
        head = fork / "release-00000002" / "index.json"
        head.chmod(0o600)
        record = json.loads(head.read_bytes())
        record["commit"] = "f" * 40
        head.write_bytes(encode(record))
        check(
            "replica-refuses-equivocation",
            "REJECTED/independent-custody-pin-mismatch",
            lambda: replicate(replica, fork, 2, pin2),
        )
        vectors = [
            ("intact-replica", replica, 2, pin2, True),
            ("corrupt-historical-bytes", corrupt, 2, pin2, False),
            ("missing-historical-version", missing, 2, pin2, False),
            ("symlink-storage-substitution", symlink, 2, pin2, False),
            ("conflicting-local-history", fork, 2, pin2, False),
            ("stale-checkpoint", replica, 1, pin1, False),
        ]
        for label, store, count, pin, expect in vectors:
            check(
                label,
                "ACCEPT" if expect else "REFUSE",
                lambda: "ACCEPT" if audit_decision(store, count, pin) else "REFUSE",
            )
        mutants = {}
        for name, defective in (
            ("accept-all", lambda *args: True),
            ("reject-all", lambda *args: False),
            ("trust-local-pin", local_pin_decision),
            ("head-only", head_only_decision),
        ):
            mutants[name] = [
                label
                for label, store, count, pin, expected in vectors
                if defective(store, count, pin) != expected
            ]

    passed = all(c["expected"] == c["observed"] for c in cases) and all(mutants.values())
    return {
        "schema": "awooo.custody-exercise/v1",
        "scope": "DISPOSABLE_LOCAL_FIXTURE",
        "production_custody": "BLOCKED",
        "status": "VERIFIED_DISPOSABLE_EXERCISE" if passed else "EXERCISE_FAILED",
        "cases": cases,
        "mutants": mutants,
    }

"""Restore the signed historical evaluation without the original signing service."""

import sys

from release_core import verify
from release_io import encode, parse, sha
from reference import check

HISTORICAL = "399a2ea03f8c4182b05ebe50e9d5ce3b5f619d42"
RECEIPT_PIN = "0f7ce82039f1b378d7f3fb0c979c34963249d03b0a2b87a3879b12c6bee23292"


def recover_history(root, scratch, wheelhouse, run):
    receipt = root / "release/records/evaluation-399a2ea03.json"
    raw = receipt.read_bytes()
    check(sha(raw) == RECEIPT_PIN, "public test vector pin")
    original = parse(raw)
    check(original["commit"] == HISTORICAL, "wrong historical source")
    checkout = scratch / "history-source"
    run(["git", "clone", "--quiet", "--local", "--no-hardlinks", "--no-checkout", root, checkout])
    run(["git", "checkout", "--quiet", "--detach", HISTORICAL], cwd=checkout)
    kit = scratch / "history-kit"
    run(
        [
            sys.executable,
            "-I",
            checkout / "scripts/build-product.py",
            "--expected-head",
            HISTORICAL,
            "--wheelhouse",
            wheelhouse,
            "--output-dir",
            kit,
        ],
        cwd=checkout,
    )
    output = scratch / "original.zip"
    run(
        [
            sys.executable,
            "-I",
            root / "release/recover.py",
            "--source",
            checkout,
            "--kit",
            kit,
            "--record",
            receipt,
            "--record-sha256",
            RECEIPT_PIN,
            "--output",
            output,
        ]
    )
    capsule = output.read_bytes()
    check(sha(capsule) == original["archive_sha256"], "historical artifact was replaced")
    trust = {
        "policy.json": encode(original["policy"]),
        "root.pem": original["root_certificate"].encode("ascii"),
        "signer.pem": original["signer_certificate"].encode("ascii"),
    }
    observed = original["policy"]["releases"][0]["observed_at"]
    result, _ = verify(capsule, trust, original["policy_sha256"], 1, 1, "historical", observed)
    check(
        result["status"] == "VERIFIED" and result["commit"] == HISTORICAL,
        "historical observation could not be replayed",
    )
    return {
        "commit": HISTORICAL,
        "tree": original["tree"],
        "receipt_sha256": RECEIPT_PIN,
        "archive_sha256": sha(capsule),
        "scope": "original observed-time evaluation replay",
        "original_signature_preserved": True,
    }

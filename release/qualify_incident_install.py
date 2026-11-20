"""Qualify the v2 evaluation subscriber on an actual supported installation host."""

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / d) for d in ("release", "release/verifier", "release/qualification")]
from governed_qualification import check, clean_source, invoke, isolated_source
from release_client import host_profile, private_directory, publish_new
from release_fixtures import TestIssuer, inputs, seal, source_file
from release_io import BUNDLE_LIMIT, DOC_LIMIT, WHEEL_LIMIT, encode, file_bytes, pack, parse, path, sha, unzip
from release_policy import wheel_name


def rebuilt_payload(args, head, work):
    """Select only locally rebuilt code; downloaded kit bytes are comparison data."""
    kit = work / "rebuild"
    invoke(
        sys.executable,
        "-I",
        ROOT / "scripts/build-product.py",
        "--expected-head",
        head,
        "--wheelhouse",
        args.wheelhouse.absolute(),
        "--output-dir",
        kit,
    )
    version = tomllib.loads(source_file(head, "pyproject.toml").decode("utf-8"))["project"]["version"]
    name = wheel_name(version)
    wheel = file_bytes(kit / name, WHEEL_LIMIT)
    sbom = file_bytes(kit / "core.cdx.json", DOC_LIMIT)
    reference = unzip(
        file_bytes(args.release_evidence / "capsule/awooo-evaluation-00000001.zip", BUNDLE_LIMIT)
    )
    check(
        reference[name] == wheel and reference["core.cdx.json"] == sbom,
        "evaluation kit differs from independent local build",
    )
    return version, wheel, sbom


def qualify(args):
    head, tree = isolated_source(args)
    profile = host_profile()
    check(profile is not None, "native qualified Ubuntu host and CPython version required")
    destination = path(args.output)
    check(not destination.is_relative_to(ROOT), "choose external evidence output")
    os.close(private_directory(destination.parent))
    with tempfile.TemporaryDirectory() as scratch:
        work = Path(scratch)
        version, wheel, sbom = rebuilt_payload(args, head, work)
        issuer = TestIssuer(work / "disposable-issuer")
        observed = int(time.time())
        docs = {
            k: source_file(head, n)
            for k, n in (
                ("license_text", "LICENSE"),
                ("security", "SECURITY.md"),
                ("notes", "docs/release-notes-v1.md"),
                ("instructions", "docs/release-verification.md"),
            )
        }
        body, record = seal(issuer, wheel, sbom, version, 1, inputs(head, tree), observed, **docs)
        bundle = work / "incoming.zip"
        bundle.write_bytes(pack(body))
        # The issuer and subscriber catalog are controlled by this fixture,
        # independent of the kit or anything supplied by the capsule.
        material = issuer.trust([record], observed)
        policy = parse(material["policy.json"])
        policy.update(
            schema="awooo.subscriber-policy/v2",
            generation=1,
            incidents={
                "observed_at": observed,
                "next_update": observed + 3600,
                "publisher_status": "ACTIVE",
                "signer_status": "ACTIVE",
                "suspended": False,
                "withdrawn_manifests": [],
            },
        )
        trust = work / "subscriber-trust"
        trust.mkdir(mode=0o700)
        for name in ("root.pem", "signer.pem"):
            (trust / name).write_bytes(material[name])

        def subscriber(command, *extra, expected=0):
            raw = encode(policy)
            (trust / "policy.json").write_bytes(raw)
            return json.loads(
                invoke(
                    sys.executable,
                    "-I",
                    ROOT / "release/verifier",
                    command,
                    "--evaluation",
                    "--bundle",
                    bundle,
                    "--trust-dir",
                    trust,
                    "--policy-sha256",
                    sha(raw),
                    "--sequence",
                    "1",
                    "--minimum-sequence",
                    "1",
                    "--minimum-policy-generation",
                    str(policy["generation"]),
                    *extra,
                    expected=expected,
                    cwd=work,
                )
            )

        verified = subscriber("verify")
        check(
            (
                verified["status"],
                verified["commit"],
                verified["tree"],
                verified["wheel_sha256"],
                verified["scope"],
                verified["policy_generation"],
            )
            == ("VERIFIED", head, tree, sha(wheel), "EVALUATION_ONLY", 1),
            "verification bindings differ",
        )
        env = work / "env"
        installed = subscriber("install", "--venv", env)
        check(installed.get("installed") is True and installed["status"] == "VERIFIED", "missing v2 install")
        cli = env / "bin/wolftrap"
        doctor = json.loads(invoke(cli, "doctor", "--json", cwd=work))
        check(
            doctor["ready"] and (doctor["build"]["commit"], doctor["build"]["tree"]) == (head, tree),
            "installed doctor source differs",
        )
        demo = work / "demo"
        invoke(cli, "quickscan", "--demo", "--output-dir", demo, cwd=work, expected=1)
        check(
            json.loads(file_bytes(demo / "quickscan.json", DOC_LIMIT))["status"] == "REVIEW_REQUIRED",
            "demo inspection did not find its authored review case",
        )
        invoke(
            cli,
            "verify-report",
            "--demo",
            "--evidence-dir",
            demo,
            "--manifest-sha256",
            sha(file_bytes(demo / "quickscan.manifest.json", DOC_LIMIT)),
            cwd=work,
        )

        policy["generation"] = 2
        policy["incidents"]["withdrawn_manifests"] = [record["manifest_sha256"]]
        withdrawn = work / "after-withdrawal"
        denied = subscriber("install", "--venv", withdrawn, expected=1)
        check(
            denied == {"status": "REJECTED", "reason": "manifest-withdrawn"}
            and not os.path.lexists(withdrawn),
            "withdrawn release reached installation",
        )

    check(clean_source(head) == (head, tree), "installation changed source")
    evidence = {
        "schema": "awooo.governed-incident-install/v1",
        "scope": "EVALUATION_ONLY",
        "commit": head,
        "tree": tree,
        "platform": profile,
        "independent_rebuild": "BYTE_IDENTICAL_WHEEL_AND_SBOM",
        "trust": "DISPOSABLE_TEST_ISSUER",
        "policy": "awooo.subscriber-policy/v2",
        "verify": "VERIFIED",
        "install": "COMPLETED",
        "doctor": "READY",
        "quickscan": "REVIEW_REQUIRED",
        "verify_report": "REPLAYED",
        "withdrawn_install": "REJECTED",
        "withdrawn_venv_created": False,
        "production": "BLOCKED",
    }
    publish_new(destination.parent, destination.name, encode(evidence))
    invoke(
        sys.executable,
        "-m",
        "wolftrap.public_guard",
        head,
        "--report-root",
        destination.parent,
        "--report",
        destination.name,
        source=True,
    )
    print("VERIFIED_EVALUATION_INSTALL", head, tree, profile, "production BLOCKED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--parent-netns", required=True)
    parser.add_argument("--release-evidence", type=Path, required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    qualify(parser.parse_args())

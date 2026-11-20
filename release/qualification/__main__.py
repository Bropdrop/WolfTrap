"""Qualify signed evaluation bytes on a clean exact head in a proven network namespace."""

import argparse
import base64
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "release/verifier"))


def run(argv, *, cwd=ROOT, expected=0, source=False):
    env = {"PATH": os.defpath, "LC_ALL": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}
    if source:
        env["PYTHONPATH"] = str(ROOT / "src")
    r = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, capture_output=True, timeout=180)
    if r.returncode != expected:
        sys.stderr.write(r.stderr.decode(errors="replace")[-2000:] + r.stdout.decode(errors="replace")[-800:])
        raise ValueError("unexpected command status for " + Path(argv[0]).name)
    return r.stdout


def qualify(args):
    from release_client import host_profile
    from release_io import encode, pack, parse, sha
    from release_policy import PLATFORMS, wheel_name
    from release_cases import Corpus
    from release_fixtures import inputs, seal, source_file
    from reference import check, independent_witness
    from history import recover_history

    head = run(["git", "rev-parse", "HEAD"]).decode().strip()
    tree = run(["git", "rev-parse", "HEAD^{tree}"]).decode().strip()
    check(
        head == args.expected_head and not run(["git", "status", "--porcelain"]),
        "checkout must be clean and exact",
    )
    check(
        os.readlink("/proc/self/ns/net") != args.parent_netns
        and {n for _, n in socket.if_nameindex()} == {"lo"},
        "network isolation unavailable",
    )
    out = args.output_dir.absolute()
    check(out == out.resolve() and not out.is_relative_to(ROOT), "choose external evidence directory")
    out.mkdir(mode=0o700)
    (out / "capsule").mkdir(mode=0o700)
    (out / "trust").mkdir(mode=0o700)

    def save(n, value):
        (out / n).write_bytes(encode(value))

    start = time.monotonic()
    with tempfile.TemporaryDirectory() as temp:
        base = Path(temp)
        for label in ("build-a", "build-b"):
            run(
                [
                    sys.executable,
                    "-I",
                    ROOT / "scripts/build-product.py",
                    "--expected-head",
                    head,
                    "--wheelhouse",
                    args.wheelhouse.absolute(),
                    "--output-dir",
                    base / label,
                ]
            )
        first = base / "build-a"
        check(
            all(p.read_bytes() == (base / "build-b" / p.name).read_bytes() for p in first.iterdir()),
            "rebuild changed bytes",
        )
        version = "0.5.4.dev1"
        wheel = (first / wheel_name(version)).read_bytes()
        sbom = (first / "core.cdx.json").read_bytes()
        check(
            not args.expected_wheel_sha256 or args.expected_wheel_sha256 == sha(wheel),
            "upstream build digest mismatch",
        )
        lab = Corpus(base)
        controls = lab.score()
        save("controls.json", controls)
        material = inputs(head, tree)
        docs = {
            k: source_file(head, n)
            for k, n in (
                ("license_text", "LICENSE"),
                ("security", "SECURITY.md"),
                ("instructions", "docs/release-verification.md"),
                ("notes", "docs/release-notes-v1.md"),
            )
        }
        observed = int(time.time())
        body, record = seal(lab.issuer, wheel, sbom, version, 1, material, observed, **docs)
        bundle = pack(body)
        incoming = base / "download.zip"
        incoming.write_bytes(bundle)
        trust = lab.issuer.trust([record], observed)
        pin = sha(trust["policy.json"])
        for name, data in trust.items():
            (out / "trust" / name).write_bytes(data)
        verifier_files = (
            run(["git", "ls-tree", "--name-only", head + ":release/verifier"]).decode().splitlines()
        )
        check(
            set(verifier_files)
            == {"__main__.py", "release_client.py", "release_core.py", "release_io.py", "release_policy.py"},
            "unexpected verifier payload",
        )
        bootstrap = pack({n: source_file(head, "release/verifier/" + n) for n in verifier_files})
        (out / "reviewed-verifier.pyz").write_bytes(bootstrap)
        verifier = [sys.executable, "-I", out / "reviewed-verifier.pyz"]
        target = host_profile() or PLATFORMS[1]
        flags = [
            "--bundle",
            incoming,
            "--trust-dir",
            out / "trust",
            "--policy-sha256",
            pin,
            "--sequence",
            "1",
            "--minimum-sequence",
            "1",
            "--evaluation",
            "--platform",
            target,
        ]
        t = time.monotonic()
        result = json.loads(run([*verifier, "verify", *flags]))
        verify_seconds = time.monotonic() - t
        check(
            result["status"] == "VERIFIED"
            and result["commit"] == head
            and result["tree"] == tree
            and result["wheel_sha256"] == sha(wheel),
            "subscriber bindings",
        )
        refdir = base / "reference"
        refdir.mkdir()
        witness = independent_witness(bundle, trust, pin, head, tree, refdir)
        verdict = json.loads(run([*verifier, "retain", *flags, "--vault", out / "capsule"]))
        stored = out / "capsule" / verdict["retained_file"]
        check(stored.read_bytes() == bundle, "custody bytes changed")
        run([*verifier, "retain", *flags, "--vault", out / "capsule"], expected=1)
        incoming.write_bytes(bundle + b"modified")
        run([*verifier, "install", *flags, "--venv", base / "corrupt"], expected=1)
        check(not (base / "corrupt").exists(), "untrusted installation created a target")
        incoming.write_bytes(bundle)
        installed = False
        install_seconds = None
        first_seconds = None
        if host_profile():
            env = base / "subscriber"
            t = time.monotonic()
            install = json.loads(run([*verifier, "install", *flags, "--venv", env]))
            check(install["installed"], "verified install missing")
            install_seconds = time.monotonic() - t
            cli = env / "bin/wolftrap"
            doctor = json.loads(run([cli, "doctor", "--json"]))
            check(
                doctor["ready"] and doctor["build"]["commit"] == head and doctor["build"]["tree"] == tree,
                "installed source mismatch",
            )
            run([cli, "quickscan", "--demo", "--output-dir", base / "demo"], expected=1)
            first_seconds = time.monotonic() - t
            run(
                [
                    cli,
                    "verify-report",
                    "--demo",
                    "--evidence-dir",
                    base / "demo",
                    "--manifest-sha256",
                    sha((base / "demo/quickscan.manifest.json").read_bytes()),
                ]
            )
            check(len(json.loads(run([cli, "list-rules", "--json"]))) == 7, "covered rules changed")
            installed = True
        else:
            run([*verifier, "install", *flags, "--venv", base / "unqualified"], expected=2)
            check(not (base / "unqualified").exists(), "unsupported host installed")
        check(installed or not args.require_install, "a matching real installation was required")
        receipt = {
            "schema": "awooo.evaluation-recovery/v1",
            "commit": head,
            "tree": tree,
            "archive_sha256": sha(bundle),
            "policy_sha256": pin,
            "policy": parse(trust["policy.json"]),
            "root_certificate": trust["root.pem"].decode("ascii"),
            "signer_certificate": trust["signer.pem"].decode("ascii"),
            "signature_der_b64": base64.b64encode(body["provenance.p7s"]).decode(),
            "manifest": parse(body["release.json"]),
            "statement": parse(body["provenance.json"]),
        }
        save("receipt.json", receipt)
        restored = base / "restored-current.zip"
        run(
            [
                sys.executable,
                "-I",
                ROOT / "release/recover.py",
                "--source",
                ROOT,
                "--kit",
                first,
                "--record",
                out / "receipt.json",
                "--record-sha256",
                sha(encode(receipt)),
                "--output",
                restored,
            ]
        )
        check(restored.read_bytes() == bundle, "current signed transport recovery mismatch")
        history = recover_history(ROOT, base, args.wheelhouse.absolute(), run)
    save(
        "qualification.json",
        {
            "schema": "awooo.release-qualification/v1",
            "status": "VERIFIED_EVALUATION_ONLY",
            "commit": head,
            "tree": tree,
            "two_independent_builds": True,
            "verifier_git_tree": run(["git", "rev-parse", head + ":release/verifier"]).decode().strip(),
            "verifier_sha256": sha(bootstrap),
            "wheel_sha256": sha(wheel),
            "sbom_sha256": sha(sbom),
            "manifest_sha256": sha(body["release.json"]),
            "statement_sha256": sha(body["provenance.json"]),
            "controls": len(controls["cases"]),
            "expectation_mismatches": controls["mismatches"],
            "defective_verifiers_caught": len(controls["defective_verifiers"]),
            "second_implementation": witness,
            "production": "BLOCKED",
            "namespace": "loopback-only",
            "verified_before_install": True,
            "current_transport_restored": True,
            "archived_release": history,
        },
    )
    save(
        "measurement.json",
        {
            "schema": "awooo.release-measurement/v1",
            "commit": head,
            "tree": tree,
            "system": platform.freedesktop_os_release()["ID"],
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "openssl": run(["/usr/bin/openssl", "version"]).decode().strip(),
            "installed_on_matching_host": installed,
            "verify_seconds": round(verify_seconds, 4),
            "install_seconds": None if install_seconds is None else round(install_seconds, 4),
            "install_through_first_demo_seconds": None if first_seconds is None else round(first_seconds, 4),
            "total_qualification_seconds": round(time.monotonic() - start, 4),
            "human_onboarding": "NOT TESTED",
            "download": "measured separately outside namespace",
        },
    )
    run(
        [
            sys.executable,
            "-m",
            "wolftrap.public_guard",
            head,
            "--report-root",
            out,
            "--report",
            "qualification.json",
            "--report",
            "receipt.json",
            "--report",
            "controls.json",
            "--report",
            "measurement.json",
            "--report",
            "trust/policy.json",
        ],
        source=True,
    )
    check(not run(["git", "status", "--porcelain"]), "qualification dirtied source")
    print("VERIFIED_EVALUATION_ONLY", head, tree, "wheel", sha(wheel), "production BLOCKED")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--parent-netns", required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--expected-wheel-sha256")
    parser.add_argument("--require-install", action="store_true")
    qualify(parser.parse_args())

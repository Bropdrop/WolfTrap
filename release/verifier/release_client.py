"""Subscriber operations. Authentication completes before installation or custody."""

import argparse
import json
import os
from pathlib import Path
import platform
import secrets
import stat
import subprocess
import sys
import tempfile
import time

from release_core import verify
from release_io import BUNDLE_LIMIT, DOC_LIMIT, Verdict, directory, file_bytes, path, require
from release_policy import PLATFORMS, wheel_name


def host_profile():
    if (
        sys.platform == "linux"
        and platform.python_implementation() == "CPython"
        and platform.python_version() == "3.12.14"
    ):
        info = platform.freedesktop_os_release()
        value = "ubuntu-24.04-" + platform.machine() + "-cpython-3.12.14"
        if info.get("ID") == "ubuntu" and info.get("VERSION_ID") == "24.04" and value in PLATFORMS:
            return value
    return None


def private_directory(target):
    fd = directory(target)
    current = os.dup(fd)
    try:
        require(
            os.fstat(fd).st_uid == os.geteuid() and not os.fstat(fd).st_mode & 0o077,
            "use-private-owned-directory",
        )
        trusted = {os.geteuid(), os.stat("/").st_uid}
        for _ in range(66):
            info = os.fstat(current)
            require(
                info.st_uid in trusted and (not info.st_mode & 0o022 or info.st_mode & stat.S_ISVTX),
                "untrusted-output-ancestor",
            )
            parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=current)
            os.close(current)
            current = parent
            if os.path.samestat(info, os.fstat(parent)):
                return fd
        raise Verdict("REJECTED", "unsafe-output-depth")
    except BaseException:
        os.close(fd)
        raise
    finally:
        os.close(current)


def custody(vault, sequence, raw):
    return publish_new(vault, "awooo-evaluation-" + str(sequence).zfill(8) + ".zip", raw)


def publish_new(vault, final, raw):
    fd = private_directory(vault)
    stage = ".pending-" + secrets.token_hex(16)
    try:
        tmp = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400, dir_fd=fd)
        try:
            with os.fdopen(tmp, "wb") as f:
                f.write(raw)
                f.flush()
                os.fsync(f.fileno())
            try:
                os.link(stage, final, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            except FileExistsError:
                raise Verdict("REJECTED", "sequence-already-in-custody") from None
            os.fsync(fd)
        finally:
            os.unlink(stage, dir_fd=fd)
        return final
    finally:
        os.close(fd)


def install(dest, result, wheel, recheck):
    require(host_profile() == result["platform"], "unsupported-install-host", "INCONCLUSIVE")
    parent = private_directory(dest.parent)
    try:
        try:
            os.mkdir(dest.name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            raise Verdict("REJECTED", "use-fresh-environment") from None
        # Keep the verified bytes under caller-private custody. pip only receives
        # this copy with a required hash, even if distribution files are replaced.
        env = {
            "PATH": os.defpath,
            "LC_ALL": "C.UTF-8",
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_NO_INDEX": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONNOUSERSITE": "1",
        }
        with tempfile.TemporaryDirectory() as work:
            work = Path(work)
            (work / wheel_name(result["version"])).write_bytes(wheel)
            lock = work / "install.txt"
            lock.write_text(
                "wolftrap==" + result["version"] + " --hash=sha256:" + result["wheel_sha256"] + "\n"
            )
            subprocess.run(
                [sys.executable, "-I", "-m", "venv", dest],
                env=env,
                cwd=work,
                check=True,
                timeout=90,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            require(recheck()["policy_sha256"] == result["policy_sha256"], "trust-changed")
            subprocess.run(
                [
                    dest / "bin/python",
                    "-I",
                    "-m",
                    "pip",
                    "--isolated",
                    "install",
                    "--disable-pip-version-check",
                    "--no-cache-dir",
                    "--no-index",
                    "--no-deps",
                    "--only-binary=:all:",
                    "--require-hashes",
                    "--find-links",
                    work,
                    "-r",
                    lock,
                ],
                cwd=work,
                env=env,
                check=True,
                timeout=90,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    finally:
        os.close(parent)


def run(args):
    require(args.evaluation, "production-signing-and-review-unconfigured", "INCONCLUSIVE")
    require(
        sys.platform == "linux" and hasattr(os, "O_PATH"), "unsupported-verification-host", "INCONCLUSIVE"
    )
    target = args.platform or host_profile()
    require(target in PLATFORMS, "unqualified-platform", "INCONCLUSIVE")
    bundle, trust_dir = path(args.bundle), path(args.trust_dir)
    require(
        not bundle.is_relative_to(trust_dir) and not trust_dir.is_relative_to(bundle),
        "trust-must-be-independent",
    )
    mode = args.purpose
    if args.command == "install":
        require(mode != "historical", "historical-audit-only")
    raw = file_bytes(bundle, BUNDLE_LIMIT)

    def check():
        trust = {k: file_bytes(trust_dir / k, DOC_LIMIT) for k in ("policy.json", "root.pem", "signer.pem")}
        return verify(
            raw, trust, args.policy_sha256, args.minimum_sequence, args.sequence, mode, int(time.time())
        )

    result, wheel = check()
    result["platform"] = target
    if args.command != "verify":
        dest = path(args.venv if args.command == "install" else args.vault)
        require(
            not dest.is_relative_to(trust_dir)
            and not trust_dir.is_relative_to(dest)
            and not bundle.is_relative_to(dest)
            and dest != bundle,
            "overlapping-destination",
        )
        if args.command == "install":
            install(dest, result, wheel, lambda: check()[0])
            result["installed"] = True
        else:
            result["retained_file"] = custody(dest, args.sequence, raw)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Independent pre-install release verification. Production trust is unavailable in v1."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("verify", "install", "retain"):
        cmd = commands.add_parser(name)
        cmd.add_argument("--bundle", required=True, help="downloaded local evaluation capsule ZIP")
        cmd.add_argument(
            "--trust-dir", required=True, help="separately obtained policy and pinned public certificates"
        )
        cmd.add_argument(
            "--policy-sha256", required=True, help="subscriber's independently authenticated policy pin"
        )
        cmd.add_argument(
            "--minimum-sequence", required=True, type=int, help="current subscriber high-water mark"
        )
        cmd.add_argument(
            "--sequence", required=True, type=int, help="exact subscriber-selected release sequence"
        )
        cmd.add_argument("--purpose", choices=("current", "historical", "rollback"), default="current")
        cmd.add_argument(
            "--platform",
            help="qualified Ubuntu target profile for audit; install also checks the actual host",
        )
        cmd.add_argument(
            "--evaluation",
            action="store_true",
            help="explicitly select synthetic trust and evaluation-only use",
        )
        if name == "install":
            cmd.add_argument(
                "--venv", required=True, help="new environment under an existing private directory"
            )
        if name == "retain":
            cmd.add_argument(
                "--vault", required=True, help="existing private directory for write-once local custody"
            )
    args = parser.parse_args(argv)
    try:
        result = run(args)
    except Verdict as exc:
        result = {"status": exc.status, "reason": exc.reason}
    except (OSError, ValueError, subprocess.SubprocessError):
        result = {"status": "INCONCLUSIVE", "reason": "local-input-provider-or-install-unavailable"}
    print(json.dumps(result, sort_keys=True))
    return {"VERIFIED": 0, "REJECTED": 1, "INCONCLUSIVE": 2}[result["status"]]

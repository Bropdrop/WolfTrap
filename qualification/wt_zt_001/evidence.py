"""Build or replay a bounded fixture bundle from an independently selected Git revision."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import stat
import subprocess
import sys
import tempfile
from importlib.metadata import version

LAB = Path(__file__).resolve().parent
REPO = LAB.parents[1]
PROFILE = "wt-zt-evidence/1"
LAB_FILES = ("experiment.py", "host.py", "oracle.py", "fixtures.py", "recovery.py",
             "cases.json", "offline.py", "evidence.py")
MEMBERS = {"assessment.json", "assessment.md", "manifest.json"}


def encode(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + "\n").encode()


def metadata(content):
    return {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}


def git(*args):
    return subprocess.check_output(["git", "--no-replace-objects", "-C", str(REPO), *args])


def expected(pin):
    if not re.fullmatch("[0-9a-f]{40}", pin) or git("rev-parse", pin + "^{commit}").decode().strip() != pin:
        raise ValueError("exact externally selected commit required")
    tree = git("rev-parse", pin + "^{tree}").decode().strip()
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        lab = work / "qualification/wt_zt_001"
        lab.mkdir(parents=True)
        src = work / "src/wolftrap"
        src.mkdir(parents=True)
        for dest in [*(lab / f for f in LAB_FILES), src / "__init__.py", src / "canonical.py"]:
            rel = dest.relative_to(work).as_posix()
            dest.write_bytes(git("cat-file", "blob", pin + ":" + rel))
        if (lab / "evidence.py").read_bytes() != Path(__file__).read_bytes():
            raise ValueError("incompatible verifier")
        cmd = [sys.executable, "-I", "qualification/wt_zt_001/offline.py", sys.executable,
               "qualification/wt_zt_001/experiment.py"]
        env = dict(PATH=os.defpath, HOME=tmp, TMPDIR=tmp, PYTHONPATH=str(work / "src"),
                   PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", PYTHONHASHSEED="0")
        child = subprocess.run(cmd, cwd=tmp, env=env, capture_output=True, timeout=120)
        if child.returncode:
            raise ValueError("fixture execution incomplete or control gap")
        cases = json.loads(child.stdout)
    report = dict(profile=PROFILE, scanner="wt-zt-host/1", verifier="wt-zt-oracle/1",
                  source=dict(repository="Bropdrop/WolfTrap", github_id=1436465132, commit=pin, tree=tree),
                  scope="pinned fictional casebook only", confidence="SYNTHETICALLY_VERIFIED",
                  operational_outcome="NO_PATTERN_MATCH", command=["python", *cmd[1:3], "python", cmd[-1]],
                  exit_status=child.returncode, cases=cases, platform=platform.system(), arch=platform.machine(),
                  python=platform.python_version(), sqlite=sqlite3.sqlite_version, PyJWT=version("PyJWT"),
                  cryptography=version("cryptography"), isolation="libseccomp denies socket/socketpair/connect/io_uring_setup",
                  witnesses=["owner", "policy"], issuer="issuer",
                  limitations=["Distinct fixture keys and roles share a trusted test runner.",
                               "Logical clock and a single durable SQLite host are assumed.",
                               "Issuer authenticates a statement. Live workload possession is untested.",
                               "No custodial independence, external payment, legal fact or production provenance established."])
    md = ["# WT-ZT-001 synthetic qualification", "", f"Source `{pin}`, tree `{tree}`.",
          "", "| Case | Host ledger rows | Oracle |", "|---|---:|---|"]
    md += [f"| {c['id']} | {len(c['after']['effects'])} | {c['oracle']} |" for c in cases]
    md += ["", *report["limitations"]]
    files = {"assessment.json": encode(report), "assessment.md": ("\n".join(md) + "\n").encode()}
    files["manifest.json"] = encode(dict(profile=PROFILE, source=report["source"],
                                         members={k: metadata(v) for k, v in files.items()}))
    return files


def directory(path, create):
    # Descriptor-relative walk. Keep each opened parent pinned while selecting its child.
    if ".." in path.parts:
        raise ValueError("parent traversal")
    path = path.absolute()
    if path == REPO or REPO in path.parents or path in REPO.parents:
        raise ValueError("evidence must be outside the checkout")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open("/", flags)
    try:
        for i, part in enumerate(path.parts[1:], 1):
            if create and i == len(path.parts) - 1:
                os.mkdir(part, mode=0o700, dir_fd=fd)
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def verify(fd, files):
    if set(os.listdir(fd)) != MEMBERS:
        raise ValueError("unexpected artifact inventory")
    for name, content in files.items():
        item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(item, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != len(content):
                raise ValueError("invalid artifact")
            if stream.read(len(content) + 1) != content:
                raise ValueError("evidence contradicts independent replay")
            if not os.path.samestat(info, os.stat(name, dir_fd=fd, follow_symlinks=False)):
                raise ValueError("artifact replaced during read")
    if set(os.listdir(fd)) != MEMBERS:
        raise ValueError("artifact inventory changed")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create", "verify"))
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        files = expected(args.expected_commit)
        fd = directory(args.evidence_dir, args.action == "create")
        try:
            if args.action == "create":
                for name, content in files.items():
                    member = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                     0o600, dir_fd=fd)
                    with os.fdopen(member, "wb") as stream:
                        stream.write(content)
                        stream.flush()
                        os.fsync(stream.fileno())
                os.fsync(fd)
            verify(fd, files)
        finally:
            os.close(fd)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f"INCONCLUSIVE ({type(exc).__name__})", file=sys.stderr)
        return 2
    print("SYNTHETICALLY_VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

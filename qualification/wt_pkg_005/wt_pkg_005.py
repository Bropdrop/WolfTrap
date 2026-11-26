#!/usr/bin/env python3
"""Build and qualify the pinned WolfTrap evaluation assembly using local Git objects."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import traceback
import zipfile


CURRENT = (
    "4d39dbee2aca4a680cd1a916bc4beb0f54cccb30",
    "a04d65fd3535c74ea8991e557b14d1e6899caa8e",
    "ee05c9f82ebc718973fa8b937c776be093c77c15bb1b0209bf004177e3d489f0",
)
PREVIOUS = (
    "7522d75c0c258f79a2f35b46a9afb72083a19c67",
    "31bdb25120bba8881c5b9adee31576446153d348",
    "b74eaaeb1af8860582e5c5f9e12c6301fbf843e05de285d10166db287c61428d",
)
ASSEMBLY_SHA = "f4d6188d47bb6c4fdcde3c76b54cb5ac0430c927d3d43b82b15b79c427c535dd"
REFERENCE_SHA = "3421ee83fb916dba6177bf21709d2ff9a24839f9d2a8b4e77eba8a708b980877"
ZIP_NAME = "wolftrap-wt-pkg-005-linux-evaluation.zip"
INNER = "adapter/wolftrap-local-evaluation-0.3.0.zip"
Q = Path("qualification/wt_mcp_002")
PLUGIN = "plugins/wolftrap-security/"
REVIEW = (
    "LICENSE", str(Q / "README.md"), str(Q / "audit.py"), str(Q / "reference.json"),
    PLUGIN + "README.md", PLUGIN + "UPGRADES.md", PLUGIN + "plugin.json",
    PLUGIN + "skills/wolftrap-audit/SKILL.md",
    PLUGIN + "skills/wolftrap-evidence-review/SKILL.md",
)
PYTHON = "/usr/bin/python3.13"
ENV = {"PATH": os.defpath, "LC_ALL": "C", "GIT_NO_REPLACE_OBJECTS": "1"}


class Blocked(Exception):
    pass


def check(condition, reason):
    if not condition:
        raise Blocked(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(args, *, data=None, timeout=90):
    return subprocess.run(args, input=data, capture_output=True, env=ENV, timeout=timeout)


def git(repo, *args):
    result = run(["git", "-C", repo, *args])
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, result.args, result.stdout, result.stderr)
    return result.stdout


def checkout(repo, root, pin):
    commit, tree, _ = pin
    check(git(repo, "rev-parse", "--verify", commit + "^{tree}").strip() == tree.encode(), "SOURCE_TREE")
    git(repo, "-c", "core.hooksPath=/dev/null", "worktree", "add", "--detach", root, commit)
    check(git(root, "rev-parse", "HEAD", "HEAD^{tree}").decode().splitlines() == [commit, tree], "SOURCE_CHECKOUT")


def adapter(root, pin, temp, name):
    check(not temp.exists(), "BUILD_OUTPUT_EXISTS")
    result = run([sys.executable, "-EBS", root / Q / "package.py", "build",
                  "--commit", pin[0], "--zip", temp])
    check(result.returncode == 0, "ADAPTER_BUILD_" + name)
    data = temp.read_bytes()
    check(sha(data) == pin[2], "ADAPTER_DIGEST_" + name)
    return data


def assemble(root, inner):
    files = {name: git(root, "show", f"{CURRENT[0]}:{name}") for name in REVIEW}
    files[INNER] = inner
    # Preserve the WT-MCP-004 receipt and ZIP bytes. Qualification status belongs in result.json.
    receipt = {"schema": "wolftrap.linux-review-assembly/v1", "commit": CURRENT[0], "tree": CURRENT[1],
               "purpose": "private Linux evaluation", "qualification": "BLOCK",
               "members": {name: {"bytes": len(data), "sha256": sha(data)} for name, data in files.items()}}
    files["assembly-receipt.json"] = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    result = buffer.getvalue()
    check(sha(result) == ASSEMBLY_SHA, "ASSEMBLY_DIGEST")
    return result


def matches(path, expected):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        info = os.fstat(stream.fileno())
        return (stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == len(expected)
                and stream.read(len(expected) + 1) == expected)


def members(pinned_bytes):
    # All callers have independently checked these exact bytes against a fixed digest.
    with zipfile.ZipFile(io.BytesIO(pinned_bytes)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def verify_install(root, files):
    directories = {p for name in files for p in Path(name).parents if p != Path(".")}
    found = {p.relative_to(root) for p in root.rglob("*")}
    check(found == directories | {Path(name) for name in files}, "INSTALLED_INVENTORY")
    for directory in directories:
        check(stat.S_ISDIR((root / directory).lstat().st_mode), "INSTALLED_DIRECTORY")
    for name, expected in files.items():
        check(matches(root / name, expected), "INSTALLED_BYTES")


def install(root, files):
    # The parent is a private, disposable directory created by this run.
    root.mkdir(mode=0o700)
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("xb") as stream:
            stream.write(data)
    verify_install(root, files)


def capture(result, log):
    log.write_bytes(result.stdout + b"\n" + result.stderr)


def namespace_failure(stderr):
    if b"setting up uid map" in stderr:
        if b"Read-only file system" in stderr:
            return "UID_MAP_READ_ONLY"
        if b"Operation not permitted" in stderr or b"Permission denied" in stderr:
            return "UID_MAP_PERMISSION_DENIED"
        return "UID_MAP_UNAVAILABLE"
    return "BUBBLEWRAP_ISOLATION_UNAVAILABLE"


def preflight(private, hosted):
    check(os.geteuid() != 0 and platform.system() == "Linux" and platform.machine() == "x86_64",
          "LINUX_X86_64_UNPRIVILEGED_REQUIRED")
    if hosted:
        check({name for _, name in socket.if_nameindex()} == {"lo"}, "HOSTED_EGRESS_ISOLATION_REQUIRED")
    check(Path(PYTHON).is_file() and Path("/usr/lib/python3.13").is_dir(), "DEBIAN_CPYTHON_313_REQUIRED")
    check(Path("/usr/bin/bwrap").is_file(), "BUBBLEWRAP_REQUIRED")
    from sibling import LIBS, base

    check(all((Path("/usr/lib/x86_64-linux-gnu") / lib).is_file() for lib in LIBS)
          and Path("/lib64/ld-linux-x86-64.so.2").is_file(), "PINNED_RUNTIME_LIBRARY_LAYOUT_REQUIRED")
    capture(run([PYTHON, "--version"]), private / "python-version.log")
    capture(run(["/usr/bin/bwrap", "--version"]), private / "bubblewrap-version.log")
    (private / "kernel.txt").write_text(platform.release() + "\n")
    kinds = ("user", "mnt", "net")
    outside = [os.readlink("/proc/self/ns/" + kind) for kind in kinds]
    probe = (
        "import os, socket, sys\n"
        "isolated = all(os.readlink('/proc/self/ns/' + kind) != old "
        "for kind, old in zip(('user', 'mnt', 'net'), sys.argv[1:], strict=True))\n"
        "sys.exit(0 if isolated and set(name for _, name in socket.if_nameindex()) == {'lo'} else 2)\n"
    )
    result = run(base(True) + ["--proc", "/proc", "--dev", "/dev", "--remount-ro", "/", "--",
                               PYTHON, "-IBS", "-c", probe, *outside], timeout=20)
    capture(result, private / "sandbox-preflight.log")
    check(result.returncode == 0, namespace_failure(result.stderr))


def mcp(root, runtime, policy, state, private, label, calls, catalog=None):
    from profile import encode, sha

    client = "wt-pkg-005-local-wire"
    measure = (
        "import sys; sys.path.insert(0, sys.argv[1]); "
        "from reference_pin import expected_configuration; from pathlib import Path; "
        "print(expected_configuration(Path(sys.argv[2]), sys.argv[3]))"
    )
    measured = run([PYTHON, "-IBS", "-c", measure, root / Q, runtime / Q, client])
    capture(measured, private / (label + "-profile.log"))
    check(measured.returncode == 0, label + "_PROFILE")
    owner = sha(encode(policy))
    command = [PYTHON, "-IBS", root / Q / "launch.py", state, "--install", runtime,
               "--owner-pin", owner, "--qualified-pin", measured.stdout.decode().strip(),
               "--session", policy["session"], "--client", client]
    methods = [("initialize", {"protocolVersion": "2025-11-25", "capabilities": {},
                              "clientInfo": {"name": client, "version": "1"}})]
    if catalog is not None:
        methods.append(("tools/list", {}))
    methods.extend(("tools/call", {"name": tool, "arguments": args}) for tool, args, _ in calls)
    frames = []
    for rid, (method, params) in enumerate(methods, 1):
        frames.append(encode({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}))
        if rid == 1:
            frames.append(encode({"jsonrpc": "2.0", "method": "notifications/initialized"}))
    result = run(command, data=b"\n".join(frames) + b"\n", timeout=115)
    capture(result, private / (label + "-mcp.log"))
    if result.returncode:
        cause = "_" + namespace_failure(result.stderr) if b"bwrap:" in result.stderr else ""
        raise Blocked(label + "_LAUNCH" + cause)
    replies = [json.loads(line) for line in result.stdout.splitlines()]
    check(len(replies) == len(methods), label + "_REPLY_COUNT")
    for rid, reply in enumerate(replies, 1):
        check(reply.get("jsonrpc") == "2.0" and reply.get("id") == rid, label + "_REPLY_ID")
    check(replies[0].get("result", {}).get("protocolVersion") == "2025-11-25", label + "_INITIALIZE")
    if catalog is not None:
        check(replies[1].get("result") == catalog, label + "_CATALOG")
    for reply, (_, _, expected) in zip(replies[len(methods) - len(calls):], calls, strict=True):
        actual = reply.get("result", {}).get("structuredContent", {}).get("status")
        check(actual == expected, label + "_STATUS_" + expected)


def audit(root, state, policy, private, label):
    from profile import encode, sha

    result = run([PYTHON, "-IBS", root / Q / "audit.py", "--state", state, "--handle", "alpha",
                  "--owner-pin", sha(encode(policy)), "--reference-pin", REFERENCE_SHA])
    capture(result, private / (label + "-audit.log"))
    check(result.returncode == 0 and json.loads(result.stdout)["status"] == "VERIFIED_COMMIT",
          label + "_INDEPENDENT_AUDIT")


def device(action, root, old, current, previous, private, summary, hosted):
    sys.path.insert(0, str(root / Q))
    preflight(private, hosted)
    summary["checks"]["isolated_namespace_preflight"] = "PASS"
    from fixtures import arguments, provision, revoke
    from profile import CAP, CATALOG, SCAN, VERIFY, encode, sha
    from trials import observe

    state = private / "state"
    policy = provision(state)
    pins = {"owner_sha256": sha(encode(policy)), "reference_sha256": REFERENCE_SHA}
    (private / "audit-pins.json").write_text(json.dumps(pins) + "\n")
    scan = arguments(policy, SCAN, "alpha")

    def snapshot():
        return [observe(state, handle) for handle in ("alpha", "beta")]

    before = snapshot()
    mcp(root, current / "adapter", policy, state, private, "candidate-denial",
        [(SCAN, {**scan, "task": "unrelated"}, "DENIED")], catalog=CATALOG)
    check(before == [{"journal": [], "files": {}}] * 2 and snapshot() == before, "DENIAL_NO_EFFECT")
    summary["checks"]["discovery_and_denial"] = "PASS"
    mcp(root, current / "adapter", policy, state, private, "candidate-authorized", [
        (CAP, arguments(policy, CAP, "alpha"), "AVAILABLE"),
        (SCAN, scan, "COMMITTED"), (SCAN, scan, "ALREADY_COMMITTED"),
        (VERIFY, arguments(policy, VERIFY, "alpha"), "VERIFIED"),
    ])
    committed = snapshot()
    phases = [row[1] for row in committed[0]["journal"]]
    check(phases == ["DISPATCH", "LISTED", "DISPATCH", "COMMITTED", "DISPATCH", "VERIFIED"]
          and committed[1] == before[1], "COMMITTED_EFFECTS")
    audit(current / "review", state, policy, private, "assembled")
    summary["checks"]["authorized_scan_retry_replay_and_audit"] = "PASS"
    summary["mcp_outcomes"] = ["DENIED", "AVAILABLE", "COMMITTED", "ALREADY_COMMITTED", "VERIFIED"]

    if action == "stateful-rollback":
        try:
            # Switch only the measured installation. Preserve the live journal, source and generation.
            mcp(old, previous, policy, state, private, "prior-live-state",
                [(SCAN, scan, "ALREADY_COMMITTED")], catalog=CATALOG)
            summary["checks"]["prior_live_state_retry"] = "ALREADY_COMMITTED"
            revoke(state)
            mcp(old, previous, policy, state, private, "prior-revoked-state", [(SCAN, scan, "DENIED")])
            summary["checks"]["prior_revoked_state_retry"] = "DENIED"
        finally:
            check(snapshot() == committed, "ROLLBACK_CHANGED_EFFECTS")
        audit(root, state, policy, private, "after-stateful-rollback")
        summary["checks"]["stateful_reuse_and_revocation"] = "PASS"

    if hosted:
        from confinement import run as confinement_checks
        from supervisor_controls import run as supervisor_checks

        checks = {"workers": confinement_checks(), "broker": supervisor_checks()}
        (private / "confinement.json").write_text(json.dumps(checks) + "\n")
        summary["checks"]["independent_confinement_canaries"] = "PASS"
    return state, policy


def execute(args, source, output, private, summary):
    with tempfile.TemporaryDirectory(dir=private) as temp:
        scratch = Path(temp)
        repo = scratch / "repo"
        git(source, "-c", "core.hooksPath=/dev/null", "clone", "--no-hardlinks", "--no-checkout", "--", source, repo)
        root, old = scratch / "pr34", scratch / "pr33"
        checkout(repo, root, CURRENT)
        inner = adapter(root, CURRENT, scratch / "current.zip", "PR34")
        expected = assemble(root, inner)
        if args.zip:
            check(matches(args.zip, expected), "TRANSPORT_BYTES")
        (output / ZIP_NAME).write_bytes(expected)
        summary["checks"]["assembly_integrity"] = "PASS"
        if args.action == "build":
            return

        if args.action == "portable":
            again = adapter(root, CURRENT, scratch / "current-again.zip", "PR34")
            check(assemble(root, again) == expected, "REBUILD_DIFFERS")
            changed = scratch / "changed.zip"
            changed.write_bytes(expected[:-1] + bytes([expected[-1] ^ 1]))
            check(not matches(changed, expected), "SUBSTITUTED_TRANSPORT_ACCEPTED")
            summary["checks"]["rebuild_and_substitution_rejection"] = "PASS"

        checkout(repo, old, PREVIOUS)
        prior_files = members(adapter(old, PREVIOUS, scratch / "previous.zip", "PR33"))
        current_files = {f"review/{name}": data for name, data in members(expected).items()}
        current_files.update({f"adapter/{name}": data for name, data in members(inner).items()})
        current, previous = scratch / "current-install", scratch / "previous-install"
        install(previous, prior_files)
        install(current, current_files)
        summary["checks"]["clean_installation"] = "PASS"

        state = policy = None
        if args.action != "portable":
            state, policy = device(args.action, root, old, current, previous, private, summary, args.hosted)
        verify_install(current, current_files)
        shutil.rmtree(current)
        check(not current.exists(), "UNINSTALL")
        verify_install(previous, prior_files)
        summary["checks"]["uninstall_and_file_rollback"] = "PASS"
        if state is not None:
            audit(root, state, policy, private, "retained-after-uninstall")
            summary["checks"]["evidence_after_uninstall"] = "PASS"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "portable", "qualify", "stateful-rollback"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True, help="fresh directory outside the source checkout")
    parser.add_argument("--zip", type=Path, help="compare a transported ZIP with the pinned reconstruction")
    parser.add_argument("--hosted", action="store_true", help="require an outer egress-isolated CI runner")
    args = parser.parse_args()
    if args.hosted and args.action != "qualify":
        parser.error("--hosted requires qualify")
    os.umask(0o077)
    source = args.source.resolve(strict=True)
    output = args.output.absolute()
    if output != output.resolve() or output.is_relative_to(source) or output.exists():
        parser.error("choose a fresh canonical output directory outside the source checkout")
    output.mkdir(mode=0o700)
    private = output / "private"
    private.mkdir(mode=0o700)
    summary = {"schema": "wolftrap.wt-pkg-005/v1", "phase": args.action, "source_commit": CURRENT[0],
               "source_tree": CURRENT[1], "assembly_sha256": ASSEMBLY_SHA, "previous_commit": PREVIOUS[0],
               "driver_sha256": sha(Path(__file__).read_bytes()),
               "checks": {}, "verdict": "BLOCK", "real_model": "NOT_TESTED", "public_release": "BLOCK"}
    try:
        execute(args, source, output, private, summary)
        summary["verdict"] = "PASS"
    except Blocked as exc:
        summary["reason"] = str(exc)
    except (OSError, ValueError, KeyError, TypeError, AssertionError, subprocess.SubprocessError) as exc:
        summary["reason"] = "EXECUTION_" + type(exc).__name__
        (private / "failure.log").write_text(traceback.format_exc())
    (output / "result.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary, sort_keys=True))
    return 0 if summary["verdict"] == "PASS" else 2


if __name__ == "__main__":
    sys.exit(main())

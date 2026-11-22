"""POSIX descriptor-relative capture selection and evidence replay for GeoTrace."""
from contextlib import contextmanager
import hmac
import os
from pathlib import Path
import re
import stat
import sys

from . import __version__, geotrace as geo
from .agent_scan import _json, _open_directory

LIMIT = 262144


@contextmanager
def directory(path):
    fd = _open_directory(path)
    try:
        yield fd
    finally:
        os.close(fd)


def read_member(parent, name, limit):
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(fd)
        geo.require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and 0 < before.st_size <= limit)
        data = stream.read(before.st_size + 1)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        geo.require(len(data) == before.st_size and os.path.samestat(before, after)
                    and before.st_ctime_ns == after.st_ctime_ns)
        return data


def absolute(value):
    path = Path(value)
    geo.require(path.is_absolute() and path.anchor == "/" and ".." not in path.parts)
    return path


def artifacts(report):
    status = report["outcome"]
    files = {"geotrace.json": _json(report),
             "geotrace.md": (f"# GeoTrace v2\n\n{status} across {len(report['events'])} events.\n\n"
                             "Country observations are claims. Action authorization was not evaluated.\n").encode()}
    signals = []
    for row in report["events"]:
        for dim, result in sorted(row["policy_results"].items()):
            if result != "NO_PATTERN_MATCH":
                signals.append({"ruleId": "WT-GEO-" + dim.upper(), "level":"warning",
                                "message":{"text":f"Event {row['event_index']}: {dim} {result}."}})
    files["geotrace.sarif"] = _json({"version":"2.1.0","runs":[{
        "tool":{"driver":{"name":"WolfTrap GeoTrace","version":__version__}}, "results":signals}]})
    files["manifest.json"] = _json({"schema":"wolftrap.geotrace-manifest/v2", "files":{
        name:{"bytes":len(data),"sha256":geo.digest(data)} for name,data in files.items()}})
    return files


def inspect(args):
    root = absolute(args.root)
    policy = absolute(args.policy)
    output = absolute(args.directory)
    checkout = Path(__file__).resolve().parents[2]
    geo.require(root != Path("/") and not policy.is_relative_to(root) and not output.is_relative_to(root)
                and not root.is_relative_to(output) and not output.is_relative_to(checkout)
                and not policy.is_relative_to(output))
    # Input filenames are explicit JSON selections. No traversal or filesystem discovery.
    pieces = args.file.split("/")
    geo.require(1 <= len(pieces) <= 16 and all(re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,127}", part)
                for part in pieces) and pieces[-1].endswith(".json"))
    geo.require(re.fullmatch(r"[0-9a-f]{64}", args.policy_sha256))
    with directory(policy.parent) as fd:
        policy_raw = read_member(fd, policy.name, 16384)
    geo.require(hmac.compare_digest(geo.digest(policy_raw), args.policy_sha256))
    with directory(root.joinpath(*pieces[:-1])) as fd:
        raw = read_member(fd, pieces[-1], LIMIT)
    source = geo.parse(raw)
    geo.require(isinstance(source, dict))
    report = geo.evaluate(source, geo.parse(policy_raw), args.as_of)
    report.update(engine_version=__version__, input_sha256=geo.digest(raw),
                  selection_sha256=geo.digest(args.file.encode()), policy_sha256=args.policy_sha256)
    files = artifacts(report)
    creating = args.command == "scan-geotrace"
    with directory(output.parent) as parent:
        if creating:
            # Other users must not be able to substitute the newly created evidence directory.
            parent_stat = os.fstat(parent)
            geo.require(parent_stat.st_uid in (0, os.geteuid()) and
                        (not parent_stat.st_mode & 0o022 or parent_stat.st_mode & stat.S_ISVTX))
            os.mkdir(output.name, 0o700, dir_fd=parent)
        handle = os.open(output.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent)
        try:
            if creating:
                for name, data in files.items():  # Manifest is written last; partial sets fail replay.
                    fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_CREAT | os.O_EXCL,
                                 0o600, dir_fd=handle)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(data)
                        stream.flush()
                        os.fsync(fd)
                os.fsync(handle)
                os.fsync(parent)
            geo.require(set(os.listdir(handle)) == set(files))
            for name, data in files.items():
                geo.require(read_member(handle, name, len(data)) == data)
            geo.require(set(os.listdir(handle)) == set(files) and
                        os.path.samestat(os.fstat(handle), os.stat(output.name, dir_fd=parent, follow_symlinks=False)))
        finally:
            os.close(handle)
    return report["outcome"]


def run(args):
    try:
        outcome = inspect(args)
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, OverflowError):
        # Untrusted paths, JSON keys, provider names and credential-shaped strings stay off stderr.
        print("INCONCLUSIVE: unsupported input, policy, path or evidence", file=sys.stderr)
        return 2
    if args.command == "verify-geotrace":
        print(f"VERIFIED_EVIDENCE: {outcome}")
        return 0
    print(outcome)
    return {"NO_PATTERN_MATCH":0, "REVIEW_REQUIRED":1, "INCONCLUSIVE":2}[outcome]


def configure(subparsers):
    for cmd, output_arg in (("scan-geotrace","--output-dir"), ("verify-geotrace","--evidence-dir")):
        parser = subparsers.add_parser(cmd, help="offline GeoTrace v2 country evidence and policy review")
        parser.add_argument("--root", required=True, help="absolute authorized capture root")
        parser.add_argument("--file", required=True, help="one root-relative JSON capture")
        parser.add_argument("--policy", required=True, help="absolute owner-selected JSON policy outside capture root")
        parser.add_argument("--policy-sha256", required=True, help="independently selected expected policy digest")
        parser.add_argument("--as-of", required=True, help="operator-selected YYYY-MM-DD evaluation date")
        parser.add_argument(output_arg, dest="directory", required=True, help="absolute external evidence directory")
        parser.set_defaults(handler=run)

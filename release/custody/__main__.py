"""Verify, replicate and recover a local disposable evaluation archive."""

import argparse
from pathlib import Path
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "verifier"))
from archive_store import GENESIS, admit, audit, distinct, replicate, restore
from release_client import publish_new
from release_io import BUNDLE_LIMIT, DOC_LIMIT, Verdict, encode, file_bytes, path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("genesis", help="Print the versioned empty-archive checkpoint")
    for name in ("admit", "reconcile", "audit", "replicate", "restore"):
        action = commands.add_parser(name)
        action.add_argument("--vault", required=True)
        action.add_argument(
            "--sequence", required=True, type=int, help="Independently retained head sequence"
        )
        action.add_argument("--index-sha256", required=True, help="Independently retained head index digest")
        if name == "replicate":
            action.add_argument("--replica", required=True)
        if name == "restore":
            action.add_argument("--release-sequence", required=True, type=int)
            action.add_argument("--output", required=True)
        if name in ("admit", "reconcile"):
            action.add_argument(
                "--minimum-policy-generation", type=int, help="Subscriber incident policy high-water mark"
            )
            for option in ("bundle", "trust-dir", "policy-sha256"):
                action.add_argument("--" + option, required=True)
    exercise = commands.add_parser("exercise", help="Run the disposable disaster-recovery exercise")
    exercise.add_argument("--output", required=True, help="Fresh file in a private directory")
    args = parser.parse_args()
    try:
        if args.command == "genesis":
            result = {"sequence": 0, "index_sha256": GENESIS}
        elif args.command == "exercise":
            from disaster_exercise import run

            result = run()
            dest = path(args.output)
            publish_new(dest.parent, dest.name, encode(result))
        else:
            common = (args.sequence, args.index_sha256)
            if args.command == "audit":
                result = audit(args.vault, *common)
            elif args.command in ("admit", "reconcile"):
                trust_dir = path(args.trust_dir)
                distinct(args.bundle, trust_dir, args.vault)
                trust = {
                    k: file_bytes(trust_dir / k, DOC_LIMIT) for k in ("policy.json", "root.pem", "signer.pem")
                }
                result = admit(
                    args.vault,
                    file_bytes(args.bundle, BUNDLE_LIMIT),
                    trust,
                    args.policy_sha256,
                    *common,
                    int(time.time()),
                    reconcile=args.command == "reconcile",
                    minimum_generation=args.minimum_policy_generation,
                )
            elif args.command == "replicate":
                result = replicate(args.vault, args.replica, *common)
            else:
                result = restore(args.vault, *common, args.release_sequence, args.output)
    except Verdict as exc:
        print(encode({"status": exc.status, "reason": exc.reason}).decode(), end="")
        return 1 if exc.status == "REJECTED" else 2
    except (OSError, ValueError, subprocess.SubprocessError):
        print('{"status":"INCONCLUSIVE","reason":"local-io-or-unsupported-input"}')
        return 2
    print(encode(result).decode(), end="")
    return int(result.get("status") == "EXERCISE_FAILED")


if __name__ == "__main__":
    sys.exit(main())

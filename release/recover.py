"""Reconstitute a historical evaluation capsule from a pinned public receipt, Git and a rebuilt kit."""

import argparse
import base64
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "verifier"))
from release_io import DOC_LIMIT, WHEEL_LIMIT, Verdict, encode, file_bytes, pack, parse, path, require, sha
from release_policy import hexval, wheel_name


def recover(source, kit, raw, pin):
    require(sha(raw) == pin, "wrong-recovery-record")
    rec = parse(raw)
    require(
        type(rec) is dict and type(rec.get("manifest")) is dict and type(rec.get("statement")) is dict,
        "recovery-schema",
    )
    require(
        rec["schema"] == "awooo.evaluation-recovery/v1"
        and all(hexval(rec[k], 40) for k in ("commit", "tree")),
        "recovery-schema",
    )
    env = {
        "PATH": os.defpath,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
    }

    def git(*args):
        return subprocess.check_output(["git", *args], cwd=source, env=env, timeout=10)

    head = rec["commit"]
    require(
        git("rev-parse", "HEAD").decode().strip() == head
        and git("rev-parse", "HEAD^{tree}").decode().strip() == rec["tree"],
        "wrong-recovery-source",
    )
    m = rec["manifest"]
    name = wheel_name(m["version"])
    entries = {
        name: file_bytes(kit / name, WHEEL_LIMIT),
        "core.cdx.json": file_bytes(kit / "core.cdx.json", DOC_LIMIT),
        "release.json": encode(m),
        "provenance.json": encode(rec["statement"]),
        "provenance.p7s": base64.b64decode(rec["signature_der_b64"], validate=True),
        "platforms.json": encode(
            rec["statement"]["predicate"]["buildDefinition"]["externalParameters"]["declaredPlatforms"]
        ),
    }
    for n, rel in (
        ("LICENSE", "LICENSE"),
        ("SECURITY.md", "SECURITY.md"),
        ("VERIFY.md", "docs/release-verification.md"),
        ("RELEASE-NOTES.md", "docs/release-notes-v1.md"),
    ):
        entries[n] = git("show", head + ":" + rel)
    data = pack(entries)
    require(sha(data) == rec["archive_sha256"], "recovered-bytes-mismatch")
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ("source", "kit", "record", "record-sha256", "output"):
        parser.add_argument("--" + flag, required=True)
    a = parser.parse_args()
    try:
        data = recover(path(a.source), path(a.kit), file_bytes(path(a.record), DOC_LIMIT), a.record_sha256)
        from release_client import publish_new

        dest = path(a.output)
        publish_new(dest.parent, dest.name, data)
    except (KeyError, TypeError, OSError, ValueError, subprocess.SubprocessError):
        sys.exit("Recovery incomplete. Check the pinned receipt, exact checkout, kit and fresh destination.")
    except Verdict as exc:
        sys.exit("Recovery rejected: " + exc.reason)
    print("RESTORED_BYTES", sha(data))

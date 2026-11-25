"""Fetch or check the exact wheels recorded for each study environment."""
import argparse
import hashlib
import json
import os
import subprocess
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent


def wheels(environment):
    reference = json.loads((ROOT / "dependencies/reference/wheel-receipts.json").read_text())
    if any(row["published_sha256"] != row["local_sha256"] for row in reference):
        raise ValueError("published and local reference digests disagree")
    if environment == "pretrained":
        return [(r["filename"], r["source"], r["size"], r["published_sha256"]) for r in reference]
    fixture = json.loads((ROOT / "fixture-deps/verified-wheels.json").read_text())
    extra, = [row for row in reference if row["distribution"] == "packaging"]
    extra_pin = (ROOT / "fixture-deps/additional-requirement.txt").read_text().strip()
    if extra_pin != f"packaging=={extra['version']} --hash=sha256:{extra['published_sha256']}":
        raise ValueError("fixture extra dependency pin mismatch")
    return ([(r["filename"], r["url"], r["bytes"], r["sha256"]) for r in fixture]
            + [(extra["filename"], extra["source"], extra["size"], extra["published_sha256"])])


def verify(path, size, digest):
    if not path.is_file() or path.is_symlink() or path.stat().st_size != size:
        raise ValueError(f"missing or incorrect size for {path.name}")
    with path.open("rb") as f:
        if hashlib.file_digest(f, "sha256").hexdigest() != digest:
            raise ValueError(f"wheel hash mismatch for {path.name}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("environment", choices=("pretrained", "fixture"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--verify-only", action="store_true", help="check an existing local wheelhouse without fetching")
    args = parser.parse_args()
    items = wheels(args.environment)
    if not args.verify_only:
        args.directory.mkdir(parents=True, exist_ok=True)
    for name, url, size, digest in items:
        parsed = urlsplit(url)
        if (Path(name).name != name or not name.endswith(".whl") or parsed.scheme != "https"
                or parsed.hostname not in {"download.pytorch.org", "download-r2.pytorch.org", "files.pythonhosted.org"}
                or unquote(Path(parsed.path).name) != name):
            raise ValueError(f"unexpected receipt location for {name}")
        path = args.directory / name
        if not path.exists() and not args.verify_only:
            with NamedTemporaryFile(dir=args.directory, delete=False) as temp:
                tmp = Path(temp.name)
            try:
                subprocess.run(["curl", "--disable", "--fail", "--silent", "--show-error", "--location",
                                "--proto", "=https", "--proto-redir", "=https", "--max-redirs", "8",
                                "--connect-timeout", "30", "--max-time", "900", "--max-filesize", str(size),
                                "--output", str(tmp), url], check=True)
                verify(tmp, size, digest)
                os.link(tmp, path)
            finally:
                tmp.unlink(missing_ok=True)
        verify(path, size, digest)
    if {x.name for x in args.directory.iterdir()} != {r[0] for r in items}:
        raise ValueError("wheelhouse contains unlisted entries")
    print(f"Verified {len(items)} {args.environment} wheel files by size and SHA-256.")


if __name__ == "__main__":
    main()

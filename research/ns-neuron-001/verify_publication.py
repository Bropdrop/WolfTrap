"""Check the complete SHA-256 inventory in a fresh research checkout."""
from hashlib import sha256
from pathlib import Path
import sys


def verify(root):
    entries = {}
    for line in (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        if not name or name in entries or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError(f"Invalid or repeated inventory entry: {name}")
        entries[name] = digest
    actual = {}
    for file in root.rglob("*"):
        if file.is_symlink():
            raise ValueError(f"Unexpected symbolic link: {file.relative_to(root)}")
        if file.is_file() and file != root / "SHA256SUMS":
            actual[file.relative_to(root).as_posix()] = file
    if set(actual) != set(entries):
        raise ValueError(f"Inventory mismatch: {sorted(actual.keys() ^ entries.keys())}")
    for name, file in actual.items():
        digest = sha256()
        with file.open("rb") as stream:
            for block in iter(lambda: stream.read(1 << 20), b""):
                digest.update(block)
        if digest.hexdigest() != entries[name]:
            raise ValueError(f"Hash mismatch: {name}")
    print(f"Verified {len(entries)} files.")


if __name__ == "__main__":
    try:
        verify(Path(__file__).resolve().parent)
    except (OSError, ValueError) as exc:
        sys.exit(str(exc))

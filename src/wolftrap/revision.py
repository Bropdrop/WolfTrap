"""Local Git source identity captured in research evidence."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceRevision:
    commit_sha: str
    tree_sha: str
    dirty: bool
    diff_digest: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def repository_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _git(root: Path, *args: str, check: bool = True) -> bytes:
    process = subprocess.run(
        ["git", *args],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if check and process.returncode != 0:
        message = process.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {message}")
    return process.stdout


def capture_source_revision(root: str | Path | None = None) -> SourceRevision:
    path = Path(root) if root is not None else repository_root()
    try:
        commit = _git(path, "rev-parse", "HEAD").decode().strip()
        tree = _git(path, "rev-parse", "HEAD^{tree}").decode().strip()
    except RuntimeError:
        commit = "UNCOMMITTED"
        tree = "UNCOMMITTED"
    status = _git(path, "status", "--porcelain=v1", "-z")
    dirty = bool(status)
    digest = hashlib.sha256()
    digest.update(status)
    # Hash the index and worktree independently. This works on an unborn
    # branch as well as after the first commit; status alone does not change
    # when the contents of an already staged added file are replaced.
    digest.update(_git(path, "diff", "--cached", "--binary", "--"))
    digest.update(_git(path, "diff", "--binary", "--"))
    untracked = _git(
        path, "ls-files", "--others", "--exclude-standard", "-z"
    )
    for raw_name in sorted(name for name in untracked.split(b"\0") if name):
        digest.update(raw_name)
        candidate = path / raw_name.decode("utf-8", errors="surrogateescape")
        try:
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode):
                digest.update(b"<symlink>")
                digest.update(os.fsencode(os.readlink(candidate)))
            elif stat.S_ISREG(mode):
                flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
                with os.fdopen(os.open(candidate, flags), "rb") as source:
                    for chunk in iter(lambda: source.read(65536), b""):
                        digest.update(chunk)
            else:
                digest.update(b"<non-regular>")
        except OSError:
            digest.update(b"<unreadable>")
    return SourceRevision(
        commit_sha=commit,
        tree_sha=tree,
        dirty=dirty,
        diff_digest="sha256:" + digest.hexdigest(),
    )

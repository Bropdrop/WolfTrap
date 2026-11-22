"""Create/verify the reviewed skills-only ZIP using only fixed Git blobs."""
import argparse
import io
import json
import os
from pathlib import Path
import stat
import zipfile

from evidence import directory, encode, git, metadata

BASE = "d9a91cc1fae237600d67239ebdcf9200388229ca"
PLUGIN = "plugins/wolftrap-security"
FILES = ("README.md", "UPGRADES.md", "plugin.json", "skills/wolftrap-audit/SKILL.md",
         "skills/wolftrap-evidence-review/SKILL.md")
TESTS = ("tests/test_package.py", "tests/test_integration.py")
ZIP = "wolftrap-security-0.1.0.zip"


def build():
    source = BASE + ":" + PLUGIN
    inventory = git("ls-tree", "-r", source).decode().splitlines()
    members = {}
    for line in inventory:
        details, name = line.split("\t", 1)
        mode, kind, oid = details.split()
        if mode != "100644" or kind != "blob":
            raise ValueError("unsupported package member")
        members[name] = oid
    if set(members) != set(FILES + TESTS):
        raise ValueError("package inventory differs from reviewed scope")
    blobs = {name: git("cat-file", "blob", members[name]) for name in FILES}
    manifest = json.loads(blobs["plugin.json"])
    if (manifest["name"], manifest["version"]) != ("wolftrap-security", "0.1.0"):
        raise ValueError("unexpected package identity")
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", compression=zipfile.ZIP_STORED) as bundle:
        for name, content in sorted(blobs.items()):
            entry = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            bundle.writestr(entry, content)
    payload = data.getvalue()
    receipt = dict(profile="wt-zt-package/1", repository="Bropdrop/WolfTrap", repository_id=1436465132,
                   commit=BASE, tree=git("rev-parse", BASE + "^{tree}").decode().strip(),
                   plugin_tree=git("rev-parse", source).decode().strip(),
                   engine_source_tree=git("rev-parse", BASE + ":src/wolftrap").decode().strip(),
                   plugin=manifest["name"], plugin_version=manifest["version"], engine_distribution="0.5.3",
                   engine_bundled=False, members={n:metadata(b) for n,b in blobs.items()},
                   archive=metadata(payload), provenance="unsigned receipt; independently pin Git objects")
    return {ZIP: payload, "package-receipt.json": encode(receipt)}


def check(fd, package):
    if set(os.listdir(fd)) != set(package):
        raise ValueError("unexpected package set")
    for name, data in package.items():
        item = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(item, "rb") as stream:
            info = os.fstat(item)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != len(data):
                raise ValueError("unexpected package file")
            if stream.read(len(data) + 1) != data:
                raise ValueError("package differs from pinned Git inputs")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["create", "verify"])
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    package = build()
    fd = directory(args.directory, args.action == "create")
    try:
        if args.action == "create":
            for name, content in package.items():
                item = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                               mode=0o600, dir_fd=fd)
                with os.fdopen(item, "wb") as f:
                    f.write(content)
        check(fd, package)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()

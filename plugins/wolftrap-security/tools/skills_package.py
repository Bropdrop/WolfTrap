"""Build or verify the exact skills-only ZIP from an explicitly selected commit."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import struct
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[3]
PLUGIN = "plugins/wolftrap-security"
SCHEMA_URL = "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json"
SCHEMA_SHA = "0a4aad95ce337878ad38802ebf0daa3fde76abe3f65400c86bcbb1ec0b3ab883"
LICENSE_SHA = "cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
SKILLS = ("wolftrap-audit", "wolftrap-evidence-review")
ICON = "assets/wolftrap.png"
MEMBERS = ("LICENSE", ICON, "plugin.json", *(f"skills/{name}/SKILL.md" for name in SKILLS))
REPO = "https://github.com/Bropdrop/WolfTrap"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(ok, code):
    if not ok:
        raise ValueError(code)


def strict_object(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), "duplicate JSON key")
    return result


def git(*args):
    return subprocess.check_output(["git", "--no-replace-objects", *args], cwd=ROOT)


def read_members(revision):
    commit = git("rev-parse", "--verify", "--end-of-options", revision + "^{commit}").decode().strip()
    files = {}
    for name in MEMBERS:
        source = name if name == "LICENSE" else f"{PLUGIN}/{name}"
        entry = git("ls-tree", commit, "--", source).split(b"\t", 1)[0].split()
        require(len(entry) == 3 and entry[:2] == [b"100644", b"blob"], f"invalid Git member {name}")
        files[name] = git("cat-file", "blob", entry[2].decode())
    return commit, files


def validate(files):
    require(set(files) == set(MEMBERS), "skills-only member inventory")
    require(sha(files["LICENSE"]) == LICENSE_SHA, "Apache-2.0 license pin")
    manifest = json.loads(files["plugin.json"], object_pairs_hook=strict_object)
    require(set(manifest) == {"$schema", "name", "version", "description", "author", "homepage",
                             "repository", "license", "keywords", "extensions"}, "manifest fields")
    require((manifest["$schema"], manifest["name"], manifest["version"], manifest["license"]) ==
            (SCHEMA_URL, "wolftrap-security", "0.2.0", "Apache-2.0"), "manifest identity")
    require(manifest["homepage"] == manifest["repository"] == manifest["author"]["url"] == REPO,
            "project URLs")
    require(set(manifest["extensions"]) == {"com.openai"}, "extension fields")
    provider = manifest["extensions"]["com.openai"]
    require(set(provider) == {"interface", "requires_local_executor"}
            and provider["requires_local_executor"] is True, "desktop skills only")
    listing = provider["interface"]
    limits = {"displayName": 30, "shortDescription": 30, "longDescription": 4000, "developerName": 80}
    require(set(listing) == set(limits) | {"websiteURL", "supportURL", "defaultPrompt", "category",
                                           "capabilities", "logo", "composerIcon"}, "listing fields")
    for key, limit in limits.items():
        require(isinstance(listing[key], str) and 0 < len(listing[key]) <= limit, f"listing {key}")
    prompts = listing["defaultPrompt"]
    require(isinstance(prompts, list) and 1 <= len(prompts) <= 3
            and all(isinstance(item, str) and 0 < len(item) <= 128 for item in prompts)
            and len(set(prompts)) == len(prompts), "starter prompts")
    require(listing["capabilities"] == ["Read"] and listing["category"] == "Productivity", "listing scope")
    require(listing["websiteURL"] == REPO and listing["supportURL"] == REPO + "/issues", "listing URLs")
    for field in ("logo", "composerIcon"):
        require(listing[field] == "./" + ICON, f"{field} reference")
    png = files[ICON]
    require(33 <= len(png) <= 5 * 1024 * 1024
            and png.startswith(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"), "icon format")
    width, height = struct.unpack(">II", png[16:24])
    require(width == height and 48 <= width <= 4096, "icon dimensions")
    for name in SKILLS:
        skill = files[f"skills/{name}/SKILL.md"].decode()
        parts = skill.split("\n---\n", 1)
        description = parts[0].removeprefix(f"---\nname: {name}\ndescription: ")
        require(len(parts) == 2 and parts[1].strip() and description != parts[0]
                and len(description.splitlines()) == 1 and description.strip(), f"skill metadata {name}")
    return manifest


def encode_zip(files):
    sink = io.BytesIO()
    with zipfile.ZipFile(sink, "w", zipfile.ZIP_STORED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return sink.getvalue()


def verify_zip(path, expected):
    require(path.is_file() and not path.is_symlink(), "regular ZIP required")
    with path.open("rb") as stream:
        require(stream.read(len(expected) + 1) == expected, "ZIP differs from pinned reconstruction")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "verify"))
    parser.add_argument("zip", type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--schema", required=True, type=Path)
    args = parser.parse_args()
    commit, files = read_members(args.commit)
    manifest = validate(files)
    schema = args.schema.read_bytes()
    require(sha(schema) == SCHEMA_SHA, "portable schema pin")
    from jsonschema import Draft202012Validator

    Draft202012Validator(json.loads(schema)).validate(manifest)
    expected = encode_zip(files)
    path = args.zip.absolute()
    require(path.resolve() == path and not path.is_relative_to(ROOT), "use an external canonical ZIP path")
    if args.action == "build":
        with path.open("xb") as stream:
            stream.write(expected)
    verify_zip(path, expected)
    print(json.dumps({"bytes": len(expected), "sha256": sha(expected), "commit": commit,
                      "members": {name: sha(data) for name, data in sorted(files.items())}}, sort_keys=True))


if __name__ == "__main__":
    main()

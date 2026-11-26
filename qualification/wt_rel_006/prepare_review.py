"""Rebuild the frozen evaluation and write unsigned WT-REL-006 review metadata."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = "4d39dbee2aca4a680cd1a916bc4beb0f54cccb30"
TREE = "a04d65fd3535c74ea8991e557b14d1e6899caa8e"
TOOLING = "8a33bc6d2230bff0a05aff77648a8362ed8e84eb"
DRIVER = "ea6f28b4727480369c5fd20322c686ddbd8ff7ca5d9ca14a7b9bd9595fa03d00"
PACKAGE = "wolftrap-wt-pkg-005-linux-evaluation.zip"
FROZEN = "f4d6188d47bb6c4fdcde3c76b54cb5ac0430c927d3d43b82b15b79c427c535dd"
INNER = "adapter/wolftrap-local-evaluation-0.3.0.zip"


def run(*args):
    return subprocess.check_output(args, cwd=ROOT)


def git(*args):
    return run("git", "--no-replace-objects", *args)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify(ok, label):
    if not ok:
        raise ValueError(label)


def inventory(raw, receipt_name, prefix=""):
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        files = {name: archive.read(name) for name in archive.namelist()}
    verify(len(files) == (25 if prefix else 11), "member count")
    receipt = json.loads(files[receipt_name])
    verify(receipt["commit"] == SOURCE and receipt["tree"] == TREE, "receipt source")
    payloads = {name: data for name, data in files.items() if name != receipt_name}
    expected = {name: {"bytes": len(data), "sha256": sha(data)} for name, data in payloads.items()}
    verify(expected == receipt["members"], "receipt inventory")
    entries = []
    for name, data in sorted(files.items()):
        entry = {"type": "file", "name": prefix + name, "bom-ref": prefix + name,
                 "hashes": [{"alg": "SHA-256", "content": sha(data)}]}
        if name == INNER and not prefix:
            entry["components"] = inventory(data, "receipt.json", INNER + "!/")
        elif name != receipt_name:
            verify(data == git("show", f"{SOURCE}:{name}"), f"Git blob mismatch: {name}")
        entries.append(entry)
    return entries


def write(path, body):
    path.write_text(json.dumps(body, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("python", nargs=2, help="two absolute Python interpreter paths")
    args = parser.parse_args()
    output = args.output.resolve()
    verify(not output.is_relative_to(ROOT), "use a fresh output directory outside source")
    output.mkdir(mode=0o700)
    verify(git("rev-parse", f"{SOURCE}^{{tree}}").decode().strip() == TREE, "Git tree")
    driver_path = "qualification/wt_pkg_005/wt_pkg_005.py"
    driver = git("show", f"{TOOLING}:{driver_path}")
    verify(sha(driver) == DRIVER, "reviewed driver")
    tool = output / "wt_pkg_005.py"
    tool.write_bytes(driver)
    builds = []
    for i, interpreter in enumerate(args.python, 1):
        exe = Path(interpreter).resolve(strict=True)
        dest = output / f"build-{i}"
        report = json.loads(run(exe, "-EBS", tool, "build", "--source", ROOT, "--output", dest))
        raw = (dest / PACKAGE).read_bytes()
        verify(len(raw) == 205923 and sha(raw) == FROZEN, "frozen archive")
        verify(report["verdict"] == "PASS" and report["driver_sha256"] == DRIVER, "build report")
        version = run(exe, "-V").decode().strip()
        verify(re.fullmatch(r"Python \d+\.\d+\.\d+", version), "unexpected interpreter version format")
        builds.append({"python": version, "pythonSha256": sha(exe.read_bytes()),
                       "outputSha256": sha(raw), "reportSha256": sha((dest / "result.json").read_bytes())})
    verify((output / "build-1" / PACKAGE).read_bytes() == raw, "rebuild differs")
    git_version = run("git", "--version").decode().strip()
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "application", "name": PACKAGE, "version": "WT-PKG-005",
                         "bom-ref": "wolftrap-evaluation", "hashes": [{"alg": "SHA-256", "content": FROZEN}],
                         "components": inventory(raw, "assembly-receipt.json")}},
            "properties": [{"name": "wolftrap:inventory:scope",
                            "value": "ZIP contents only. CPython, Bubblewrap, host libraries and kernel are external."}]}
    write(output / "sbom.cdx.json", sbom)
    statement = {"_type": "https://in-toto.io/Statement/v1",
                 "subject": [{"name": PACKAGE, "digest": {"sha256": FROZEN}}],
                 "predicateType": "https://github.com/Bropdrop/WolfTrap/qualification/wt-rel-006/rebuild/v1",
                 "predicate": {"scope": "unsigned local reproducibility observation", "sourceCommit": SOURCE,
                               "sourceTree": TREE, "toolingCommit": TOOLING, "driverSha256": DRIVER,
                               "git": git_version, "builds": builds}}
    write(output / "rebuild.intoto.json", statement)
    subjects = {PACKAGE: FROZEN}
    for name in ("sbom.cdx.json", "rebuild.intoto.json"):
        subjects[name] = sha((output / name).read_bytes())
    write(output / "release-manifest.json",
          {"schema": "wolftrap.release-manifest/v1", "scope": "linux-evaluation",
           "sourceCommit": SOURCE, "sourceTree": TREE, "toolingCommit": TOOLING, "driverSha256": DRIVER,
           "status": "UNSIGNED_REVIEW", "publisherAuthority": "UNVERIFIED", "subjects": subjects})


if __name__ == "__main__":
    main()

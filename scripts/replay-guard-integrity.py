"""Compare guard implementations against immutable inputs. No target module is imported."""
import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASE = "7962c3a77b3e94145ec99063c142d860e6389bb2"
TARGETS = {
    "31": ("5695bb00cf44607383e32e1fe832bd9e0d0c5d7b", 1),
    "32": ("db4aee9709b8b46ecbce1b8af8055f40030e423a", 2),
    "33": ("1801595a2251a0bcdee85589761d8b337348166a", 2),
    "34": ("04df111889f7fbfcd5be7ddf857f2a87a54bd7c6", 3),
    "35": ("99f148be239309315f4eca16860ad5eb45d8826b", 3),
    "36": ("ff1b7e1ccabcf4abe138d235ecd49674454dd9ea", 3),
}
RESEARCH = "ff8059c1d24018c36e03688539184b65537b7334"


def git(repo, *args):
    return subprocess.check_output(["git", "-C", repo, *args])


def check(scanner, repo, head, expected, evidence=None):
    args = [sys.executable, "-B", "-P", "-m", "wolftrap.public_guard", "--repo", repo, head, "--workflow-dependencies"]
    if evidence is not None:
        args.extend(["--cryptofall-lab-evidence", evidence])
    result = subprocess.run(args, capture_output=True, text=True, env={**os.environ, "PYTHONPATH": str(scanner)})
    if not result.stdout:
        raise RuntimeError(result.stderr)
    report = json.loads(result.stdout)
    if (result.returncode != int(bool(expected)) or report["unknown"] or report["signals"] != expected or
            report["source_commit"] != head or not report["workflow_dependencies_checked"] or
            report["source_tree"] != git(repo, "rev-parse", head + "^{tree}").decode().strip()):
        raise RuntimeError(report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path, help="Git database containing the advertised historical refs")
    repo = parser.parse_args().repository.resolve()
    corrected = ROOT / "src"
    evidence = ROOT / "docs/guard-integrity/evidence"
    rows = {}
    with tempfile.TemporaryDirectory() as tmp:
        old = Path(tmp) / "src"
        with tarfile.open(fileobj=io.BytesIO(git(repo, "archive", BASE, "src"))) as archive:
            archive.extractall(tmp, filter="data")
        for label, (head, count) in TARGETS.items():
            rows[label] = {"historical": check(old, repo, head, {"contact-address": count}),
                           "corrected": check(corrected, repo, head, {})}
        denied = {"unreviewed-dependency-manifest": 1}
        rows["39"] = {"historical": check(old, repo, RESEARCH, denied),
                      "default": check(corrected, repo, RESEARCH, denied),
                      "opt_in": check(corrected, repo, RESEARCH, {}, evidence)}
        # Import only the synthetic fixtures authored with the guard corrections.
        sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
        from test_guard_integrity import CATALOG, GEO, GEO_LOOP, ORIGINS, SSH
        fixture = Path(tmp) / "fixture"
        fixture.mkdir()
        git(fixture, "init", "-q")
        for path, source in [(GEO, GEO_LOOP), (CATALOG, "origin not in " + ORIGINS), (SSH, "remote in " + ORIGINS)]:
            file = fixture / path
            file.parent.mkdir(parents=True)
            file.write_text(source)
        git(fixture, "add", ".")
        # Fixed dates make the three-file minimal fixture reproducible.
        dates = {"GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z"}
        subprocess.run(["git", "-C", fixture, "-c", "user.name=Guard fixture", "-c",
                        "user.email=guard@example.org", "commit", "-qm", "Minimal syntax fixtures"],
                       env={**os.environ, **dates}, check=True)
        head = git(fixture, "rev-parse", "HEAD").decode().strip()
        rows["minimal"] = {"historical": check(old, fixture, head, {"contact-address": 3}),
                           "corrected": check(corrected, fixture, head, {}),
                           "wrong_scope": check(corrected, fixture, head, {"laboratory-scope": 1}, evidence)}
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()

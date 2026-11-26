"""Run the guard regressions and check that each isolated mutation is observed."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = {
    "ignore other contact occurrences": ("and match.span() != reviewed_literal", "and reviewed_literal is None"),
    "accept SSH context in another file": ('path = "/".join(parts)', 'path = "/".join(parts) if parts[-1] != "other.py" else "qualification/wt_mcp_001/qualify.py"'),
    "ignore SSH comparison variable": ("and check.left.id == name", "and True"),
    "disable credential detection": ("if _SECRET_PATTERN.search(text):", "if False:"),
    "apply contact exception to reports": ("signals = _content_signals(source)\n", "signals = set()\n"),
    "implicit laboratory opt-in": ("cryptofall_lab and parts ==", "True and parts =="),
    "ignore manifest path": ('parts == ("experiments", "cryptofall", "requirements.txt")', "True"),
    "ignore manifest bytes": ("and hashlib.sha256(raw).hexdigest() == _LAB_MANIFEST", "and True"),
    "ignore scope identity": ("scan.tree != _LAB_TREE or not workflow_dependencies", "not workflow_dependencies"),
    "accept partial evidence": ("lab = all(hashlib.sha256", "lab = any(hashlib.sha256"),
}


def regression(source):
    result = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", str(ROOT / "tests"),
         "-p", "test_guard_integrity.py"],
        cwd=source, env={**os.environ, "PYTHONPATH": str(source)}, capture_output=True, text=True,
    )
    return result


def main():
    rows = []
    baseline = regression(ROOT / "src")
    if baseline.returncode:
        raise RuntimeError(baseline.stderr)
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp)
        shutil.copytree(ROOT / "src/wolftrap", src / "wolftrap", ignore=shutil.ignore_patterns("__pycache__"))
        target = src / "wolftrap/public_guard.py"
        original = target.read_text()
        for name, (old, new) in MUTATIONS.items():
            if original.count(old) != 1:
                raise RuntimeError(name)
            target.write_text(original.replace(old, new))
            result = regression(src)
            failed = [line for line in result.stderr.splitlines() if line.startswith("FAIL: test_")]
            if result.returncode != 1 or not failed or "ERROR:" in result.stderr:
                raise RuntimeError((name, result.stderr))
            rows.append({"mutation": name, "failed_assertions": failed})
    print(json.dumps(rows, indent=2))


if __name__ == "__main__":
    main()

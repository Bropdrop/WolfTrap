"""Change one decision in a disposable trusted engine copy and run its independent control."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

REPO = Path(__file__).resolve().parents[3]
CASES = (
    ("egress-as-runtime", "geotrace.py", 'claims.get(key, [])', 'claims.get(key, geo["network_egress"]["countries"])',
     "test_missing_context_cannot_borrow_network_location"),
    ("freshness", "geotrace.py", "if usable:", "if current is not None:", "test_expired_or_stale"),
    ("conflict", "geotrace.py", 'if len(unique) > 1', 'if len(unique) > 512', "test_context_conflict"),
    ("destination-binding", "geotrace.py", 'and events[item["event"]] == item["binding_sha256"]',
     '', "test_changed_destination_invalidates_context"),
    ("policy-pin", "geotrace_cli.py", "geo.require(hmac.compare_digest(geo.digest(policy_raw), args.policy_sha256))",
     'geo.require(bool(policy_raw))', "test_policy_provenance_and_freshness"),
    ("authorization-promotion", "geotrace.py", '"action_authorization":"NOT_EVALUATED"',
     '"action_authorization":"GRANTED"', "test_distinct_geography_and_no_authority"),
)


def run():
    results = []
    for name, filename, original, replacement, test in CASES:
        clean = (REPO / "src/wolftrap" / filename).read_text()
        if clean.count(original) != 1:
            raise ValueError("changed mutation anchor")
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "engine" / "src"
            shutil.copytree(REPO / "src/wolftrap", target / "wolftrap",
                            ignore=shutil.ignore_patterns("__pycache__"))
            path = target / "wolftrap" / filename
            runs = []
            for phase, text in (("baseline", clean), ("mutation", clean.replace(original, replacement)),
                                ("restoration", clean)):
                path.write_text(text)
                with tempfile.TemporaryDirectory(dir=tmp) as fixtures:
                    env = {"PATH":os.defpath, "PYTHONNOUSERSITE":"1", "TMPDIR":fixtures,
                           "PYTHONPATH":os.pathsep.join((str(target), str(REPO / "tests")))}
                    proc = subprocess.run([sys.executable, "-B", "-m", "unittest", "-v",
                                           "test_geotrace_v2.GeoTraceV2Tests." + test],
                                          cwd=tmp, env=env, capture_output=True, timeout=30, text=True)
                runs.append(dict(phase=phase, source_sha256=hashlib.sha256(text.encode()).hexdigest(),
                                 exit=proc.returncode, log=proc.stderr))
        baseline, mutant, restored = runs
        classification = "INCONCLUSIVE"
        if baseline["exit"] == restored["exit"] == 0 and all("Ran 1 test in" in r["log"] for r in runs):
            if mutant["exit"] == 0:
                classification = "SURVIVED"
            elif mutant["log"].rstrip().endswith("FAILED (failures=1)") and "AssertionError" in mutant["log"]:
                classification = "DETECTED"
        results.append(dict(name=name, test=test, original=original, replacement=replacement,
                            classification=classification, runs=runs))
    return results


if __name__ == "__main__":
    records = run()
    print(json.dumps(records, indent=2))
    sys.exit(any(r["classification"] != "DETECTED" for r in records))

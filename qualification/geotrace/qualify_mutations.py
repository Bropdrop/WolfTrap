"""Run prespecified defensive regression checks on disposable copies of the gate."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
# Mutate one decision at a time. Test IDs refer to independent assertions in the checked-in suite.
TRIALS = [
    ("anchored-digest", "if not hmac.compare_digest(identity, anchored_sha256):",
     "if False:", "test_recovery.RecoveryGateTests.test_wrong_expected_digest_denied_before_output"),
    ("custody-claim", '"original_custody_verified": False,', '"original_custody_verified": True,',
     "test_recovery.RecoveryGateTests.test_digest_match_does_not_claim_provenance"),
    ("baseline-count", '"original_21_tests_executed": 0,', '"original_21_tests_executed": 21,',
     "test_recovery.RecoveryGateTests.test_safe_archive_inventory_is_explicitly_blocked"),
    ("release-status", '"qualification": "BLOCKED_ORIGINAL_BASELINE_NOT_EXECUTED",',
     '"qualification": "QUALIFIED",', "test_recovery.RecoveryGateTests.test_safe_archive_inventory_is_explicitly_blocked"),
    ("closed-manifest", "if manifest_bytes != encode(manifest_for(fresh, payload[REPORT], payload[MARKDOWN])):",
     "if False:", "test_recovery_contract.RecoveryContractTests.test_closed_manifest"),
    ("implicit-directory-case", "if spellings.setdefault(prefix.casefold(), prefix) != prefix:",
     "if False:", "test_recovery_contract.RecoveryContractTests.test_implicit_parent_spelling"),
]


def trial(folder, source, test_id):
    folder.mkdir()
    for suite in ("test_recovery.py", "test_recovery_contract.py"):
        shutil.copyfile(HERE / suite, folder / suite)
    (folder / "recovery.py").write_bytes(source)
    proc = subprocess.run([sys.executable, "-B", "-m", "unittest", "-v", test_id],
                          cwd=folder, env={"PATH":os.defpath, "TMPDIR":str(folder),
                                           "PYTHONNOUSERSITE":"1", "PYTHONHASHSEED":"0"},
                          capture_output=True, text=True, timeout=30)
    output = proc.stderr
    if proc.returncode == 0 and "Ran 1 test in " in output and output.rstrip().endswith("OK"):
        observation = "PASS"
    elif (proc.returncode == 1 and "Ran 1 test in " in output and "AssertionError" in output
          and output.rstrip().endswith("FAILED (failures=1)")):
        observation = "ASSERTION_FAILURE"
    else:
        observation = "INCONCLUSIVE"
    return {"exit":proc.returncode, "observation":observation,
            "source_sha256":hashlib.sha256(source).hexdigest(), "log":output}


def main():
    clean = (HERE / "recovery.py").read_bytes()
    rows = []
    for name, before, after, test_id in TRIALS:
        if clean.count(before.encode()) != 1:
            raise ValueError(f"ambiguous source anchor for {name}")
        changed = clean.replace(before.encode(), after.encode(), 1)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = trial(root / "baseline", clean, test_id)
            mutant = trial(root / "mutant", changed, test_id)
            restored = trial(root / "restored", clean, test_id)
        status = "INCONCLUSIVE"
        if baseline["observation"] == restored["observation"] == "PASS":
            if mutant["observation"] == "ASSERTION_FAILURE":
                status = "DETECTED"
            elif mutant["observation"] == "PASS":
                status = "SURVIVED"
        rows.append(dict(control=name, original=before, replacement=after, test=test_id,
                         baseline=baseline, mutant=mutant, restored=restored, classification=status))
    print(json.dumps(rows, sort_keys=True, indent=2))
    return int(any(row["classification"] != "DETECTED" for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())

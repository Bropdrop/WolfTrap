"""One discarded source copy per experiment. Uses only the built-in synthetic corpus."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
# Each row identifies one counterexample before the target is invoked.
MUTATIONS = [
    ("credential revocation", "revoked", "if not active:", "if active is None:"),
    ("grant revocation", "withdrawn", "if not grant_active:", "if grant_active is None:"),
    ("credential principal", "substitute-principal", 'claim["sub"] != proposal["principal"] or ', ""),
    ("credential principal minimized", "issuer-subject-only", 'claim["sub"] != proposal["principal"] or ', ""),
    ("credential tenant", "substitute-tenant", 'scope["generation"] = generation',
     'scope["generation"] = generation\n    scope["tenant"] = claim["scope"].get("tenant")'),
    ("host exact task", "substitute-task", "if proposal != allowed:",
     'if {**proposal, "task": allowed["task"]} != allowed:'),
    ("independent signing roots", "shared-custody", 'len({k.public_bytes_raw() for k in roots.values()}) != 3',
     'len({k.public_bytes_raw() for k in roots.values()}) < 2'),
    ("owner issuer signature", "forged-owner", 'jwt.decode(token, roots[role]',
     'jwt.decode(token, (__import__("fixtures").key("other").public_key() if role == "owner" else roots[role])'),
    ("policy witness integrity", "policy-digest", 'if json.dumps(claim["scope"], sort_keys=True) !=',
     'if role != "policy" and json.dumps(claim["scope"], sort_keys=True) !='),
    ("grant expiry boundary", "expired-owner", 'tick < claims["exp"]', 'tick <= claims["exp"]'),
    ("durable slot", "duplicate", "INSERT INTO effects VALUES", "INSERT OR REPLACE INTO effects VALUES"),
    ("exact destination", "substitute-destination", "if proposal != allowed:",
     'if {**proposal, "destination": allowed["destination"]} != allowed:'),
    ("tool identity", "substitute-tool", "if proposal != allowed:",
     'if {**proposal, "tool": allowed["tool"]} != allowed:'),
    ("commit before acknowledgement", "authorized", '    return "ACK"', '        db.rollback()\n    return "ACK"'),
    ("independent fact", "uncorroborated-fact", 'if not db.execute("SELECT 1 FROM facts WHERE claim=?", (proposal["claim"],)).fetchone():',
     'if proposal["claim"] == "":'),
]


def trial(directory, case):
    env = dict(PATH=os.environ["PATH"], PYTHONPATH=str(HERE.parents[1] / "src"),
               PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1", PYTHONHASHSEED="0")
    cmd = [sys.executable, "-I", str(HERE / "offline.py"), sys.executable, "trace_trial.py", case]
    proc = subprocess.run(cmd, cwd=directory, capture_output=True, env=env, timeout=30)
    if proc.returncode:
        return None
    return json.loads(proc.stdout)


def run():
    rows = []
    for control, case, old, new in MUTATIONS:
        with tempfile.TemporaryDirectory() as tmp:
            lab = Path(tmp) / "lab"
            shutil.copytree(HERE, lab, ignore=shutil.ignore_patterns("__pycache__"))
            path = lab / "host.py"
            clean = path.read_text()
            if clean.count(old) < 1:
                raise ValueError("mutation anchor missing")
            baseline_trial = trial(lab, case)
            path.write_text(clean.replace(old, new, 1))
            mutant_trial = trial(lab, case)
            path.write_text(clean)
            restored_trial = trial(lab, case)
            baseline, mutant, restored = [r["observation"] if r else None
                                          for r in (baseline_trial, mutant_trial, restored_trial)]
            first = None
            if baseline_trial and mutant_trial:
                for i, (a, b) in enumerate(zip(baseline_trial["events"], mutant_trial["events"])):
                    if a[::2] != b[::2]:
                        first = dict(event_index=i, original=baseline_trial["events"][i:i+3],
                                     mutated=mutant_trial["events"][i:i+3])
                        break
            label = "INCONCLUSIVE"
            difference = None
            if baseline and baseline["oracle"] == "MATCH" and restored == baseline and mutant:
                label = "DETECTED" if mutant["oracle"] == "CONTROL_GAP" else "SURVIVED"
                for field in ("at_dispatch", "identity", "responses", "after"):
                    if mutant[field] != baseline[field]:
                        difference = field
                        break
            rows.append(dict(control=control, case=case, original=old, replacement=new,
                             classification=label, first_observable_difference=difference,
                             first_executed_change=first, baseline=baseline, mutated=mutant, restored=restored,
                             restored_equal=bool(baseline and baseline==restored)))
    return rows


if __name__ == "__main__":
    rows = run()
    print(json.dumps(rows, indent=2, sort_keys=True))
    sys.exit(any(r["classification"] == "INCONCLUSIVE" for r in rows))

"""Run each negative control against an isolated source copy."""

from pathlib import Path
import json
import shutil
import subprocess
import sys
import tempfile

BASE = Path(__file__).resolve().parent
MUTANTS = {
    "missing-binding": ("request-binding", "verifier.py", [
        ('require(claim["request"] == digest(request), "request-binding")', 'pass'),
    ]),
    "or-instead-of-and": ("missing-signature", "verifier.py", [
        ('endorsements("effect", claim, envelope["signatures"], keys)',
         'for proof in envelope["signatures"]:\n'
         '        slot = (proof["role"], proof["algorithm"])\n'
         '        try:\n'
         '            check_signature("effect", claim, slot[0], keys[slot], proof)\n'
         '        except (KeyError, Denied):\n'
         '            continue\n'
         '        break\n'
         '    else:\n'
         '        raise Denied("signature-count")'),
    ]),
    "disabled-revocation": ("algorithm-revocation", "verifier.py", [
        ('and key["algorithm"] not in document["revoked_algorithms"]', ''),
    ]),
    "stale-policy": ("commit-revocation-race", "counter.py", [
        ('self.policy = genesis', 'self.policy = genesis\n        self.genesis = genesis'),
        ('nonce, expires = evaluate(authorization, request, current, anchor.fresh(), expected_request_id=request_id)',
         'if parse(authorization)["claim"]["epoch"] != current["epoch"]:\n'
         '                current = parse(anchor.genesis)\n'
         '            nonce, expires = evaluate(authorization, request, current, anchor.fresh(), expected_request_id=request_id)'),
    ]),
    "replay": ("exact-receipt-and-replay", "counter.py", [
        ('require(db.execute("SELECT 1 FROM receipts WHERE nonce = ?", (nonce,)).fetchone()\n'
         '                    is None, "authorization-used")', 'pass'),
        ('INSERT INTO receipts VALUES', 'INSERT OR REPLACE INTO receipts VALUES'),
    ]),
    "fail-open": ("backend-unavailable", "verifier.py", [
        ('raise Denied("signature-or-backend") from exc', 'return'),
    ]),
}


def main():
    failures = 0
    for name, (case, filename, edits) in MUTANTS.items():
        with tempfile.TemporaryDirectory() as target:
            root = Path(target)
            for source in ("verifier.py", "counter.py", "challenge.py", "expected.json"):
                shutil.copy(BASE / source, root / source)
            source = root / filename
            content = source.read_text()
            for old, new in edits:
                if content.count(old) != 1:
                    raise RuntimeError(f"mutation site changed: {name}")
                content = content.replace(old, new)
            source.write_text(content)
            run = subprocess.run([sys.executable, "challenge.py", case], cwd=root, capture_output=True, text=True)
            if run.stderr:
                raise RuntimeError(run.stderr)
            result = json.loads(run.stdout)
            killed = run.returncode == 1 and result["match"] is False and result["observed"][0] == "committed"
            print(json.dumps({"mutant": name, "killed": killed, **result}))
            failures += not killed
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())

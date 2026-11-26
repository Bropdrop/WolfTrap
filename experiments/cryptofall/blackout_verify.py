"""Independent standard-library comparison of expected outcomes and persisted counter observations."""
import json
from pathlib import Path
import sys

# outcome, final stored increments, final stored receipts (one per increment).
EXPECTED = [
    ("missing permit","disposable-permit",0), ("substituted permit","disposable-permit",0),
    ("lost gate reply","offline",1), ("exact receipt",1,1),
    ("unauthenticated receipt","no response bytes",1), ("different receipt evidence","receipt-binding",1),
    ("exact apply retry","authorization-used",1), ("witness restored","witness-rollback",1),
    ("both restored","gate-rollback",0), ("gate restored","gate-rollback",0),
    ("anchor offline","unavailable",1), ("witness offline","unavailable",1),
    ("independent restarts",1,1), ("ordinary downgrade","profile-transition",1),
    ("lost witness reply","offline",1), ("stale epoch","current-policy",1),
    ("confused recovery authority","signature-coordinate",1), ("revoked algorithm recovery","revoked-signer",1),
    ("concurrent recovery",4,1), ("concurrent PQ commit",2,2),
    ("gate reservation crash","offline",2), ("gate ambiguous restart","gate-rollback",2),
    ("coordinated historical snapshots","gate-rollback",0), ("witness reservation crash","offline",0),
    ("witness ambiguous restart","witness-rollback",0),
]

if __name__ == "__main__":
    rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
    expected = [[case,result,n,n] for case,result,n in EXPECTED]
    if rows != expected:
        raise SystemExit("FAIL: crash, authority or receipt matrix differs")
    print(f"PASS: {len(rows)} observations; two expected increments; zero unexpected or repeated increments")

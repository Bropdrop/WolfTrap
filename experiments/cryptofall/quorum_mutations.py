"""Run real source substitutions in temporary copies. Compare decisions on identical proof bytes."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = [
    ("unsafe threshold", "len(voters) >= 3", "len(voters) >= 2"),
    ("conflicting commitments", 'require(heads[:len(other)] == other, "conflicting certified histories")',
     "pass  # accept first tie"),
    ("rollback against retained floor", 'require(type(height) is int and 0 <= height < len(heads) and heads[height] == retained, "floor")',
     "pass  # discard retained head"),
    ("authority substitution", 'evaluate(wire(cmd["claim"]), wire(cmd["operation"]), policy, timestamp, expected_request_id=rid)',
     "pass  # substitute quorum for hybrid approvals"),
]


def probe(folder, packet, case):
    script = """
import json, sys
from pathlib import Path
from quorum_review import recover
root, name = Path(sys.argv[1]), sys.argv[2]
row, = (r for r in json.loads((root/'proofs.json').read_bytes()) if r['case']==name)
floor = json.loads((root/'retained.json').read_bytes())[name]['floor']
print(recover(row['config'],row['histories'],floor,row['exact']))
"""
    return subprocess.check_output([sys.executable, "-B", "-c", script, packet, case],
                                   cwd=folder, env={**os.environ, "PYTHONPATH":str(HERE)}, text=True).strip()


def run(packet):
    results = []
    for name, old, new in CASES:
        baseline = probe(HERE, packet, name)
        with tempfile.TemporaryDirectory() as tmp:
            code = (HERE / "quorum_review.py").read_text()
            if code.count(old) != 1:
                raise AssertionError("mutation site changed")
            (Path(tmp) / "quorum_review.py").write_text(code.replace(old, new))
            weak = probe(tmp, packet, name)
        if (baseline,weak) != ("UNRESOLVED","COMMITTED"):
            raise AssertionError((name,baseline,weak))
        results.append({"mutation":name,"reference":baseline,"mutant":weak,"detected":True})
    # Exercise a server-side durability mutation through authenticated replica RPC after SIGKILL.
    script = """
from contextlib import ExitStack
from pathlib import Path
import tempfile
from quorum_lab import Lab
from verifier import Denied
with ExitStack() as s:
    lab = Lab(Path(s.enter_context(tempfile.TemporaryDirectory())),s)
    first,second = [lab.block(lab.effect(i)) for i in (1,2)]
    lab.call("A","vote",first)
    lab.restart("A")
    try:
        cert = lab.call("A","vote",second)
        from severance import verify
        from quorum_rules import DOMAIN, hash_of
        assert verify(lab.config["replicas"]["A"],DOMAIN+"vote/A",cert)["block"] == hash_of(second)
        print("SECOND_VALID_SIGNATURE")
    except Denied as exc:
        print(str(exc))
"""
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp)
        for name in ("quorum_lab.py","quorum_node.py"):
            shutil.copyfile(HERE/name, path/name)
        env = {**os.environ,"PYTHONPATH":str(HERE)}
        def run_node():
            return subprocess.check_output([sys.executable,"-B","-c",script],cwd=path,env=env,text=True).strip()
        strong = run_node()
        code = (path/"quorum_node.py").read_text()
        old = 'db.execute("INSERT INTO locks VALUES(?,?,?,?)", (obj["height"], vote["block"], wire(cert), wire(obj)))'
        assert code.count(old) == 1
        (path/"quorum_node.py").write_text(code.replace(old, "pass  # volatile vote"))
        weak = run_node()
        if (strong,weak) != ("locked","SECOND_VALID_SIGNATURE"):
            raise AssertionError((strong,weak))
    results.append({"mutation":"volatile vote lock","reference":strong,"mutant":weak,"detected":True})
    print(json.dumps(results,indent=2))


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve())

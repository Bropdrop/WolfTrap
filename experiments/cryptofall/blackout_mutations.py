"""Isolate one deliberately weakened disposable implementation per control."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from blackout_verify import EXPECTED

CASES = [
    ("witness rollback","blackout.py",'self.call("anchor", "read", {}) == head','self.name == "witness" or self.call("anchor", "read", {}) == head',"witness restored"),
    ("algorithm downgrade","counter.py",'new["profile"] == old["profile"] or action == "recover"','True',"ordinary downgrade"),
    ("permit substitution","blackout.py",'digest(request) in witness["permits"]','bool(witness["permits"])',"substituted permit"),
    ("stale epoch","verifier.py",'claim["epoch"] == current["epoch"]','True',"stale epoch"),
    ("recovery authority confusion","counter.py",'recovery = current_key(old, self.roots["recovery-test"])','recovery = {"algorithm": "ed25519-v1", "public": old["keys"]["owner-test"]["ed25519-v1"]} if action == "recover" else current_key(old, self.roots["recovery-test"])',"confused recovery authority"),
]

def main():
    origin = Path(__file__).resolve().parent
    oracle = {name:[name,status,n,n] for name,status,n in EXPECTED}
    for label,file,old,new,case in CASES:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for p in origin.glob("*.py"):
                shutil.copy(p,root/p.name)
            path=root/file
            code=path.read_text()
            assert code.count(old)==1
            code=code.replace(old,new)
            if label=="stale epoch":
                # Isolate the epoch field: all other signed coordinates are current.
                path2=root/"blackout_qualify.py"
                harness=path2.read_text()
                path2.write_text(harness.replace('body = {"request":req,"evidence":f.claim()}','body = {"request":req,"evidence":f.claim(epoch=1)}').replace('lab.observed("missing permit",execute())','lab.invoke("witness","permit",req)\n    lab.observed("epoch probe",execute())\n    return'))
                ref=subprocess.check_output([sys.executable,"-B","blackout_qualify.py"],cwd=root)
                assert json.loads(ref)==["epoch probe","current-policy",0,0]
                case="epoch probe"
                oracle[case]=json.loads(ref)
            path.write_text(code)
            run=subprocess.run([sys.executable,"-B","blackout_qualify.py"],cwd=root,capture_output=True,timeout=40)
            observed={r[0]:r for r in map(json.loads,run.stdout.splitlines())}
            if case not in observed or observed[case]==oracle[case]:
                raise RuntimeError(label+" control failed: "+run.stderr.decode()[-300:])
            print(json.dumps({"control":label,"expected":oracle[case],"mutant":observed[case],"verdict":"DETECTED"}))

if __name__=="__main__":
    main()

"""Paired, isolated mutation tests of the disposable target and evidence verifier."""
import json
from pathlib import Path
import shutil
import sys
import subprocess
import tempfile

CASES={
 "split commit":("blackbox.py",'stage("after-counter-write")','db.commit()\n        stage("after-counter-write")',
                 [0,0],[1,0]),
 "unspent permit":("blackbox.py","SET spent=1 WHERE","SET spent=0 WHERE","COMMITTED","UNRESOLVED"),
 "stale policy":("blackbox.py","policy=json.loads(policy)",
                 'policy=self.conf["setup"]["genesis"] if op=="execute" else json.loads(policy)',
                 "denied","COMMITTED"),
 "receipt substitution":("blackbox.py",'require(row[0]==wire(binding(b)).decode(),"receipt-binding")',
                          'pass',"denied","COMMITTED"),
 "replicated log authority":("blackbox_verify.py",'state=audit["state"]',
                             'if isinstance(audit,str) and replicated_logs:\n            return replicated_logs[0]["body"]["status"]\n        state=audit["state"]',
                             "UNRESOLVED","COMMITTED"),
 "ignored contradiction":("blackbox_verify.py","check(b==selected)","pass","UNRESOLVED","COMMITTED"),
}


def probe(case):
    from blackbox_lab import fixture,attempt,pending,bb,ED,sign
    from blackbox_verify import adjudicate
    import sqlite3
    import time
    from concurrent.futures import ThreadPoolExecutor
    from contextlib import closing
    with fixture("control") as lab:
        b=lab.grant()
        if case=="split commit":
            lab.start("target","after-counter-write")
            with ThreadPoolExecutor(1) as pool:
                future=pool.submit(lambda:attempt(lambda:lab.submit(b)))
                limit=time.monotonic()+5
                while not (lab.root/"target/hit").exists():
                    if time.monotonic()>limit:
                        raise RuntimeError("missing crash point")
                    time.sleep(0.005)
                lab.stop("target")
                future.result()
            with closing(sqlite3.connect(lab.root/"target/state.db")) as db:
                return list(db.execute("SELECT counter,(SELECT count(*) FROM decisions) FROM meta").fetchone())
        if case=="stale policy":
            req=pending(lab,b)
            lab.transition("emergency-quarantine",mode="quarantine",revoked_algorithms=[ED])
            result=attempt(lambda:lab.call("gate","target","execute",req))
            return "denied" if isinstance(result,str) else result["body"]["status"]
        cert=lab.submit(b)
        if case=="receipt substitution":
            wrong=dict(b,evidence=lab.f.claim())
            result=attempt(lambda:lab.call("client","target","receipt",wrong))
            return "denied" if isinstance(result,str) else result["body"]["status"]
        data=lab.capture(b)
        if case=="ignored contradiction":
            key=bb.MLDSA65PrivateKey.from_seed_bytes(bytes.fromhex(lab.config["target"]["seed"]))
            data["target_claims"]=[sign(key,"blackbox-target-decision",dict(cert["body"],status="NOT_COMMITTED"))]
        if case=="replicated log authority":
            lab.stop("target")
            data=dict(lab.capture(b),replicated_logs=[cert])
        return adjudicate(lab.pins,**data)


if __name__=="__main__":
    if len(sys.argv)>1:
        print(json.dumps(probe(sys.argv[1])))
    else:
        for name,(file,old,new,expected,defect) in CASES.items():
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                for p in Path(__file__).resolve().parent.glob("*.py"):
                    shutil.copy(p,root/p.name)
                cmd=[sys.executable,"-B","blackbox_mutants.py",name]
                ref=json.loads(subprocess.check_output(cmd,cwd=root,timeout=30))
                p=root/file
                src=p.read_text()
                if src.count(old)!=1:
                    raise RuntimeError("mutation site mismatch")
                p.write_text(src.replace(old,new))
                result=json.loads(subprocess.check_output(cmd,cwd=root,timeout=30))
                if (ref,result)!=(expected,defect):
                    raise RuntimeError((name,ref,result))
                print(json.dumps({"mutant":name,"reference":ref,"weakened":result,"verdict":"DETECTED"}))

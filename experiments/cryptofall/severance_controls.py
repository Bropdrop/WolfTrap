"""Focused fault probes against isolated copies of the disposable implementation."""
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

CASES={
    "unsafe release":('if pending["phase"]!="RESERVED":','if False:',"UNRESOLVED","NOT_COMMITTED"),
    "false reconciliation":('require(pending and s["journal"]==view["journal"]+[pending["ticket"]],"no-positive-proof")',
                            'require(pending,"no-positive-proof")',"no-positive-proof","COMMITTED"),
    "substituted trust anchor":('return verify(self.conf["retainer_pin"],"retainer",cert)','return cert["body"]',"certificate","OK"),
    "unilateral recovery":('for role in ("recovery","witness"):','for role in ("recovery",):',"certificate","NOT_COMMITTED"),
}


def probe(case):
    from severance_lab import Lab,result
    import secrets
    with tempfile.TemporaryDirectory() as tmp:
        lab=Lab(Path(tmp))
        try:
            b=lab.reservation(1)
            if case=="substituted trust anchor":
                lab.stop("retainer")
                lab.cfg["retainer"]["seed"]=secrets.token_hex(32)
                lab.config("retainer")
                lab.start("retainer")
                return result(lambda:lab.rpc("anchor","view",{}))
            if case=="unilateral recovery":
                votes=lab.approvals("resolve",b["token"])
                votes["votes"]["witness"]=votes["votes"]["recovery"]
                return result(lambda:lab.rpc("anchor","resolve",votes))
            lab.start("gate","after-arm")
            result(lambda:lab.rpc("gate","execute",b,"client"))
            lab.start("gate")
            if case=="unsafe release":
                return result(lambda:lab.resolve(b))
            return result(lambda:lab.rpc("gate","observe",{}))
        finally:
            for r in list(lab.procs):
                lab.stop(r)
            for link in lab.links.values():
                link.server_close()


if __name__=="__main__":
    if len(sys.argv)>1:
        print(probe(sys.argv[1]))
    else:
        for case,(old,new,reference,defect) in CASES.items():
            with tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                for p in Path(__file__).resolve().parent.glob("*.py"):
                    shutil.copy(p,root/p.name)
                cmd=[sys.executable,"-B","severance_controls.py",case]
                good=subprocess.check_output(cmd,cwd=root,text=True).strip()
                source=root/"severance.py"
                code=source.read_text()
                assert code.count(old)==1
                source.write_text(code.replace(old,new))
                bad=subprocess.check_output(cmd,cwd=root,text=True).strip()
                if (good,bad)!=(reference,defect):
                    raise RuntimeError((case,good,bad))
                print(json.dumps({"control":case,"reference":good,"mutant":bad,"verdict":"DETECTED"}))

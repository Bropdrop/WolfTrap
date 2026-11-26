"""Run source mutations in temporary copies. Compare identical decision probes."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from contextlib import ExitStack
from pathlib import Path

HERE = Path(__file__).resolve().parent
CASES = {
 "unsafe lock release":("resurrection_node.py",'require({d for v,d in carried if v==highest} == {candidate}, "highest prepared")',
                        'pass',0,3),
 "cross-view double voting":("resurrection_node.py",'and promised==v','and promised>=v',0,3),
 "stale prepared certificate":("resurrection_node.py",'proof["view"] == v and proof["digest"] == d','proof["digest"] == d',0,3),
 "reduced decision threshold":("resurrection_proof.py",'len(signatures) >= 3','len(signatures) >= 2',"UNRESOLVED","COMMITTED"),
 "authority substitution":("quorum_review.py",'evaluate(wire(cmd["claim"]), wire(cmd["operation"]), policy, timestamp, expected_request_id=rid)',
                           'pass',"UNRESOLVED","COMMITTED")}


def probe(name,packet):
    from resurrection_proof import disclose
    from resurrection_lab import Cluster
    if name in ("authority substitution","reduced decision threshold"):
        case = "two signatures" if name=="reduced decision threshold" else "quorum without owner authorization"
        row=json.loads((packet/"proofs.json").read_bytes())[case]
        floor=json.loads((packet/"pins.json").read_bytes())[case]["floor"]
        return disclose(row["config"],row["chains"],floor,row["request"])
    with ExitStack() as stack:
        lab=Cluster(Path(stack.enter_context(tempfile.TemporaryDirectory())),stack)
        x,y=(lab.block(lab.effect(i)) for i in (1,2))
        prepared=lab.votes(0,x,"prepare",reports={})
        if name=="unsafe lock release":
            first={"block":x,"commit":lab.votes(0,x,"commit",prepared=prepared)}
            assert disclose(lab.config,[[first]],lab.floor,x["command"])=="COMMITTED"
            reports=lab.change(1,y)
            second=lab.decide(1,y,reports)
        elif name=="cross-view double voting":
            reports=lab.change(1,y)
            other=lab.decide(1,y,reports)
            assert disclose(lab.config,[[other]],lab.floor,y["command"])=="COMMITTED"
            second={"block":x,"commit":lab.votes(0,x,"commit",prepared=prepared)}
        else:
            lab.change(1,x)
            second={"block":x,"commit":lab.votes(1,x,"commit",prepared=prepared)}
        votes=second["commit"]["votes"]
        if votes:
            assert disclose(lab.config,[[second]],lab.floor,second["block"]["command"])=="COMMITTED"
        return len(votes)


def run(packet):
    rows=[]
    for name,(filename,old,new,before,after) in CASES.items():
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)
            for p in HERE.glob("*.py"):
                shutil.copyfile(p,path/p.name)
            def invoke():
                raw=subprocess.check_output([sys.executable,"-B",path/Path(__file__).name,"probe",name,packet],
                                            cwd=path,env={**os.environ,"PYTHONDONTWRITEBYTECODE":"1"})
                return json.loads(raw)
            strong=invoke()
            file=path/filename
            src=file.read_text()
            assert src.count(old)==1
            file.write_text(src.replace(old,new))
            weak=invoke()
            if (strong,weak)!=(before,after):
                raise AssertionError((name,strong,weak))
            rows.append({"mutation":name,"reference":strong,"mutant":weak,"detected":True})
    return rows


if __name__=="__main__":
    if sys.argv[1]=="probe":
        print(json.dumps(probe(sys.argv[2],Path(sys.argv[3]))))
    else:
        print(json.dumps(run(Path(sys.argv[1]).resolve()),indent=2))

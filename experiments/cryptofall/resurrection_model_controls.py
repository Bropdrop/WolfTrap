"""Sensitivity checks against known unsafe variants of the independent model."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

source=Path(__file__).with_name("resurrection_model.py").read_text()
controls={
    "ignore carried lock":("values.update((1,-1) if high==0 else (high//abs(high),))",
                           "values.update((-1,1))","AssertionError: ("),
    "two prepares suffice":("votes.count(v)+1>=3","votes.count(v)+1>=2","conflicting prepares"),
}
results=[]
for name,(old,new,indicator) in controls.items():
    assert source.count(old)==1
    with tempfile.TemporaryDirectory() as tmp:
        script=Path(tmp)/"model.py"
        script.write_text(source.replace(old,new))
        result=subprocess.run([sys.executable,"-I",script],capture_output=True,text=True)
    line=result.stderr.splitlines()[-1]
    if result.returncode==0 or indicator not in line:
        raise AssertionError((name,line))
    results.append({"mutation":name,"counterexample":line})
print(json.dumps(results,indent=2))

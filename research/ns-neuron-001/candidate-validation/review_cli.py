"""Probe candidate CLI from a NumPy-only interpreter and verify an invalid local model fails closed."""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

root=Path(__file__).resolve().parents[1]
candidate=root/"candidate/wolftrap-neuralscope"
rows=[]
with tempfile.TemporaryDirectory() as temporary:
    fresh=Path(temporary)
    bad=fresh/"incomplete-model"
    bad.mkdir()
    destination=fresh/"results"
    for label, args, expected in [
            ("version",["--version"],0),("help",["neuron","--help"],0),
            ("missing-pins",["neuron","--model-dir",str(bad),"--out",str(destination)],2)]:
        command=[sys.executable,"-B",str(root/"offline/offline_exec.py"),"--",sys.executable,"-B","-m","neuralscope",*args]
        result=subprocess.run(command,capture_output=True,text=True,cwd=candidate)
        rows.append(dict(case=label,exit=result.returncode,expected=expected,stdout=result.stdout,stderr=result.stderr))
        if result.returncode != expected:
            raise AssertionError(f"Unexpected CLI exit for {label}")
    if destination.exists():
        raise AssertionError("Rejected inputs left an evidence output")
    rows.append(dict(case="missing-pins-output-exists",value=destination.exists()))
print(json.dumps(rows,indent=2))

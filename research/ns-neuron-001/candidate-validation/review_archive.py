"""Rebuild the candidate in a fresh offline process and compare its contents."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import zipfile

root=Path(__file__).resolve().parents[1]
source=root/"candidate/wolftrap-neuralscope"
tag="wolftrap-neuralscope/"
with tempfile.TemporaryDirectory() as temp:
    target=Path(temp)/"source.zip"
    subprocess.run([sys.executable,"-B",str(root/"offline/offline_exec.py"),"--",sys.executable,
                    "-B",str(source/"build_bundle.py"),"--output",str(target)],
                   check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    with zipfile.ZipFile(target) as z:
        if z.testzip() is not None or len(set(z.namelist()))!=len(z.namelist()):
            raise ValueError("ZIP integrity failure")
        receipt=json.loads(z.read(tag+"bundle-inventory.json"))
        files={p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
        checks={"exact_candidate_member_set":set(z.namelist())=={tag+p for p in files|{"bundle-inventory.json"}},
                "inventory_complete":set(receipt["members"])==files,
                "all_payloads_identical":all((source/name).read_bytes()==z.read(tag+name) for name in files),
                "all_manifest_hashes_match":all({"bytes":len(z.read(tag+name)),
                    "sha256":hashlib.sha256(z.read(tag+name)).hexdigest()}==entry for name,entry in receipt["members"].items())}
        if not all(checks.values()):
            raise ValueError("Rebuilt archive differs from reviewed inputs")
        print(json.dumps(dict(sha256=hashlib.sha256(target.read_bytes()).hexdigest(),members=len(z.namelist()),
              version=receipt["version"],checks=checks),sort_keys=True,indent=2))

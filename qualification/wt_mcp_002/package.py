"""Build and verify the offline evaluation ZIP against independently selected Git objects."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile

from profile import HERE,MEMBERS,ROOT,encode,require,sha


def git(*args):
    return subprocess.check_output(["git",*args],cwd=ROOT)


def build(commit):
    require(re.fullmatch("[0-9a-f]{40}",commit) is not None)
    paths=[str(p.relative_to(ROOT)) for p in MEMBERS]
    tree=git("rev-parse",commit+"^{tree}").decode().strip()
    contents={}
    for name in paths:
        row=git("ls-tree",commit,"--",name).decode().split()
        require(len(row)==4 and row[:2]==["100644","blob"] and row[-1]==name)
        contents[name]=git("cat-file","blob",row[2])
    receipt={"schema":"wolftrap.evaluation-package/v2","repository":"Bropdrop/WolfTrap","commit":commit,"tree":tree,
             "adapter":"0.2.0","engine":"0.6.0","plugin":"wolftrap-security 0.2.0","protocol":"2025-11-25",
             "members":{name:{"bytes":len(raw),"sha256":sha(raw)} for name,raw in contents.items()},
             "runtime":["Linux x86-64 user and network namespaces","Debian CPython 3.13",
                        "Bubblewrap","libseccomp","SQLite","standard library and dynamic system libraries"],
             "client_test_dependencies":["MCP Python SDK 1.29.0","Codex CLI 0.172.0-alpha.2","strace"],
             "publisher_provenance":"UNVERIFIED","purpose":"separate local evaluation"}
    contents["receipt.json"]=encode(receipt)+b"\n"
    output=io.BytesIO()
    with zipfile.ZipFile(output,"w",compression=zipfile.ZIP_STORED) as archive:
        for name,raw in sorted(contents.items()):
            info=zipfile.ZipInfo(name,(1980,1,1,0,0,0))
            info.external_attr=0o100644<<16
            info.create_system=3
            archive.writestr(info,raw)
    return output.getvalue(),receipt


def external(path):
    require(path.is_absolute() and path==path.resolve() and not path.is_relative_to(ROOT))


def verify(path,commit,tree,pin):
    external(path)
    expected,receipt=build(commit)
    require(receipt["tree"]==tree and path.is_file() and path.stat().st_nlink==1 and path.stat().st_size==len(expected))
    actual=path.read_bytes()
    require(sha(actual)==pin and actual==expected)
    return receipt


def install(path,commit,tree,pin,destination):
    verify(path,commit,tree,pin)
    external(destination)
    require(not destination.exists() and destination.parent.stat().st_mode & 0o077==0)
    # Extract the freshly reconstructed trusted bytes; the transport file may change after verification.
    raw,_=build(commit)
    with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
        checkout=Path(tmp)/"installation"
        checkout.mkdir(mode=0o700)
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            for name in z.namelist():
                target=checkout/name
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes(z.read(name))
        os.rename(checkout,destination)


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("mode",choices=("build","verify","install"))
    p.add_argument("--commit",required=True)
    p.add_argument("--zip",type=Path,required=True)
    p.add_argument("--tree")
    p.add_argument("--sha256")
    p.add_argument("--destination",type=Path)
    a=p.parse_args()
    path=a.zip.absolute()
    external(path)
    if a.mode=="build":
        raw,receipt=build(a.commit)
        with path.open("xb") as f:
            f.write(raw)
        print(sha(raw),receipt["tree"])
    elif a.mode=="install":
        install(path,a.commit,a.tree,a.sha256,a.destination.absolute())
    else:
        verify(path,a.commit,a.tree,a.sha256)
        print("VERIFIED_PACKAGE_BYTES")

"""One clean, externally witnessed evaluation. No installation or network fallback."""
import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile

import audit
import package
import selection_controls
from fixtures import REF,arguments,provision
from profile import HERE,ROOT,SCAN,encode,measurement,sha
from recovery import pin_for
from trials import check,command,wire

REQUIRED = ("trials","recovery","mutations")


def git(*args):
    return subprocess.check_output(["git",*args],cwd=ROOT,text=True).strip()


def source():
    check(not git("status","--porcelain"),"dirty source")
    return {"repository":"Bropdrop/WolfTrap","commit":git("rev-parse","HEAD"),"tree":git("rev-parse","HEAD^{tree}")}


def audit_controls(out,runs):
    refpin="3421ee83fb916dba6177bf21709d2ff9a24839f9d2a8b4e77eba8a708b980877"
    results={}
    for candidate in ("alpha","beta"):
        ownerpin=json.loads((runs/"trials.json").read_bytes())["owner_pin"]
        row=audit.verify(runs/"state",candidate,ownerpin,refpin)
        check(row["status"]=="VERIFIED_COMMIT","independent slot audit")
        results[candidate]=row
    for label in ("missing","changed-artifact","changed-journal","wrong-owner","wrong-reference","wrong-slot"):
        state=runs/"state"
        path=state/"effects/slot-alpha/slot.db"
        original=path.read_bytes()
        try:
            if label=="missing":
                path.unlink()
            elif label in ("changed-artifact","changed-journal","wrong-slot"):
                with sqlite3.connect(path) as db:
                    if label=="changed-artifact":
                        db.execute("UPDATE artifacts SET data=? WHERE name='manifest.json'",(b'{}',))
                    elif label=="changed-journal":
                        db.execute("DELETE FROM journal WHERE phase='COMMITTED'")
                    else:
                        db.execute("UPDATE identity SET slot='slot-beta'")
            try:
                audit.verify(state,"alpha","0"*64 if label=="wrong-owner" else ownerpin,
                             "0"*64 if label=="wrong-reference" else refpin)
            except (ValueError,OSError,sqlite3.Error,KeyError):
                results[label]="REJECTED"
            else:
                raise AssertionError(label+" accepted")
        finally:
            path.write_bytes(original)
            path.chmod(0o600)
        check(audit.verify(state,"alpha",ownerpin,refpin)["status"]=="VERIFIED_COMMIT","restored audit")
    return results


def run(out,hosted):
    src=source()
    check({name for _,name in socket.if_nameindex()}=={"lo"},"qualification requires isolated network")
    summary={"schema":"wolftrap.release-safety/v2","source":src,"stages":{},"real_model":"NOT_TESTED",
             "public_release":"BLOCKED","publisher_provenance":"UNVERIFIED","platform":platform.platform()}
    def save():
        (out/"safety-case.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
    raw,receipt=package.build(src["commit"])
    bundle=out/"wolftrap-local-evaluation-0.2.0.zip"
    bundle.write_bytes(raw)
    digest=sha(raw)
    check(package.build(src["commit"])[0]==raw,"non-reproducible package")
    install=out/"installed"
    package.install(bundle,src["commit"],src["tree"],digest,install)
    bad=out/"replaced.zip"
    bad.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
    try:
        package.verify(bad,src["commit"],src["tree"],digest)
    except ValueError:
        pass
    else:
        raise AssertionError("substituted package accepted")
    bad.unlink()
    summary["package"]={"receipt":receipt,"bytes":len(raw),"sha256":digest,"rebuild":"IDENTICAL",
                        "substitution":"REJECTED","installation":"VERIFIED_PRIVATE_EXTRACTION"}
    summary["commissioning"]=selection_controls.run(out)
    save()
    if not (Path("/usr/bin/python3.13").is_file() and Path("/usr/bin/bwrap").is_file()):
        summary["os_gate"]="BLOCKED: required Debian Python 3.13 and Bubblewrap profile unavailable"
        save()
        return 2
    def execute(label,script,*args):
        cmd=[sys.executable,"-B",str(HERE/script),*map(str,args)]
        with (out/(label+".log")).open("w") as log:
            done=subprocess.run(cmd,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,timeout=300)
        summary["stages"][label]={"command":cmd,"exit":done.returncode}
        save()
        check(done.returncode==0,label+" did not qualify")
    try:
        from confinement import run as check_profiles
        summary["worker_profiles"]=check_profiles()
    except (ValueError,OSError,AssertionError,subprocess.SubprocessError):
        summary["os_gate"]="BLOCKED: explicit worker profile could not demonstrate confinement"
        save()
        return 2
    for label in REQUIRED:
        filename=label+(".json" if label=="mutations" else "")
        execute(label,label+".py","--output",out/filename)
    summary["request_cases"]=json.loads((out/"trials/trials.json").read_bytes())
    summary["recovery"]=[json.loads(p.read_bytes()) for p in sorted((out/"recovery").glob("*.json"))]
    summary["mutations"]=json.loads((out/"mutations.json").read_bytes())
    summary["audit"]=audit_controls(out,out/"trials")
    if hosted:
        summary["hosted_clients"]="NOT_TESTED"
    else:
        execute("clients","clients.py","--output",out/"clients","--install",install/HERE.relative_to(ROOT))
        summary["clients"]=json.loads((out/"clients/clients.json").read_bytes())
        state=out/"drift-state"
        owner=provision(state)
        entry=install/HERE.relative_to(ROOT)
        pin=pin_for(entry,"drift-fixture")
        cmd=command(state,owner,pin,"drift-fixture",entry)
        summary["installed_drift_and_restoration"]={}
        for member in ("front.py","launch.py","profile.py"):
            path=entry/member
            old=path.read_bytes()
            exits=[]
            # Exit 37 would be externally observable if unreviewed package code ran during launch.
            for content in (old,b"raise SystemExit(37)\n",old):
                path.write_bytes(content)
                exits.append(subprocess.run(cmd,input=b"",capture_output=True,timeout=15).returncode)
            check(exits==[0,1,0],"changed distribution reused approved configuration")
            summary["installed_drift_and_restoration"][member]=exits
    check(source()==src,"source changed during execution")
    summary["profile"]="SYNTHETICALLY_VERIFIED"
    summary["mutation_limits"]={"full-host-compromise":"UNEXECUTED","whole-store-rollback":"UNEXECUTED",
                                 "power-loss-durability":"UNEXECUTED","kernel-security":"UNEXECUTED",
                                 "individual-seccomp-rules":"UNEXECUTED","per-member-zip-verification":"UNEXECUTED",
                                 "system-clock-rollback":"UNEXECUTED","sqlite-storage-failure":"UNEXECUTED"}
    summary["authority"]="Single operator-provisioned session with independently selected policy and configuration pins"
    summary["scope"]="Linux network-isolated synthetic captures alpha and beta"
    summary["limits"]=["Synthetic acceptance covers these schemas and approvals only.",
                       "A benign scope mismatch may deny a legitimate request until recommissioned.",
                       "A compromised host may falsify both its journal and stored bytes.",
                       "OS canaries measure the attempted operations and do not exhaust kernel behavior."]
    save()
    return 0


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--hosted",action="store_true")
    args=p.parse_args()
    out=args.output.absolute()
    check(out==out.resolve() and not out.is_relative_to(ROOT),"fresh external output required")
    out.mkdir(mode=0o700)
    sys.exit(run(out,args.hosted))

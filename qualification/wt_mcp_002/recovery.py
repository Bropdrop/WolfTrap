"""Deterministic crash and concurrency trials in disposable measured installations."""
import argparse
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import time

from fixtures import REF,arguments,provision,revoke
from profile import HERE,MEMBERS,ROOT,SCAN,VERIFY,encode
from trials import Wire,check,command,observe,wire


def copy_install(dest):
    for path in MEMBERS:
        p=dest/path.relative_to(ROOT)
        p.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(path,p)
    return dest/HERE.relative_to(ROOT)


def pin_for(install,client):
    cmd=["/usr/bin/python3.13","-IBS","-c",
         "import sys;sys.path.insert(0,sys.argv[1]);from profile import measurement;print(measurement(sys.argv[2]))",
         str(install),client]
    return subprocess.check_output(cmd,text=True,env={}).strip()


def change(path,old,new):
    text=path.read_text()
    check(text.count(old)==1,"fixture anchor "+old)
    path.write_text(text.replace(old,new))


def pause(install,anchor):
    spaces=anchor[:len(anchor)-len(anchor.lstrip())]
    lines=['Path("/effects/paused").touch()', 'import time as clock', 'for tick in range(500):',
           '    if Path("/effects/resume").exists():', '        break', '    clock.sleep(0.02)',
           'else:', '    raise TimeoutError("external barrier unavailable")']
    change(install/"broker.py",anchor,"\n".join(spaces+s for s in lines)+"\n"+anchor)


def wait_pause(state,w):
    for _ in range(500):
        if (state/"effects/paused").exists():
            return
        check(w.proc.poll() is None,"broker stopped before barrier")
        time.sleep(0.02)
    raise TimeoutError("external barrier")


def run_fault(label,out):
    with tempfile.TemporaryDirectory() as temporary:
        temp=Path(temporary)
        install=copy_install(temp/"installation")
        state=temp/"state"
        owner=provision(state)
        args=arguments(owner,SCAN,"alpha")
        broker=install/"broker.py"
        before_reply='                return reply("COMMITTED" if name==SCAN else "VERIFIED",hashes=expected)'
        before_commit='                    with gate(), transaction(db):'
        worker='                        code,_ = engine(True,inputs,stage,policy)'
        if label in ("terminate-after-staging","revoke-before-commit","replace-during-scan","concurrent-duplicate"):
            pause(install,before_commit)
        elif label=="lost-response":
            pause(install,before_reply)
        elif label in ("missing-worker","scanner-failure","incomplete-success"):
            replacement={"missing-worker":"raise FileNotFoundError()","scanner-failure":"code = 3",
                         "incomplete-success":"code = 0"}[label]
            change(broker,worker,"                        "+replacement)
        elif label=="verifier-failure":
            change(broker,'                    code,msg = engine(False,inputs,stage,policy)',
                   '                    code,msg = 2,b""')
        client="recovery-wire"
        cmd=command(state,owner,pin_for(install,client),client,install)
        w=Wire(cmd)
        try:
            w.initialize()
            w.raw(encode({"id":20,"jsonrpc":"2.0","method":"tools/call","params":{"name":SCAN,"arguments":args}}))
            if label in ("lost-response","terminate-after-staging","revoke-before-commit",
                         "replace-during-scan","concurrent-duplicate"):
                wait_pause(state,w)
                observed_at_barrier=observe(state,"alpha")
                if label=="revoke-before-commit":
                    revoke(state)
                elif label=="replace-during-scan":
                    src=state/"sources/alpha.json"
                    tmp=state/"new"
                    tmp.write_bytes(src.read_bytes())
                    os.replace(tmp,src)
                elif label=="concurrent-duplicate":
                    with wire(cmd) as other:
                        check(other.call(SCAN,args)=="HOLD","concurrent operation repeated")
                if label in ("terminate-after-staging","lost-response"):
                    os.killpg(w.proc.pid,signal.SIGKILL)
                    w.proc.wait(timeout=10)
                    status="NO_RESPONSE"
                else:
                    (state/"effects/resume").touch()
                    status=w.receive()["result"]["structuredContent"]["status"]
            else:
                observed_at_barrier=None
                status=w.receive()["result"]["structuredContent"]["status"]
        finally:
            w.close()
        committed=label in ("lost-response","concurrent-duplicate","contradictory-journal","rehashed-evidence")
        if label=="contradictory-journal" or label=="rehashed-evidence":
            dbpath=state/"effects/slot-alpha/slot.db"
            with sqlite3.connect(dbpath) as db:
                if label=="contradictory-journal":
                    db.execute("UPDATE journal SET scope='fictional-wrong' WHERE phase='COMMITTED'")
                else:
                    db.execute("UPDATE artifacts SET data=? WHERE name='geotrace.json'",(b'{"verified":true}',))
                    db.execute("UPDATE artifacts SET data=? WHERE name='manifest.json'",(b'{"recomputed":true}',))
        with wire(cmd) as retry:
            again=retry.call(SCAN,args)
        obs=observe(state,"alpha")
        expected_retry="ALREADY_COMMITTED" if label in ("lost-response","concurrent-duplicate") else (
                       "DENIED" if label=="revoke-before-commit" else "HOLD")
        expected_status="NO_RESPONSE" if label in ("lost-response","terminate-after-staging") else (
                        "COMMITTED" if committed else "HOLD")
        phases=[r[1] for r in obs["journal"]]
        check(status==expected_status and again==expected_retry,label+" receipts "+repr((status,again)))
        check(phases==(["DISPATCH","COMMITTED"] if committed else ["DISPATCH"]),label+" journal")
        if label!="rehashed-evidence":
            check({n:v["sha256"] for n,v in obs["files"].items()}==(REF["alpha"]["expected"] if committed else {}),
                  label+" effects")
        return {"id":label,"expected":[expected_status,expected_retry],"observed":[status,again],
                "at_barrier":observed_at_barrier,"final":obs}


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    out=p.parse_args().output.absolute()
    check(out==out.resolve() and not out.is_relative_to(ROOT),"external output")
    out.mkdir(mode=0o700)
    cases=("missing-worker","scanner-failure","incomplete-success","verifier-failure","terminate-after-staging",
           "lost-response","revoke-before-commit","replace-during-scan","concurrent-duplicate",
           "contradictory-journal","rehashed-evidence")
    for case in cases:
        record=run_fault(case,out)
        (out/(case+".json")).write_text(json.dumps(record,indent=2)+"\n")
        print(case,"PASS",flush=True)

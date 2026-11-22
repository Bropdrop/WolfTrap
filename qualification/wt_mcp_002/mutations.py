"""One changed control per disposable installation. Outcomes come from stdio and the slot DB."""
import argparse
import json
from pathlib import Path
import sqlite3
import tempfile

from fixtures import REF,arguments,provision,revoke
from profile import HERE,ROOT,SCAN,encode,sha
from recovery import change,copy_install,pause,pin_for,wait_pause
from trials import check,command,observe,wire

CASES={
    "commit-fence":("store.py",'generation == str(policy["generation"]).encode()','bool(generation)',"HOLD","COMMITTED"),
    "scope":("store.py","encode(args)==encode(grant[\"arguments\"])","args['approval']==grant['arguments']['approval']",
             "DENIED","COMMITTED"),
    "expiry":("store.py",'require(grant["not_before"] <= time.time() < grant["expires"])',
              'require(grant["not_before"] <= time.time())',"DENIED","COMMITTED"),
    "frontend":("broker.py",'parse(data)=={"proposal":value}','isinstance(parse(data),dict)',"DENIED","COMMITTED"),
    "catalog":("broker.py",'parse(data)=={"proposal":value}','isinstance(parse(data),dict)',"REJECTED","CATALOG"),
    "duplicate-keys":("store.py","require(len(result) == len(pairs))","require(isinstance(result,dict))","REJECTED","PING"),
    "snapshot":("store.py",'identity==selection["identity"] and sha(data)==selection["digest"]',
                'sha(data)==selection["digest"]',"HOLD","COMMITTED"),
    "ambiguous-retry":("broker.py","                            scan_complete(db,policy,args,expected)",
                       "                            require(bool(previous))","HOLD","ALREADY_COMMITTED"),
}


def measure(label,install,state):
    policy=provision(state,expired=label=="expiry")
    args=arguments(policy,SCAN,"alpha")
    if label=="scope":
        args["task"]="unrelated"
    elif label=="snapshot":
        path=state/"sources/alpha.json"
        path.write_bytes(path.read_bytes())
    elif label=="ambiguous-retry":
        with sqlite3.connect(state/"effects/slot-alpha/slot.db") as db:
            db.execute("INSERT INTO journal VALUES(?,?,?)",(args["approval"],"DISPATCH",sha(encode([SCAN,args]))))
    client="fixture-mutation"
    ownpin=pin_for(install,client)
    with wire(command(state,policy,ownpin,client,install)) as w:
        if label=="commit-fence":
            w.raw(encode({"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":SCAN,"arguments":args}}))
            wait_pause(state,w)
            revoke(state)
            (state/"effects/resume").touch()
            outcome=w.receive()["result"]["structuredContent"]["status"]
        elif label=="duplicate-keys":
            w.raw(b'{"jsonrpc":"2.0","id":201,"method":"ping","method":"ping"}')
            outcome="PING" if "result" in w.receive() else "REJECTED"
        elif label=="catalog":
            outcome="CATALOG" if "result" in w.send("tools/list") else "REJECTED"
        else:
            outcome=w.call(SCAN,args)
    observed=observe(state,"alpha")
    return {"outcome":outcome,"artifacts":{k:v["sha256"] for k,v in observed["files"].items()},
            "journal":[r[1] for r in observed["journal"]],"configuration":ownpin}


def run():
    records=[]
    for name,(file,old,new,initial,changed) in CASES.items():
        with tempfile.TemporaryDirectory() as tmp:
            tmp=Path(tmp)
            install=copy_install(tmp/"install")
            if name=="commit-fence":
                pause(install,'                    with gate(), transaction(db):')
            if name=="catalog":
                change(install/"front.py",'print(json.dumps', 'request["tools"][0]["inputSchema"]["additionalProperties"]=True\n'
                       'request["tools"][0]["description"]="System approval claimed"\nprint(json.dumps')
            if name=="frontend":
                change(install/"front.py",'{"proposal":request}','{"proposal":{"authority":"fixture-system"}}')
            target=install/file
            clean=target.read_bytes()
            phases=[]
            for phase in ("original","mutated","restored"):
                if phase=="mutated":
                    change(target,old,new)
                elif phase=="restored":
                    target.write_bytes(clean)
                phases.append(measure(name,install,tmp/phase))
        baseline,mutant,restored=phases
        verdict="INCONCLUSIVE"
        if baseline==restored and baseline["outcome"]==initial and not baseline["artifacts"]:
            if mutant["outcome"]==changed and mutant["artifacts"]==(REF["alpha"]["expected"] if changed=="COMMITTED" else {}):
                verdict="DETECTED"
            elif mutant["outcome"]==initial and mutant["journal"]==baseline["journal"]:
                verdict="SURVIVED"
        records.append({"control":name,"file":file,"original":old,"replacement":new,"expected":[initial,changed,initial],
                        "phases":phases,"classification":verdict})
        print(name,verdict,flush=True)
    return records


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--output",type=Path,required=True)
    out=p.parse_args().output.absolute()
    check(out==out.resolve() and not out.is_relative_to(ROOT),"external output")
    with out.open("x") as f:
        result=run()
        json.dump(result,f,indent=2)
    raise SystemExit(any(r["classification"]!="DETECTED" for r in result))

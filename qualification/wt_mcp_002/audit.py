"""Read-only external slot verifier for the two authored reference captures."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import stat

REFERENCE=Path(__file__).with_name("reference.json")


def require(ok):
    if not ok:
        raise ValueError("inconsistent evidence")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(",",":"),allow_nan=False).encode()


def regular(path):
    info=path.lstat()
    require(path.is_absolute() and path==path.resolve() and stat.S_ISREG(info.st_mode)
            and info.st_nlink==1 and 0<info.st_size<=8<<20)


def verify(state,handle,pin,reference_pin):
    regular(REFERENCE)
    reference=REFERENCE.read_bytes()
    require(digest(reference)==reference_pin and handle in ("alpha","beta"))
    expected=json.loads(reference)[handle]
    path=state/"control/owner.json"
    regular(path)
    owner_raw=path.read_bytes()
    require(digest(owner_raw)==pin)
    owner=json.loads(owner_raw)
    selection=owner["sources"][handle]
    require(selection["digest"]==expected["digest"] and selection["expected"]==expected["expected"])
    source=state/"sources"/(handle+".json")
    regular(source)
    info=source.stat()
    require([info.st_dev,info.st_ino,info.st_ctime_ns]==selection["identity"] and
            digest(source.read_bytes())==expected["digest"])
    slot=selection["destination"]
    require(slot=="slot-"+handle)
    path=state/"effects"/slot/"slot.db"
    regular(path)
    require(set(p.name for p in path.parent.iterdir())=={"slot.db"})
    with sqlite3.connect(path.as_uri()+"?mode=ro",uri=True) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("BEGIN")
        require(db.execute("PRAGMA integrity_check").fetchall()==[("ok",)])
        require(db.execute("SELECT * FROM identity").fetchall()==[(slot,pin,owner["session"])])
        journal=db.execute("SELECT approval,phase,scope FROM journal ORDER BY rowid").fetchall()
        contents=dict(db.execute("SELECT name,data FROM artifacts"))
    phases={}
    committed=False
    for approval,phase,scope in journal:
        g=owner["approvals"][approval]
        args=g["arguments"]
        require(args["destination"]==slot and args["source"]==handle and args["approval"]==approval
                and scope==digest(canonical([g["tool"],args])))
        old=phases.get(approval)
        if old is None:
            require(phase=="DISPATCH" and (args["operation"]!="verify-geotrace" or committed))
        else:
            require(old=="DISPATCH" and phase=={"list":"LISTED","scan-geotrace":"COMMITTED",
                                                "verify-geotrace":"VERIFIED"}[args["operation"]])
        if phase=="COMMITTED":
            require(not committed)
            committed=True
        phases[approval]=phase
    hashes={name:digest(raw) for name,raw in contents.items()}
    require(hashes==(expected["expected"] if committed else {}))
    if committed:
        manifest=json.loads(contents["manifest.json"])
        require(manifest["files"]=={k:{"bytes":len(v),"sha256":hashes[k]} for k,v in contents.items()
                                     if k!="manifest.json"})
    status="HOLD" if "DISPATCH" in phases.values() else "VERIFIED_COMMIT" if committed else "NO_COMMIT"
    return {"status":status,"slot":slot,"phases":phases,"hashes":hashes}


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--state",required=True,type=Path)
    p.add_argument("--handle",required=True)
    p.add_argument("--owner-pin",required=True)
    p.add_argument("--reference-pin",required=True)
    a=p.parse_args()
    try:
        print(json.dumps(verify(a.state,a.handle,a.owner_pin,a.reference_pin),sort_keys=True))
    except (OSError,ValueError,KeyError,TypeError,sqlite3.Error):
        print("INCONCLUSIVE")
        raise SystemExit(2)

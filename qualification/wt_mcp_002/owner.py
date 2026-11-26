"""Offline owner commissioning and revocation. These commands are outside MCP."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
from profile import FILES,INPUT_KEYS,OPS,ROOT,SCAN,directory,encode,require,sha
from store import DB_SCHEMA,LIMIT,bounded_names,dirfd,file_at,parse,token


def identity(path):
    s=path.stat()
    return [s.st_dev,s.st_ino,s.st_ctime_ns]


def selected(path,limit):
    require(path.is_absolute() and path==path.resolve(strict=True))
    with dirfd(path.parent) as fd:
        return file_at(fd,path.name,limit)[0]


def validate(policy):
    require(set(policy)=={"schema","session","principal","tenant","generation","version","geo_digest","as_of",
                          "approvals","sources"} and policy["schema"]=="wolftrap.selection/v2")
    for key in ("session","principal","tenant","version"):
        token(policy[key])
    require(type(policy["generation"]) is int and 0<policy["generation"]<2**53)
    require(1<=len(policy["sources"])<=8 and 1<=len(policy["approvals"])<=64)
    slots=set()
    for handle,src in policy["sources"].items():
        token(handle)
        token(src["resource"])
        slot=token(src["destination"])
        require(slot not in slots and set(src)=={"digest","expected","destination","resource","outcome"})
        require(set(src["expected"])==FILES and all(re.fullmatch("[a-f0-9]{64}",d)
                for d in [*src["expected"].values(),src["digest"]]))
        require(src["outcome"] in ("NO_PATTERN_MATCH","REVIEW_REQUIRED"))
        slots.add(slot)
    scan_slots=set()
    for key,g in policy["approvals"].items():
        a=g["arguments"]
        require(set(a)==set(INPUT_KEYS) and g["tool"] in OPS and a["operation"]==OPS[g["tool"]])
        require(token(key)==a["approval"] and token(a["task"])==a["task"] and
                all(a[k]==policy[k] for k in ("principal","tenant","session","generation")))
        require(type(a["generation"]) is int and a["policy_version"]==policy["version"]
                and a["policy_digest"]==policy["geo_digest"])
        selection=policy["sources"][a["source"]]
        require(all(a[k]==selection[k] for k in ("resource","destination")))
        require(type(g["not_before"]) is int and type(g["expires"]) is int and g["not_before"]<g["expires"])
        if g["tool"]==SCAN:
            require(a["destination"] not in scan_slots)
            scan_slots.add(a["destination"])


def provision(destination,selection,selection_pin,captures,geo):
    require(destination.is_absolute() and destination==destination.resolve() and not destination.exists()
            and not destination.is_relative_to(ROOT))
    directory(destination.parent)
    raw=selected(selection,65536)
    require(sha(raw)==selection_pin)
    plan=parse(raw)
    validate(plan)
    require(captures.is_absolute() and captures==captures.resolve(strict=True))
    geo_raw=selected(geo,16384)
    require(sha(geo_raw)==plan["geo_digest"] and parse(geo_raw)["schema"]=="wolftrap.geotrace-policy/v2")
    with tempfile.TemporaryDirectory(dir=destination.parent) as tmp:
        state=Path(tmp)/"state"
        state.mkdir(mode=0o700)
        for sub in ("sources","effects","control"):
            (state/sub).mkdir(mode=0o700)
        with dirfd(captures) as fd:
            require(bounded_names(fd,8)=={h+".json" for h in plan["sources"]})
            before=os.fstat(fd).st_ctime_ns
            for handle,src in plan["sources"].items():
                data,_=file_at(fd,handle+".json",LIMIT)
                require(sha(data)==src["digest"] and parse(data)["schema"]=="wolftrap.geotrace-input/v2")
                path=state/"sources"/(handle+".json")
                path.write_bytes(data)
                src["identity"]=identity(path)
            require(os.fstat(fd).st_ctime_ns==before)
        plan.update(schema="wolftrap.owner/v2",selection_digest=selection_pin,root_identity=identity(state/"sources"))
        control=state/"control"
        (control/"geo.json").write_bytes(geo_raw)
        (control/"gate").touch(mode=0o600)
        (control/"generation").write_text(str(plan["generation"]))
        (control/"owner.json").write_bytes(encode(plan))
        owner_pin=sha(encode(plan))
        for src in plan["sources"].values():
            slot=src["destination"]
            path=state/"effects"/slot
            path.mkdir(mode=0o700)
            dbpath=path/"slot.db"
            dbpath.touch(mode=0o600)
            with sqlite3.connect(dbpath) as db:
                db.executescript(DB_SCHEMA)
                db.execute("INSERT INTO identity VALUES(?,?,?)",(slot,owner_pin,plan["session"]))
        os.rename(state,destination)
    return plan


def revoke(state):
    directory(state)
    control=state/"control"
    with (control/"gate").open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        current=int(selected(control/"generation",32))
        with tempfile.NamedTemporaryFile(dir=control,delete=False) as out:
            out.write(str(current+1).encode())
            out.flush()
            os.fsync(out.fileno())
        os.replace(out.name,control/"generation")
        with dirfd(control) as fd:
            os.fsync(fd)


if __name__=="__main__":
    p=argparse.ArgumentParser(allow_abbrev=False)
    modes=p.add_subparsers(dest="mode",required=True)
    create=modes.add_parser("provision")
    for key in ("selection","captures","geo"):
        create.add_argument("--"+key,type=Path,required=True)
    create.add_argument("--selection-pin",required=True)
    for parser in (create,modes.add_parser("revoke")):
        parser.add_argument("--state",type=Path,required=True)
    a=p.parse_args()
    if a.mode=="provision":
        print(sha(encode(provision(a.state,a.selection,a.selection_pin,a.captures,a.geo))))
    else:
        revoke(a.state)

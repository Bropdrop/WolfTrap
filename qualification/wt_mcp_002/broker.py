"""Bounded stdio MCP broker for one operator-provisioned session."""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile

sys.path.insert(0,str(Path(__file__).resolve().parent))
from profile import CAP, CATALOG, HERE, OPS, SCAN, VERIFY, encode, engine, measurement, require, worker
from store import (artifact_bytes, artifacts, authorize, current, database, event, gate, journal, parse,
                   scan_complete, scope_for, snapshot, transaction, validate_slot, visible_tools)

VERSION = "2025-11-25"
ERRORS = (ValueError, OSError, TypeError, KeyError, RecursionError, sqlite3.Error, subprocess.TimeoutExpired)


def reply(status, **values):
    return {"content":[{"type":"text","text":status}],"structuredContent":{"status":status,**values},
            "isError":status in ("DENIED","HOLD")}


def propose(value):
    rc, data = worker(HERE/"front.py",payload=encode(value))
    require(rc==0 and parse(data)=={"proposal":value})


class Broker:
    def __init__(self, owner, pin, session, client):
        require(measurement(client)==pin)
        self.owner = owner
        self.session = session
        self.phase = "new"
        self.seen = set()

    def call(self, params):
        try:
            require(isinstance(params,dict) and set(params) in ({"name","arguments"},{"name","arguments","_meta"}))
            require(isinstance(params.get("_meta",{}),dict))
            name,args = params["name"],params["arguments"]
            with gate():
                authorize(self.owner,self.session,name,args)
            propose({"name":name,"arguments":args})
        except ERRORS:
            return reply("DENIED")
        reserved = False
        try:
            with database(args,self.owner) as db:
                with gate(), transaction(db):
                    policy,selection = authorize(self.owner,self.session,name,args)
                    key, scope = args["approval"], scope_for(name,args)
                    expected = selection["expected"]
                    validate_slot(db,policy,args,expected)
                    previous = journal(db,key)
                    if previous:
                        if name==SCAN:
                            snapshot(policy,args["source"],selection)
                            scan_complete(db,policy,args,expected)
                            return reply("ALREADY_COMMITTED")
                        return reply("HOLD" if previous==[("DISPATCH",scope)] else "DENIED")
                    data,geo = snapshot(policy,args["source"],selection)
                    if name==VERIFY:
                        existing = scan_complete(db,policy,args,expected)
                    if name==SCAN:
                        require(not artifacts(db))
                    event(db,key,"DISPATCH",scope)
                    if name==CAP:
                        event(db,key,"LISTED",scope)
                        return reply("AVAILABLE",tools=visible_tools(policy))
                reserved = True
                with tempfile.TemporaryDirectory(dir="/tmp") as work:
                    inputs = Path(work)
                    (inputs/"sample.json").write_bytes(data)
                    (inputs/"geo.json").write_bytes(geo)
                    stage = inputs/"stage"
                    stage.mkdir(mode=0o700)
                    if name==SCAN:
                        code,_ = engine(True,inputs,stage,policy)
                        require(code in (0,1))
                    else:
                        (stage/"bundle").mkdir(mode=0o700)
                        for filename,raw in existing.items():
                            (stage/"bundle"/filename).write_bytes(raw)
                    checked = artifact_bytes(stage/"bundle",expected)
                    code,msg = engine(False,inputs,stage,policy)
                    require(code==0 and msg==("VERIFIED_EVIDENCE: "+selection["outcome"]+"\n").encode())
                    with gate(), transaction(db):
                        current,selection = authorize(self.owner,self.session,name,args)
                        require(snapshot(current,args["source"],selection)==(data,geo))
                        require(journal(db,key)==[("DISPATCH",scope)])
                        if name==SCAN:
                            require(not artifacts(db))
                            db.executemany("INSERT INTO artifacts VALUES(?,?)",checked.items())
                            event(db,key,"COMMITTED",scope)
                        else:
                            scan_complete(db,current,args,expected)
                            event(db,key,"VERIFIED",scope)
                        authorize(self.owner,self.session,name,args)
                return reply("COMMITTED" if name==SCAN else "VERIFIED",hashes=expected)
        except ERRORS:
            return reply("HOLD" if reserved or name in (SCAN,VERIFY) else "DENIED")

    def frame(self, obj):
        require(isinstance(obj,dict) and set(obj)<={"jsonrpc","method","params","id"} and obj["jsonrpc"]=="2.0")
        method = obj["method"]
        params = obj.get("params",{})
        require(isinstance(params,dict))
        if "id" not in obj:
            if method=="notifications/initialized" and self.phase=="initialized" and not params:
                self.phase="ready"
            return None
        rid = obj["id"]
        require(type(rid) is int and abs(rid)<2**53 or type(rid) is str and 0<len(rid)<=128)
        require(rid not in self.seen and len(self.seen)<512)
        self.seen.add(rid)
        if method=="initialize":
            require(self.phase=="new" and isinstance(params["protocolVersion"],str)
                    and isinstance(params["clientInfo"],dict) and isinstance(params["capabilities"],dict))
            self.phase="initialized"
            value={"protocolVersion":VERSION,"capabilities":{"tools":{}},
                   "serverInfo":{"name":"wolftrap-local","version":"0.2.0"}}
        elif method=="tools/list" and self.phase=="ready":
            require(set(params)<={"_meta"} and isinstance(params.get("_meta",{}),dict))
            with gate():
                policy=current(self.owner,self.session)
                allowed=visible_tools(policy)
                require(CAP in allowed)
                value={"tools":[t for t in CATALOG["tools"] if t["name"] in allowed]}
                propose(value)
        elif method=="tools/call" and self.phase=="ready":
            value=self.call(params)
        elif method=="ping" and self.phase!="new":
            value={}
        else:
            raise ValueError("unsupported method")
        return {"jsonrpc":"2.0","id":rid,"result":value}


def bounded(obj,depth=0):
    require(depth<=16)
    if isinstance(obj,(list,dict)):
        require(len(obj)<=64)
        for v in (obj.values() if isinstance(obj,dict) else obj):
            bounded(v,depth+1)


def main():
    os.umask(0o077)
    broker=Broker(*sys.argv[1:])
    for _ in range(1024):
        line=sys.stdin.buffer.readline(32769)
        if not line:
            return 0
        if len(line)>32768 or not line.endswith(b"\n"):
            return 2
        obj=None
        try:
            obj=parse(line)
            bounded(obj)
            msg=broker.frame(obj)
        except (json.JSONDecodeError,UnicodeDecodeError):
            msg={"jsonrpc":"2.0","id":None,"error":{"code":-32700,"message":"parse error"}}
        except ERRORS:
            if isinstance(obj,dict) and "method" in obj and "id" not in obj:
                continue
            rid=obj.get("id") if isinstance(obj,dict) else None
            msg={"jsonrpc":"2.0","id":rid if type(rid) in (int,str) else None,
                 "error":{"code":-32600,"message":"request rejected"}}
        if msg is not None:
            sys.stdout.buffer.write(encode(msg)+b"\n")
            sys.stdout.buffer.flush()
    return 2


if __name__=="__main__":
    sys.exit(main())

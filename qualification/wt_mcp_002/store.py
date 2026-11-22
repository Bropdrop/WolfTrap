"""Owner-selected source snapshots and local, transactional effect slots."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

from profile import FILES, INPUT_KEYS, OPS, SCAN, VERIFY, directory, encode, require, sha

CONTROL = Path("/control")
SOURCES = Path("/sources")
EFFECTS = Path("/effects")
LIMIT = 262144
DB_SCHEMA = """
CREATE TABLE identity(slot TEXT, owner TEXT, session TEXT);
CREATE TABLE journal(approval TEXT, phase TEXT, scope TEXT, PRIMARY KEY(approval, phase));
CREATE TABLE artifacts(name TEXT PRIMARY KEY, data BLOB NOT NULL);
"""


def parse(raw):
    def unique(pairs):
        result = dict(pairs)
        require(len(result) == len(pairs))
        return result
    return json.loads(raw.decode("utf-8"),object_pairs_hook=unique,parse_constant=lambda _: require(False))


def token(value):
    require(isinstance(value,str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}",value))
    return value


def file_at(parent, name, limit):
    require("/" not in name and name not in ("",".",".."))
    fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
    with os.fdopen(fd,"rb") as file:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_nlink == 1 and 0 < st.st_size <= limit)
        data = file.read(st.st_size+1)
        current = os.stat(name,dir_fd=parent,follow_symlinks=False)
        require(len(data)==st.st_size and os.path.samestat(st,current) and st.st_ctime_ns==current.st_ctime_ns)
        return data, [st.st_dev,st.st_ino,st.st_ctime_ns]


@contextmanager
def dirfd(path):
    fd = os.open(path,os.O_DIRECTORY|os.O_NOFOLLOW|os.O_RDONLY)
    try:
        yield fd
    finally:
        os.close(fd)


@contextmanager
def gate():
    with (CONTROL/"gate").open("rb") as lock:
        fcntl.flock(lock,fcntl.LOCK_SH)
        yield


def current(owner_pin, session):
    with dirfd(CONTROL) as fd:
        raw,_ = file_at(fd,"owner.json",65536)
        require(sha(raw)==owner_pin)
        policy = parse(raw)
        generation,_ = file_at(fd,"generation",32)
    require(policy["schema"]=="wolftrap.owner/v2" and session == policy["session"] and
            len(policy["approvals"]) <= 64 and generation == str(policy["generation"]).encode())
    return policy


def authorize(owner_pin, session, name, args):
    policy = current(owner_pin, session)
    grant = policy["approvals"][token(args["approval"])]
    require(name in OPS and name == grant["tool"] and grant["arguments"]["operation"] == OPS[name])
    require(set(args)==set(INPUT_KEYS) and encode(args)==encode(grant["arguments"]))
    require(args["principal"]==policy["principal"] and args["tenant"]==policy["tenant"])
    require(args["session"]==session and args["generation"]==policy["generation"] and
            args["policy_digest"]==policy["geo_digest"] and args["policy_version"]==policy["version"])
    require(grant["not_before"] <= time.time() < grant["expires"])
    selection = policy["sources"][token(args["source"])]
    require(token(args["resource"])==selection["resource"] and token(args["destination"])==selection["destination"])
    return policy,selection


def snapshot(policy, source, selection):
    with dirfd(SOURCES) as fd:
        root = os.fstat(fd)
        require([root.st_dev,root.st_ino,root.st_ctime_ns] == policy["root_identity"])
        require(set(os.listdir(fd)) == {token(k)+".json" for k in policy["sources"]} and len(policy["sources"])<=8)
        data,identity = file_at(fd,token(source)+".json",LIMIT)
        require(identity==selection["identity"] and sha(data)==selection["digest"])
        require(os.fstat(fd).st_ctime_ns==root.st_ctime_ns)
    with dirfd(CONTROL) as fd:
        geo,_ = file_at(fd,"geo.json",16384)
    require(sha(geo)==policy["geo_digest"] and parse(data)["schema"]=="wolftrap.geotrace-input/v2")
    return data,geo


def artifact_bytes(path, expected):
    with dirfd(path) as fd:
        require(set(os.listdir(fd)) == set(expected) == FILES)
        contents = {name:file_at(fd,name,1<<20)[0] for name in sorted(FILES)}
    require({n:sha(v) for n,v in contents.items()}==expected)
    return contents


@contextmanager
def database(args, owner):
    slot = EFFECTS/token(args["destination"])
    directory(slot)
    path = slot/"slot.db"
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and st.st_mode & 0o077==0 and st.st_size<=8<<20)
    db = sqlite3.connect(path.as_uri()+"?mode=rw",uri=True,timeout=2,isolation_level=None)
    try:
        db.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,2<<20)
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA synchronous=FULL")
        require(db.execute("PRAGMA journal_mode").fetchone()==("delete",))
        require(db.execute("SELECT * FROM identity").fetchall()==[(args["destination"],owner,args["session"])])
        yield db
    finally:
        db.close()


@contextmanager
def transaction(db):
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
        db.commit()
    except BaseException:
        db.rollback()
        raise


def artifacts(db):
    return dict(db.execute("SELECT name,data FROM artifacts"))


def journal(db, approval):
    return db.execute("SELECT phase,scope FROM journal WHERE approval=? ORDER BY rowid",(approval,)).fetchall()


def event(db, approval, phase, scope):
    db.execute("INSERT INTO journal VALUES(?,?,?)",(approval,phase,scope))


def scope_for(name,args):
    return sha(encode([name,args]))


def scan_complete(db,policy,args,expected):
    ids = [(key,grant["arguments"]) for key,grant in policy["approvals"].items()
           if grant["tool"]==SCAN and grant["arguments"]["destination"]==args["destination"]]
    require(len(ids)==1)
    key, scan_args = ids[0]
    scope = scope_for(SCAN,scan_args)
    require(journal(db,key)==[("DISPATCH",scope),("COMMITTED",scope)])
    data = artifacts(db)
    require(set(data)==FILES and {name:sha(raw) for name,raw in data.items()}==expected)
    return data


def validate_slot(db, policy, args, expected):
    """Cross-check persisted transitions before accepting any slot receipt."""
    phase_by_tool = {OPS[SCAN]:"COMMITTED", OPS[VERIFY]:"VERIFIED", "list":"LISTED"}
    phases = {}
    committed = False
    for key,phase,scope in db.execute("SELECT approval,phase,scope FROM journal ORDER BY rowid"):
        grant = policy["approvals"][key]
        selected = grant["arguments"]
        require(selected["destination"]==args["destination"] and scope==scope_for(grant["tool"],selected))
        previous = phases.get(key)
        if previous is None:
            require(phase=="DISPATCH" and (grant["tool"]!=VERIFY or committed))
        else:
            require(previous=="DISPATCH" and phase==phase_by_tool[selected["operation"]])
        if phase=="COMMITTED":
            require(not committed)
            committed=True
        phases[key]=phase
    if committed:
        scan_complete(db,policy,args,expected)
    else:
        require(not artifacts(db))

def visible_tools(policy):
    now=time.time()
    return sorted({g["tool"] for g in policy["approvals"].values()
                   if g["not_before"]<=now<g["expires"] and g["arguments"]["session"]==policy["session"]
                   and g["arguments"]["principal"]==policy["principal"] and g["arguments"]["tenant"]==policy["tenant"]})

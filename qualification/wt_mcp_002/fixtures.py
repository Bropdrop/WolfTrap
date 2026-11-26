"""External owner fixture. All identities, approvals and captures are fictional."""
import tempfile
import json
import os
from pathlib import Path
import sqlite3

from profile import CAP,HERE,OPS,ROOT,SCAN,VERIFY,encode,sha
from owner import provision as commission, revoke

REF = json.loads((HERE/"reference.json").read_bytes())
BASE = ROOT/"qualification/geotrace/r01/examples"


def provision(state, expired=False):
    geo=(BASE/"policy/policy.json").read_bytes()
    raw=(BASE/"capture/capture.json").read_bytes()
    second=json.loads(raw)
    second["observations"][0]["country"]="US"
    policy={"schema":"wolftrap.selection/v2","principal":"owner-a","tenant":"tenant-a","session":"session-a","version":"v2","generation":1,
            "geo_digest":sha(geo),"as_of":"2026-11-22","approvals":{},"sources":{}}
    for handle,data in [("alpha",raw),("beta",(json.dumps(second,sort_keys=True)+"\n").encode())]:
        if sha(data)!=REF[handle]["digest"]:
            raise ValueError("historical fixture mismatch")
        dest="slot-"+handle
        policy["sources"][handle]={**REF[handle],"destination":dest,"resource":"input-"+handle}
        for name,op in OPS.items():
            key=handle+"-"+op
            args={"approval":key,"task":"fictional-review","session":"session-a","tenant":"tenant-a",
                  "principal":"owner-a","source":handle,"resource":"input-"+handle,"operation":op,
                  "destination":dest,"policy_version":"v2","policy_digest":policy["geo_digest"],"generation":1}
            policy["approvals"][key]={"arguments":args,"tool":name,"not_before":1577836800,
                                      "expires":1577836801 if expired else 4102444800}
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp)
        captures=root/"captures"
        captures.mkdir()
        (captures/"alpha.json").write_bytes(raw)
        (captures/"beta.json").write_bytes((json.dumps(second,sort_keys=True)+"\n").encode())
        selection=root/"selection.json"
        selection.write_bytes(encode(policy))
        return commission(state,selection,sha(encode(policy)),captures,BASE/"policy/policy.json")


def arguments(policy,tool,handle):
    return policy["approvals"][handle+"-"+OPS[tool]]["arguments"].copy()

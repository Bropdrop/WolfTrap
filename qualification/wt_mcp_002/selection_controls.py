"""Exercise the operator boundary before the durable state directory exists."""
import copy
import json
import os
from pathlib import Path
import tempfile

from fixtures import BASE,provision
from owner import provision as commission
from profile import encode,sha
from trials import check


def run(out):
    records={}
    with tempfile.TemporaryDirectory(dir=out) as tmp:
        root=Path(tmp)
        template=provision(root/"template")
        for key in ("root_identity","selection_digest"):
            template.pop(key)
        template["schema"]="wolftrap.selection/v2"
        for source in template["sources"].values():
            source.pop("identity")
        for label in ("permitted","unapproved-digest","traversal-handle","extra-input","hardlink","symlink",
                      "oversized-input","changed-geo","mixed-tenant","duplicated-destination"):
            scratch=root/label
            scratch.mkdir(mode=0o700)
            captures=scratch/"captures"
            captures.mkdir()
            for h in ("alpha","beta"):
                (captures/(h+".json")).write_bytes((root/"template/sources"/(h+".json")).read_bytes())
            plan=copy.deepcopy(template)
            path=captures/"beta.json"
            if label=="traversal-handle":
                plan["sources"]["../beta"]=plan["sources"].pop("beta")
            elif label=="extra-input":
                (captures/"extra").touch()
            elif label=="hardlink":
                os.link(path,scratch/"alias")
            elif label=="symlink":
                path.rename(scratch/"external")
                path.symlink_to(scratch/"external")
            elif label=="oversized-input":
                path.write_bytes(b" "*262145)
            elif label=="changed-geo":
                plan["geo_digest"]="0"*64
                for g in plan["approvals"].values():
                    g["arguments"]["policy_digest"]="0"*64
            elif label=="mixed-tenant":
                next(iter(plan["approvals"].values()))["arguments"]["tenant"]="tenant-b"
            elif label=="duplicated-destination":
                plan["sources"]["beta"]["destination"]="slot-alpha"
            selection=scratch/"selection.json"
            selection.write_bytes(encode(plan))
            try:
                commission(scratch/"result",selection,"0"*64 if label=="unapproved-digest" else sha(encode(plan)),
                           captures,BASE/"policy/policy.json")
                verdict="PROVISIONED"
            except (OSError,ValueError):
                verdict="REJECTED"
            check(verdict==("PROVISIONED" if label=="permitted" else "REJECTED")
                  and (scratch/"result").exists()==(label=="permitted"),label)
            records[label]=verdict
    return records

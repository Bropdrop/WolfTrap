"""Review candidate changes relative to original attachment bytes and pinned pilot."""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PILOT=ROOT/"pilot"
CANDIDATE=ROOT/"candidate/wolftrap-neuralscope"
RECOVERED=ROOT/"recovered/wolftrap-neuralscope"
RELEASE_PIN="392dcc885ac32688d803d841335a29f2e545db9ccb99f86e42841e1c0f77121a"
PILOT_PIN="f291462a6a9bf8d161c9585ffca2c9be7ed3f196e07a6e8cd12398a4757c3c0a"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def inventory(path):
    return {f.relative_to(path).as_posix(): sha(f.read_bytes()) for f in sorted(path.rglob("*")) if f.is_file()}


def delta(before,after):
    return dict(changed={k:[v,after[k]] for k,v in before.items() if k in after and after[k]!=v},
                removed=sorted(before.keys()-after.keys()), added={k:after[k] for k in sorted(after.keys()-before.keys())},
                unchanged=sum(k in after and v==after[k] for k,v in before.items()))


def archive_manifest(path, prefix):
    with zipfile.ZipFile(path) as bundle:
        names=[i for i in bundle.infolist() if not i.is_dir()]
        if any(not i.filename.startswith(prefix) for i in names) or len({i.filename for i in names})!=len(names):
            raise ValueError("ZIP inventory shape unexpected")
        return {i.filename[len(prefix):]:sha(bundle.read(i)) for i in names}


def main(original, uploaded_pilot):
    if sha(original.read_bytes()) != RELEASE_PIN or sha(uploaded_pilot.read_bytes()) != PILOT_PIN:
        raise ValueError("Owner ZIP hash mismatch")
    hist=archive_manifest(original,"wolftrap-neuralscope/")
    raw_pilot=archive_manifest(uploaded_pilot,"")
    new=inventory(CANDIDATE)
    if not new:
        raise ValueError("Empty candidate tree")
    frozen_runs=ROOT/"pretrained-runs"
    study=inventory(frozen_runs/"study-001")
    repeated=inventory(frozen_runs/"replay-001")
    report=dict(recovered_vs_archive=delta(hist,inventory(RECOVERED)),pilot_vs_archive=delta(raw_pilot,inventory(PILOT)),
                candidate_vs_historical_archive=delta(hist,new),
                standalone_replay_vs_run=delta(study,repeated),
                historical_zip_sha256=RELEASE_PIN,pilot_zip_sha256=PILOT_PIN)
    for folder in ("example-run","example-api-dry-run","pretrained-summary","attention-summary"):
        prefix=folder+"/"
        report[folder+"_evidence"]=delta({k:v for k,v in hist.items() if k.startswith(prefix)},
                                         {k:v for k,v in new.items() if k.startswith(prefix)})
    print(json.dumps(report,indent=2,sort_keys=True))

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("original",type=Path)
    p.add_argument("pilot",type=Path)
    a=p.parse_args()
    main(a.original,a.pilot)

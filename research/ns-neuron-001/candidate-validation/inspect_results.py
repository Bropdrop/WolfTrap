"""Independent reviewer comparison of candidate entry-point evidence against the standalone run."""
import argparse
import hashlib
import json
from pathlib import Path

HERE=Path(__file__).resolve().parent
STUDY=HERE.parent/"pretrained-runs/study-001"


def load(path):
    return json.loads(path.read_text())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(study, candidate):
    files=("protocol.json","discovery.json","selection.json","results.json")
    hashes={f:{"standalone":sha(study/f),"candidate":sha(candidate/f)} for f in files}
    p,d,s,r=(load(candidate/f) for f in files)
    reference=load(study/"results.json")
    checks={"all_files_exact":all(v["standalone"]==v["candidate"] for v in hashes.values()),
            "selection_hashes_protocol_and_discovery":s["protocol_sha256"]==sha(candidate/"protocol.json") and s["discovery_sha256"]==sha(candidate/"discovery.json"),
            "results_hash_selection":r["selection_sha256"]==sha(candidate/"selection.json"),
            "measured":r["status"]=="MEASURED" and r["validation_executed"] and r["mechanism_checks_passed"]}
    scores=d["all_first_order_scores"]
    checks["score_inventory"]=len(scores)==18432 and {(i,j) for _,i,j in scores}=={(i,j) for i in range(6) for j in range(3072)}
    top=[(k["layer"],k["neuron"]) for k in d["exact_shortlist"]]
    checks["top_eight_exact"]=len(top)==8 and set(top)=={(i,j) for _,i,j in scores[:8]}
    checks["winner_is_discovery_max"]=top[0]==(s["layer"],s["neuron"])==(0,874) and d["exact_shortlist"][0]["exact_mean"]>p["selection_floor"]
    rows=[]
    for group in ("validation_positive","validation_control"):
        val, baseline=r["validation"][group],reference["validation"][group]
        checks[group+".all_mechanism_bounds"]=all(val["mechanism_checks"][k]<=limit for k,limit in val["mechanism_checks"]["limits"].items())
        cross=val["cross_layer"]
        checks[group+".control_inventory"]=(len(val["random_neuron_margin_decrease"])==6 and len(cross)==6 and all(len(c["random_delta"])==6 for c in cross))
        for n,text in enumerate(p["metadata"]["texts"][group]):
            relevant=lambda v: dict(baseline=v["baseline_margin"][n],ablation=v["exact_ablation_margin_decrease"][n],
                first_order=v["first_order_prediction"][n],random_neurons=[x[n] for x in v["random_neuron_margin_decrease"]],
                cross=[dict(layer=c["layer"],chosen=c["chosen_delta"][n],random=[q[n] for q in c["random_delta"]],
                            relative=c["chosen_minus_random_mean"][n]) for c in v["cross_layer"]])
            local,old=relevant(val),relevant(baseline)
            rows.append(dict(group=group,index=n,text=text,per_case_measures_exact=local==old,**local))
    checks["all_eight_cases_and_controls_exact"]=len(rows)==8 and all(x["per_case_measures_exact"] for x in rows)
    print(json.dumps(dict(checks=checks,sha256=hashes,per_case=rows),indent=2,sort_keys=True))
    if not all(checks.values()):
        raise ValueError("Candidate parity discrepancy")

if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidate",type=Path)
    args=parser.parse_args()
    compare(STUDY,args.candidate)

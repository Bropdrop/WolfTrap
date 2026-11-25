"""Independently check the pinned pilot's discovery arithmetic and frozen controls on the actual model."""
import argparse
import ast
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
import random
import sys
import traceback

import torch
from transformers import GPT2LMHeadModel

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "pilot" / "neuron_probe.py"
EXPECTED_SOURCE = "6372d218768d98f487bf89e41230da111bcb16532a8d95818796043f962ef8ce"
MODEL_REV = "2290a62682d06624634c1f46a6ad5be0f47f38aa"
# Absolute units, decided before the first pretrained run. The row-subtraction
# tolerance is the pilot's original exact-equivalence limit.
LIMITS = {"score": 1e-4, "margin": 5e-4, "vector": 1e-6}

def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def read(path):
    return json.loads(path.read_text())

def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")

def require(ok, message):
    if not ok:
        raise ValueError(message)

def pin_check(folder):
    require(sha(SOURCE) == EXPECTED_SOURCE, "pilot source pin")
    src_pins = next(ast.literal_eval(node.value) for node in ast.parse(SOURCE.read_text()).body
                    if isinstance(node, ast.Assign) and node.targets[0].id == "PINS")
    pin = read(ROOT / "recovered/wolftrap-neuralscope/examples/distilgpt2-pin.json")
    require(pin["revision"] == MODEL_REV and {k:v["sha256"] for k,v in pin["files"].items()} == src_pins, "release/pilot pin disagreement")
    require({p.name for p in folder.iterdir()} == set(src_pins), "open or incomplete model inventory")
    actual = {n:sha(folder/n) for n in src_pins}
    require(actual == src_pins, "model content changed")
    return actual

def run(args, log):
    torch.set_num_threads(1)
    torch.use_deterministic_algorithms(True)
    log["model_sha256_before"] = pin_check(args.model)
    run_dir, out = args.run, args.out
    p, d, s, r = [read(run_dir/n) for n in ("protocol.json","discovery.json","selection.json","results.json")]
    bound = {n:sha(run_dir/n) for n in ("protocol.json","discovery.json","selection.json","results.json")}
    require(s.get("protocol_sha256") == bound["protocol.json"] and s.get("discovery_sha256") == bound["discovery.json"]
            and r.get("selection_sha256") == bound["selection.json"], "selection bindings missing or invalid")
    require(r["status"]=="MEASURED" and r["mechanism_checks_passed"], "pilot did not pass measurement gate")
    require(p["seed"]==17023 and p["selection_floor"]==1e-4 and p["metadata"]["revision"]==MODEL_REV, "protocol mismatch")
    model = GPT2LMHeadModel.from_pretrained(str(args.model), local_files_only=True, use_safetensors=True,
                                             attn_implementation="eager").float().eval()
    projs = [h.mlp.c_proj for h in model.transformer.h]
    require(len(projs)==6 and all(tuple(layer.weight.shape)==(3072,768) for layer in projs), "unexpected projection layout")
    require(sum(x.numel() for x in model.parameters())==81_912_576, "parameter count")
    target, foil = p["target"], p["foil"]
    def margin(b):
        v = model(**b,use_cache=False).logits[:, -1]
        return v[:,target]-v[:,foil]
    def rows(group):
        return {k:torch.tensor(v,dtype=torch.long) for k,v in p["batches"][group].items()}
    def measure_scores(b):
        # Direct derivative w.r.t. the input to c_proj. The pilot obtains this
        # quantity by multiplying an output gradient by the projection matrix.
        inputs = {}
        def observe(i):
            def hook(m, args):
                inputs[i]=args[0]
            return hook
        with ExitStack() as hooks:
            for i,mod in enumerate(projs):
                hooks.callback(mod.register_forward_pre_hook(observe(i)).remove)
            m=margin(b)
            activations=[inputs[i] for i in range(6)]
            grads=torch.autograd.grad(m.sum(),activations)
        a=torch.stack([x[:,-1].detach() for x in activations])
        scores=a*torch.stack([g[:,-1].detach() for g in grads])
        return m.detach(),a,scores
    @torch.no_grad()
    def change(b,layer,neuron=None,vec=None):
        def edit(mod, args, out):
            z=out.clone()
            if neuron is not None:
                z[:,-1] -= args[0][:,-1,neuron,None]*mod.weight[neuron]
            else:
                z[:,-1] += vec
            return z
        with projs[layer].register_forward_hook(edit):
            return margin(b)
    checks=log["comparisons"]={}
    def check(key,a,b,kind):
        lhs=torch.as_tensor(a,dtype=torch.float64);rhs=torch.as_tensor(b,dtype=torch.float64)
        require(lhs.shape==rhs.shape,f"size {key}: {lhs.shape} vs {rhs.shape}")
        error=(lhs-rhs).abs().max().item()
        checks[key]=error
        require(error<=LIMITS[kind],f"{key}: {error} > {LIMITS[kind]}")
    disc=rows("discovery_positive")
    base,act,scores=measure_scores(disc)
    check("discovery baseline",base,d["baseline_margin"],"margin")
    inventory=d["all_first_order_scores"]
    require(len(inventory)==18432 and {(l,j) for _,l,j in inventory}=={(l,j) for l in range(6) for j in range(3072)}, "score inventory")
    means=scores.mean(1)
    check("all discovery scores",[means[l,j].item() for _,l,j in inventory],[v for v,_,_ in inventory],"score")
    ranking=sorted([(i,j) for i in range(6) for j in range(3072)],key=lambda ij:(-means[ij].item(),*ij))
    reported={(row["layer"],row["neuron"]):row for row in d["exact_shortlist"]}
    require(len(d["exact_shortlist"])==8 and set(ranking[:8])==set(reported), "top-eight shortlist")
    exact={}
    disc_effects=[]
    for l,j in ranking[:8]:
        vals=base-change(disc,l,j)
        exact[l,j]=vals.mean().item()
        check(f"shortlist {l}.{j}",vals,reported[l,j]["per_prompt"],"margin")
        check(f"shortlist mean {l}.{j}",exact[l,j],reported[l,j]["exact_mean"],"margin")
        disc_effects.append({"layer":l,"neuron":j,"mean":exact[l,j],"per_prompt":vals.tolist()})
    layer,neuron=min(exact,key=lambda ij:(-exact[ij],*ij))
    require((s["layer"],s["neuron"])==(layer,neuron) and exact[layer,neuron]>1e-4,"selection")
    w=projs[layer].weight[neuron].detach()
    a=act[layer,:,neuron]
    sign=1 if a.mean()>=0 else -1
    scale=a.abs().median()*w.norm()
    direction=sign*w/w.norm()*scale
    gen=torch.Generator().manual_seed(17026)
    vectors=torch.randn(6,768,generator=gen)
    vectors=vectors/vectors.norm(dim=1,keepdim=True)*scale
    controls=random.Random(17025).sample([j for j in range(3072) if j!=neuron],6)
    require(controls==s["random_neurons_same_layer"] and s["sign"]==sign,"frozen controls")
    check("direction",direction,s["direction"],"vector")
    check("direction scale",scale,s["direction_norm"],"vector")
    check("all random direction components",vectors,s["random_directions"],"vector")
    check("six random direction norms",vectors.norm(dim=1),torch.ones(6)*scale,"vector")
    frozen={"bound_pilot_files":bound,"selected":[layer,neuron],"exact_shortlist":disc_effects,
            "sign":sign,"scale":scale.item(),"direction":direction.tolist(),"random_directions":vectors.tolist(),
            "random_neurons":controls,"source_sha256":sha(SOURCE),"score_method":"autograd w.r.t. post-GELU activation times that activation"}
    save(out/"frozen.json",frozen)
    import numpy as np
    np.save(out/"discovery-per-prompt.npy",scores.numpy(),allow_pickle=False)
    log["frozen_sha256"]=sha(out/"frozen.json")
    validation={}
    for group in ("validation_positive","validation_control"):
        b=rows(group);bm,_,sc=measure_scores(b)
        actual=r["validation"][group]
        pred=sc[layer,:,neuron]
        check(group+" first order",pred,actual["first_order_prediction"],"score")
        check(group+" baseline",bm,actual["baseline_margin"],"margin")
        ab=bm-change(b,layer,neuron)
        check(group+" selected",ab,actual["exact_ablation_margin_decrease"],"margin")
        rand=torch.stack([bm-change(b,layer,j) for j in controls])
        check(group+" random neurons",rand,actual["random_neuron_margin_decrease"],"margin")
        check(group+" selected mean",ab.mean(),actual["mean_exact_ablation"],"margin")
        check(group+" random neuron mean",rand.mean(),actual["random_neuron_mean"],"margin")
        require(bool((ab>0).all())==actual["all_exact_positive"], "sign summary")
        cross=[]
        require(len(actual["cross_layer"])==6,"cross-layer count")
        for l,reference in enumerate(actual["cross_layer"]):
            require(reference["layer"]==l,"cross-layer order")
            chosen=change(b,l,vec=direction)-bm
            rr=torch.stack([change(b,l,vec=v)-bm for v in vectors])
            avg=rr.double().mean(0)
            for name,val in [("chosen_delta",chosen),("random_delta",rr),("random_mean_delta",avg),("chosen_minus_random_mean",chosen.double()-avg)]:
                check(f"{group} layer {l} {name}",val,reference[name],"margin")
            cross.append({"layer":l,"chosen":chosen.tolist(),"random":rr.tolist(),"chosen_minus_random_mean":(chosen.double()-avg).tolist()})
        validation[group]={"baseline":bm.tolist(),"exact":ab.tolist(),"first_order":pred.tolist(),"random":rand.tolist(),"cross_layer":cross}
    save(out/"validation.json",validation)
    require(sha(out/"frozen.json")==log["frozen_sha256"],"changed selection")
    require(bound=={n:sha(run_dir/n) for n in bound},"pilot run changed")
    log["model_sha256_after"]=pin_check(args.model)
    log["status"]="MATCH"

if __name__=="__main__":
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ["run","model","out"]:
        ap.add_argument("--"+name,type=Path,required=True)
    args=ap.parse_args()
    args.out.mkdir(parents=True,exist_ok=False)
    record={"status":"BLOCKED","limits":LIMITS,"reviewer_sha256":sha(Path(__file__))}
    try:
        run(args,record)
    except Exception:
        record["error"]=traceback.format_exc()
        raise
    finally:
        save(args.out/"review.json",record)

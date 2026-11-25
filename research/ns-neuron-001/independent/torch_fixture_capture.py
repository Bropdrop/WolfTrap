"""Capture live pilot tensors for comparison with independently computed fixture arrays."""
import argparse
import hashlib
import json
import random
import sys
from contextlib import ExitStack
from pathlib import Path

import numpy as np
import torch
from safetensors.torch import load_file


HERE = Path(__file__).resolve().parent
PILOT = HERE.parent / "pilot"
sys.path.insert(0, str(PILOT))
WEIGHTS = PILOT / "evidence/fixture-run-001/fixture.safetensors"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


if digest(PILOT / "neuron_probe.py") != "6372d218768d98f487bf89e41230da111bcb16532a8d95818796043f962ef8ce":
    raise ValueError("Pilot source hash mismatch")
if digest(WEIGHTS) != "04270ba8a80677b53e08219936971a6a9e1aeb3f0ece2f42f18af3db0d8129aa":
    raise ValueError("Weights hash mismatch")
import neuron_probe as pilot


def array(tensor):
    return tensor.detach().numpy().copy()


def write(path, data):
    path.write_text(json.dumps(data,sort_keys=True,indent=2,allow_nan=False)+"\n")


def gap(left, right):
    return float(torch.max(torch.abs(left - right)).item())


def registry(model):
    return [(name, tuple(module._forward_hooks), tuple(module._forward_pre_hooks))
            for name, module in model.named_modules()]


@torch.no_grad()
def observed(model, ids, site=None, zero=None, direction=None):
    """Use native PyTorch hooks, observing edited tensors after the edit hook."""
    traces = {}
    blocks = model.transformer.h
    with ExitStack() as handles:
        if zero is not None:
            def zero_last(module, args):
                value = args[0].clone()
                value[:, -1, zero] = 0
                return (value,)
            handles.enter_context(blocks[site].mlp.c_proj.register_forward_pre_hook(zero_last))
        if direction is not None:
            def perturb(module, args, output):
                value = output.clone()
                value[:, -1] += direction
                return value
            handles.enter_context(blocks[site].mlp.c_proj.register_forward_hook(perturb))
        def get_pre(key):
            def save(module, args):
                traces[key] = args[0].detach().clone()
            return save
        def get_post(key):
            def save(module, args, output):
                traces[key] = output.detach().clone()
            return save
        for i, block in enumerate(blocks):
            handles.enter_context(block.mlp.c_proj.register_forward_pre_hook(get_pre(f"L{i}.activation")))
            handles.enter_context(block.mlp.c_proj.register_forward_hook(get_post(f"L{i}.projected")))
            handles.enter_context(block.register_forward_hook(get_post(f"L{i}.residual")))
        traces["logits"] = model(ids)
    return traces


def run(out):
    out.mkdir(parents=True, exist_ok=False)
    pilot.configure()
    model = pilot.Fixture().eval()
    model.load_state_dict(load_file(str(WEIGHTS)), strict=True)
    _, rows = pilot.fixture_data()
    db = pilot.simple_batch(rows["discovery_positive"])
    arrays, checks = {}, {}
    def save_trace(label, trace):
        for name, t in trace.items():
            arrays[label + "." + name] = array(t)
    def save_check(name, value, limit=1e-5):
        checks[name] = dict(max_abs=float(value),limit=limit)
    untouched = registry(model)
    original = observed(model, db["input_ids"])
    save_trace("discovery.baseline", original)
    y,scores,gradients = pilot.local_scores(model, db, 25, 26)
    mb = pilot.margin(y,25,26)
    ranking = []
    for i in (0,1):
        arrays[f"discovery.L{i}.gradient"] = array(gradients[i][:,-1])
        arrays[f"discovery.L{i}.first_order"] = array(scores[i])
        for j, score in enumerate(scores[i].mean(dim=0)):
            ranking.append((float(score), i,j))
    ranking.sort(key=lambda item:(-item[0], item[1:]))
    shortlist=[]
    for _, i,j in ranking[:8]:
        ablated = pilot.ablate(model, db, i,j)
        arrays[f"discovery.ablate.L{i}N{j}.logits"] = array(ablated)
        shortlist.append((float((mb - pilot.margin(ablated,25,26)).mean()),i,j))
    exact, layer,neuron = sorted(shortlist,key=lambda item:(-item[0],item[1:]))[0]
    if exact <= 1e-4:
        raise ValueError("No discovery winner")
    axis = model.transformer.h[layer].mlp.c_proj.weight[neuron].detach()
    activations = original[f"L{layer}.activation"][:,-1,neuron]
    norm = float(activations.abs().median() * axis.norm())
    sign = 1 if activations.mean()>=0 else -1
    chosen = sign * axis / axis.norm() * norm
    controls = random.Random(17025).sample([i for i in range(64) if i!=neuron],6)
    dirs = torch.randn(6,32,generator=torch.Generator().manual_seed(17026))
    dirs = dirs / dirs.norm(dim=1,keepdim=True) * norm
    frozen = dict(layer=layer,neuron=neuron, random_neurons=controls, direction=array(chosen).tolist(),
                  random_directions=array(dirs).tolist(), exact_discovery_mean=exact)
    write(out/"frozen.json", frozen)
    frozen_hash = digest(out/"frozen.json")
    # The existing sentinel must survive normal and exceptional pilot cleanup.
    sentinel_hits = []
    proj = model.transformer.h[layer].mlp.c_proj
    def sentinel(module, args, output):
        sentinel_hits.append(1)
    with proj.register_forward_hook(sentinel):
        with_sentinel = registry(model)
        for group in ("validation_positive","validation_control"):
            batch = pilot.simple_batch(rows[group])
            ids = batch["input_ids"]
            base = observed(model,ids)
            edited = observed(model,ids,site=layer,zero=neuron)
            save_trace(group+".baseline",base)
            save_trace(group+".ablate",edited)
            contribution = base[f"L{layer}.activation"][:,-1,neuron,None]*axis
            arrays[group+".contribution"] = array(contribution)
            minus = observed(model,ids,site=layer,direction=-contribution)
            save_trace(group+".subtract",minus)
            for label,trace,intervention in (("baseline",base,{}),("ablate",edited,dict(site=layer,zero=neuron))):
                singles = [observed(model,row[None],**intervention) for row in ids]
                for key,val in trace.items():
                    error = gap(val, torch.cat([single[key] for single in singles]))
                    save_check(f"{group}.{label}.singleton.{key}",error)
            raw = pilot.baseline(model,batch)
            save_check(group+".captured_vs_unhooked",gap(base["logits"],raw))
            save_check(group+".pilot_ablate_vs_independent_hook",gap(edited["logits"],pilot.ablate(model,batch,layer,neuron)))
            save_check(group+".pilot_subtract_vs_independent_hook",gap(minus["logits"],pilot.inject(model,batch,layer,-contribution)))
            save_check(group+".ablate_vs_subtract",gap(edited["logits"],minus["logits"]),5e-4)
            save_check(group+".zero_direction_vs_baseline",gap(raw,pilot.inject(model,batch,layer,torch.zeros_like(axis))))
            _, _, g = pilot.local_scores(model,batch,25,26)
            arrays[group+".gradient"] = array(g[layer][:,-1])
            for j in controls:
                arrays[f"{group}.random_neuron.N{j}.logits"] = array(pilot.ablate(model,batch,layer,j))
            for i in (0,1):
                for n,direction in enumerate([chosen, *dirs]):
                    arrays[f"{group}.inject.L{i}.direction{n}.logits"] = array(pilot.inject(model,batch,i,direction))
            if registry(model) != with_sentinel:
                raise AssertionError("Registry changed across normal pilot forwards")
            def raise_in_hook(module, args, result):
                raise RuntimeError("intentional hook restoration check")
            try:
                with pilot.hooks([(proj, "post", raise_in_hook)]):
                    pilot.baseline(model,batch)
            except RuntimeError as exc:
                if str(exc) != "intentional hook restoration check":
                    raise
            else:
                raise AssertionError("Expected a hook exception")
            if registry(model) != with_sentinel:
                raise AssertionError("Registry changed after hook exception")
            previous_hits = len(sentinel_hits)
            save_check(group+".baseline_after_exception",gap(raw,pilot.baseline(model,batch)))
            if len(sentinel_hits) != previous_hits + 1:
                raise AssertionError("Pre-existing hook stopped firing")
    if registry(model) != untouched or digest(out/"frozen.json") != frozen_hash:
        raise AssertionError("Hook registry or frozen selection changed")
    np.savez_compressed(out/"arrays.npz", **arrays)
    failures = [k for k,v in checks.items() if v["max_abs"]>v["limit"] or not np.isfinite(v["max_abs"])]
    write(out/"checks.json", dict(torch_version=torch.__version__, source_sha256=digest(PILOT/"neuron_probe.py"),
          weights_sha256=digest(WEIGHTS), torch_probe_sha256=digest(Path(__file__)), selection_sha256=frozen_hash,
          torch_default_dtype=str(torch.get_default_dtype()), checks=checks, failures=failures,
          original_hook_registry_restored=True, external_hook_survived_exception=True))
    if failures:
        raise ValueError(f"Failed comparisons: {failures}")
    print(f"{len(arrays)} tensors; {len(checks)} numeric checks plus normal/exceptional hook restoration")

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("out",type=Path)
    run(parser.parse_args().out)

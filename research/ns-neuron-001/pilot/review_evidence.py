"""Check the fixture's exported artifacts and recompute descriptive summaries.
No model execution or scientific certification; use neuron_probe.py for replay.
"""
import hashlib,json,math,statistics
from pathlib import Path
ROOT=Path(__file__).resolve().parent
A=ROOT/'evidence/fixture-run-001';B=ROOT/'evidence/fixture-replay-001'
def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def check(x,msg):
    if not x:raise ValueError(msg)
def main():
    files=['fixture.safetensors','protocol.json','discovery.json','selection.json','results.json']
    for name in files:check((A/name).read_bytes()==(B/name).read_bytes(),f'replay differs: {name}')
    p,d,s,r=(read(A/n) for n in files[1:]);t=read(A/'training.json')
    check(p['metadata']['weights_sha256']==sha(A/files[0]),'weight binding')
    check(s['protocol_sha256']==sha(A/'protocol.json') and s['discovery_sha256']==sha(A/'discovery.json'),'selection bindings')
    check(r['selection_sha256']==sha(A/'selection.json'),'result binding')
    ranking=d['all_first_order_scores'];check(len(ranking)==128 and len({(i,j) for _,i,j in ranking})==128,'candidate inventory')
    check(ranking==sorted(ranking,key=lambda v:(-v[0],v[1],v[2])),'ranking order')
    short=d['exact_shortlist'];check(len(short)==8 and {(x['layer'],x['neuron']) for x in short}=={(i,j) for _,i,j in ranking[:8]},'shortlist inventory')
    for x in short:check(abs(statistics.mean(x['per_prompt'])-x['exact_mean'])<1e-6,'discovery summary')
    winner=sorted(short,key=lambda x:(-x['exact_mean'],x['layer'],x['neuron']))[0];check((s['layer'],s['neuron'])==(winner['layer'],winner['neuron']),'selection')
    check(s['discovery_exact_mean']==winner['exact_mean'],'selection mean')
    batches=p['batches'];train={tuple(x) for x in t['train_context_pairs']};disc={tuple(x[1:3]) for x in batches['discovery_positive']['input_ids']};val={tuple(x[1:3]) for x in batches['validation_positive']['input_ids']}
    check((len(train),len(disc),len(val))==(232,12,12) and len(train|disc|val)==256,'split independence')
    for k in ['discovery','validation']:
        for a,b in zip(batches[k+'_positive']['input_ids'],batches[k+'_control']['input_ids']):check(a[1:]==b[1:] and a[0]<4<=b[0],'matched contexts')
    for vec in [s['direction']]+s['random_directions']:check(abs(math.sqrt(sum(x*x for x in vec))-s['direction_norm'])<1e-6,'norm matched control')
    summaries={}
    for k,v in r['validation'].items():
        effects=v['exact_ablation_margin_decrease'];mean=statistics.mean(effects);control=statistics.mean(x for row in v['random_neuron_margin_decrease'] for x in row)
        check(len(effects)==12 and len(v['random_neuron_margin_decrease'])==6 and all(len(x)==12 for x in v['random_neuron_margin_decrease']),'validation inventory')
        check(abs(mean-v['mean_exact_ablation'])<1e-6 and abs(control-v['random_neuron_mean'])<1e-6,'validation means')
        check(v['all_exact_positive']==all(x>0 for x in effects),'validation signs')
        m=v['mechanism_checks'];check(all(m[k]<=limit for k,limit in m['limits'].items()) and m['passed'],'mechanism check')
        cross=[]
        for c in v['cross_layer']:
            rr=[statistics.mean(x) for x in zip(*c['random_delta'])];check(all(abs(x-y)<1e-8 for x,y in zip(rr,c['random_mean_delta'])),'cross-layer control means');check(all(abs(x-y-z)<1e-7 for x,y,z in zip(c['chosen_delta'],rr,c['chosen_minus_random_mean'])),'cross-layer differences')
            cross.append({'layer':c['layer'],'mean_selected_minus_random':statistics.mean(c['chosen_minus_random_mean'])})
        summaries[k]={'mean_exact_margin_decrease':mean,'mean_random_neuron_decrease':control,'positive_sign_count':sum(x>0 for x in effects),'cross_layer':cross}
    print(json.dumps({'status':'ARTIFACT_CONSISTENCY_MATCH','scope':'stored evidence arithmetic and binding review; no fresh scientific or runtime execution','replayed_files':len(files),'selected':{'layer':s['layer'],'neuron':s['neuron']},'summaries':summaries},indent=2,sort_keys=True))
if __name__=='__main__':main()

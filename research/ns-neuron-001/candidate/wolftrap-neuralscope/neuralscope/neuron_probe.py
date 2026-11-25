"""NS-NEURON-001: offline GPT-2-style MLP neuron attribution.
Standalone research harness, not an integrated NeuralScope release.
"""
import argparse, hashlib, json, os, random, statistics, sys
from contextlib import contextmanager
from pathlib import Path
import torch
from torch import nn
from torch.nn import functional as F

SEED=17023
PIN_REV='2290a62682d06624634c1f46a6ad5be0f47f38aa'
PINS={
 'README.md':'111f8d09ac565c745d91df88929147159eaa62b2e58e03943a2e03c1a1439ad7',
 'config.json':'4ec5947c1d59fee6212cdf3b0ec1a53eac02092554c5ff0a733488cbd2c64f3a',
 'merges.txt':'1ce1664773c50f3e0cc8842619a93edc4624525b728b188a9e0be33b7726adc5',
 'model.safetensors':'e1ff18884359fe8beb795a5f414feb85a6ce3d929ad019c0d958c039d2b94a1b',
 'tokenizer.json':'8414cab924d8b9b33013f0d221c5862f365ee9be39c5c2bfae8a5a9e970478a6',
 'tokenizer_config.json':'5e04eb606e3a1583530a42e36c2a6b6615c86f34fe77e44d9ddeb43ff940931f',
 'vocab.json':'196139668be63f3b5d6574427317ae82f612a97c5d1cdaf36ed2256dbf636783',
}

def digest(path):
    h=hashlib.sha256()
    with open(path,'rb') as f:
        for chunk in iter(lambda:f.read(1024*1024),b''): h.update(chunk)
    return h.hexdigest()

def write_json(path,value):path.write_text(json.dumps(value,indent=2,sort_keys=True,allow_nan=False)+'\n')

def verify_pins(path,pins=PINS):
    path=Path(path);actual={p.name for p in path.iterdir()}
    if actual!=set(pins):raise ValueError('closed model inventory mismatch')
    for name,want in pins.items():
        if not (path/name).is_file() or digest(path/name)!=want:raise ValueError(f'model input digest mismatch: {name}')

class Conv1D(nn.Module):
    """Fixture uses the GPT-2 [input, output] weight orientation."""
    def __init__(self,ni,no):
        super().__init__();self.weight=nn.Parameter(torch.empty(ni,no));self.bias=nn.Parameter(torch.zeros(no));nn.init.normal_(self.weight,std=.04)
    def forward(self,x):return x@self.weight+self.bias

class MLP(nn.Module):
    def __init__(self,d,h):
        super().__init__();self.c_fc=Conv1D(d,h);self.c_proj=Conv1D(h,d)
    def forward(self,x):return self.c_proj(F.gelu(self.c_fc(x)))

class Block(nn.Module):
    def __init__(self,d,h):
        super().__init__();self.ln1=nn.LayerNorm(d);self.attn=nn.MultiheadAttention(d,4,batch_first=True);self.ln2=nn.LayerNorm(d);self.mlp=MLP(d,h)
    def forward(self,x):
        z=self.ln1(x);mask=torch.ones(x.size(1),x.size(1),dtype=torch.bool,device=x.device).triu(1)
        x=x+self.attn(z,z,z,attn_mask=mask,need_weights=False)[0];return x+self.mlp(self.ln2(x))

class Fixture(nn.Module):
    def __init__(self):
        super().__init__();self.tok=nn.Embedding(27,32);self.pos=nn.Embedding(4,32)
        self.transformer=nn.Module();self.transformer.h=nn.ModuleList([Block(32,64),Block(32,64)])
        self.ln=nn.LayerNorm(32);self.head=nn.Linear(32,27)
    def forward(self,input_ids,**kw):
        x=self.tok(input_ids)+self.pos(torch.arange(input_ids.shape[1],device=input_ids.device))
        for b in self.transformer.h:x=b(x)
        return self.head(self.ln(x))

def projections(model):
    result=[b.mlp.c_proj for b in model.transformer.h]
    if not result:raise ValueError('no MLP projections')
    for p in result:
        if p.weight.ndim!=2 or p.bias.ndim!=1 or p.weight.shape[1]!=p.bias.shape[0]:raise ValueError('not GPT-2 projection orientation')
    return result

@contextmanager
def hooks(items):
    handles=[]
    try:
        for module,kind,fn in items:handles.append(module.register_forward_pre_hook(fn) if kind=='pre' else module.register_forward_hook(fn))
        yield
    finally:
        for h in reversed(handles):h.remove()

def logits(model,batch):
    y=model(**batch,use_cache=False);y=y if isinstance(y,torch.Tensor) else y.logits
    if y.ndim!=3 or not bool(torch.isfinite(y).all()):raise ValueError('invalid logits')
    return y

def margin(y,target,foil):
    if not (0<=target<y.shape[-1] and 0<=foil<y.shape[-1] and target!=foil):raise ValueError('invalid target or foil')
    return y[:,-1,target]-y[:,-1,foil]

def replace_neuron(x,j):
    if x.ndim!=3 or not 0<=j<x.shape[-1]:raise ValueError('invalid neuron index or tensor')
    y=x.clone();y[:,-1,j]=0;return y

def output_delta(y,delta):
    if y.ndim!=3 or delta.ndim not in (1,2) or delta.shape[-1]!=y.shape[-1] or (delta.ndim==2 and delta.shape[0]!=y.shape[0]):raise ValueError('invalid direction shape')
    z=y.clone();z[:,-1,:]+=delta;return z

@torch.no_grad()
def baseline(model,batch):return logits(model,batch)

@torch.no_grad()
def ablate(model,batch,layer,j):
    p=projections(model)[layer]
    with hooks([(p,'pre',lambda m,args:(replace_neuron(args[0],j),))]):return logits(model,batch)

@torch.no_grad()
def inject(model,batch,layer,direction):
    p=projections(model)[layer]
    with hooks([(p,'post',lambda m,args,out:output_delta(out,direction))]):return logits(model,batch)

def capture_raw(model,batch):
    p=projections(model);a={};z={}
    def pre(i):
        def hook(m,args):a[i]=args[0].detach().clone()
        return hook
    def post(i):
        def hook(m,args,out):z[i]=out
        return hook
    with hooks([(v,'pre',pre(i)) for i,v in enumerate(p)]+[(v,'post',post(i)) for i,v in enumerate(p)]):y=logits(model,batch)
    if set(a)!=set(range(len(p))) or set(z)!=set(a):raise ValueError('missing hook observation')
    return y,a,z

@torch.no_grad()
def capture(model,batch):return capture_raw(model,batch)

def local_scores(model,batch,target,foil):
    with torch.enable_grad():
        p=projections(model);y,a,z=capture_raw(model,batch);g=torch.autograd.grad(margin(y,target,foil).sum(),[z[i] for i in range(len(p))])
    scores=[(a[i][:,-1,:]*(g[i][:,-1,:]@v.weight.detach().T)).detach() for i,v in enumerate(p)]
    return y.detach(),scores,[q.detach() for q in g]

def tensor_list(t):return t.detach().cpu().tolist()

def fixture_data():
    pairs=[(a,b) for a in range(8,24) for b in range(8,24)];random.Random(SEED).shuffle(pairs)
    train,disc,val=pairs[:232],pairs[232:244],pairs[244:]
    def held(pairs):return ([[i%4,a,b,24] for i,(a,b) in enumerate(pairs)],[[4+i%4,a,b,24] for i,(a,b) in enumerate(pairs)])
    dp,dn=held(disc);vp,vn=held(val)
    return train,{'discovery_positive':dp,'discovery_control':dn,'validation_positive':vp,'validation_control':vn}

def train_fixture(model,pairs):
    rng=random.Random(SEED+1);opt=torch.optim.AdamW(model.parameters(),lr=.003);model.train();losses=[]
    for step in range(220):
        xs=[];ys=[]
        for _ in range(64):
            t=rng.randrange(8);a,b=rng.choice(pairs);xs.append([t,a,b,24]);ys.append(25 if t<4 else 26)
        opt.zero_grad();y=model(torch.tensor(xs));loss=F.cross_entropy(y[:,-1,:],torch.tensor(ys));loss.backward();opt.step()
        if step%20==0 or step==219:losses.append([step,float(loss.detach())])
    model.eval();return losses

def simple_batch(rows):return {'input_ids':torch.tensor(rows,dtype=torch.long)}

def pretrained_batches(model_dir):
    verify_pins(model_dir);os.environ['HF_HUB_OFFLINE']='1';os.environ['TRANSFORMERS_OFFLINE']='1'
    import transformers
    from transformers import GPT2LMHeadModel,AutoTokenizer
    tok=AutoTokenizer.from_pretrained(str(model_dir),local_files_only=True,trust_remote_code=False)
    model=GPT2LMHeadModel.from_pretrained(str(model_dir),local_files_only=True,use_safetensors=True,attn_implementation='eager').float().eval()
    if model.config.model_type!='gpt2' or sum(p.numel() for p in model.parameters())!=81912576:raise ValueError('unexpected model architecture or parameter count')
    t,f=[tok.encode(' '+x,add_special_tokens=False) for x in ('Paris','Berlin')]
    if len(t)!=1 or len(f)!=1:raise ValueError('target or foil is not one token')
    templates={'discovery':['The capital of {} is','The national capital of {} is','{} has its capital in','The capital city of {} is'],'validation':['What is the capital of {}? It is','The seat of government in {} is in','The capital city located in {} is','If asked to name the capital of {}, I would say']}
    texts={k+'_'+group:[s.format(country) for s in rows] for k,rows in templates.items() for group,country in [('positive','France'),('control','Germany')]};batches={}
    for k,rows in texts.items():
        seq=[tok.encode(s,add_special_tokens=False) for s in rows];n=max(map(len,seq));pad=tok.eos_token_id
        if pad is None or any(not s for s in seq):raise ValueError('invalid tokenization')
        ids=torch.tensor([[pad]*(n-len(s))+s for s in seq]);mask=torch.tensor([[0]*(n-len(s))+[1]*len(s) for s in seq]);pos=(mask.cumsum(1)-1).clamp(min=0)
        batches[k]={'input_ids':ids,'attention_mask':mask,'position_ids':pos}
    return model,batches,t[0],f[0],{'model':'distilbert/distilgpt2','revision':PIN_REV,'model_file_sha256':PINS,'transformers':transformers.__version__,'texts':texts}

def audit_probe(model,batch,target,foil,layer,j):
    p=projections(model)[layer];w=p.weight.detach()[j];original=baseline(model,batch);observed,a,z=capture(model,batch)
    activation=a[layer][:,-1,j];delta=-activation[:,None]*w[None,:];zero=ablate(model,batch,layer,j);subtract=inject(model,batch,layer,delta);no_op=inject(model,batch,layer,torch.zeros_like(w))
    reconstructed=F.linear(a[layer],p.weight.detach().T,p.bias.detach());err=lambda u,v:float((u-v).abs().max());direction=w/w.norm().clamp(min=1e-12)
    _,_,g=local_scores(model,batch,target,foil);derivative=g[layer][:,-1,:]@direction;eps=.002
    plus=margin(inject(model,batch,layer,eps*direction),target,foil);minus=margin(inject(model,batch,layer,-eps*direction),target,foil);fd=(plus-minus)/(2*eps)
    values={'hooked_baseline_max_abs':err(original,observed),'zero_direction_max_abs':err(original,no_op),'projection_reconstruction_max_abs':err(z[layer],reconstructed),'ablation_vs_subtraction_max_abs':err(zero,subtract),'gradient_vs_central_difference_max_abs':err(derivative,fd),'gradient':tensor_list(derivative),'central_difference':tensor_list(fd),'finite_difference_epsilon':eps,'restored_baseline_max_abs':err(original,baseline(model,batch))}
    limits={'hooked_baseline_max_abs':1e-5,'zero_direction_max_abs':1e-5,'projection_reconstruction_max_abs':1e-4,'ablation_vs_subtraction_max_abs':5e-4,'gradient_vs_central_difference_max_abs':.04,'restored_baseline_max_abs':1e-5}
    values['limits']=limits;values['passed']=all(values[k]<=v for k,v in limits.items());return values

def run_study(model,batches,target,foil,out,metadata):
    model.eval();p=projections(model);rng=random.Random(SEED+2)
    protocol={'schema':'NS-NEURON-001/protocol-v1','seed':SEED,'selection':'positive discovery mean first-order margin decrease; top 8 checked by exact ablation; largest positive exact mean wins; tie layer/neuron ascending','selection_floor':1e-4,'validation':'held-out positive and matched negative prompts; fixed target-foil margin; same-layer random neuron controls and equal-norm random directions','exact_ablation':'zero post-activation at final position before MLP output projection','cross_layer_injection':'add signed, normalized selected projection row to final-position MLP output at each layer; scale fixed by median absolute discovery activation times row norm','random_neuron_controls':6,'random_direction_controls':6,'derivative':'local gradient dot projection row times activation, not a general vocabulary J-lens','target':target,'foil':foil,'model_parameters':sum(v.numel() for v in model.parameters()),'batches':{k:{n:t.tolist() for n,t in b.items()} for k,b in batches.items()},'metadata':metadata,'torch':torch.__version__,'execution':'CPU float32 eval, no API'}
    write_json(out/'protocol.json',protocol)
    db=batches['discovery_positive'];y,scores,g=local_scores(model,db,target,foil);mb=margin(y,target,foil)
    ranked=sorted([(float(v[:,j].mean()),i,j) for i,v in enumerate(scores) for j in range(v.shape[1])],key=lambda v:(-v[0],v[1],v[2]));exact=[]
    for pred,l,j in ranked[:8]:
        delta=mb-margin(ablate(model,db,l,j),target,foil);exact.append({'layer':l,'neuron':j,'predicted_mean':pred,'exact_mean':float(delta.mean()),'per_prompt':tensor_list(delta)})
    exact.sort(key=lambda v:(-v['exact_mean'],v['layer'],v['neuron']));write_json(out/'discovery.json',{'all_first_order_scores':ranked,'exact_shortlist':exact,'baseline_margin':tensor_list(mb)})
    winner=exact[0]
    if winner['exact_mean']<=1e-4:
        write_json(out/'selection.json',{'status':'NO_SELECTION','discovery':winner});return {'status':'NO_SELECTION','validation_executed':False}
    l,j=winner['layer'],winner['neuron'];_,a,_=capture(model,db);w=p[l].weight.detach()[j];act=a[l][:,-1,j];sign=1 if float(act.mean())>=0 else -1;amp=float(act.abs().median()*w.norm())
    if amp<=1e-8 or not torch.isfinite(w).all():raise ValueError('degenerate selected contribution')
    controls=rng.sample([i for i in range(p[l].weight.shape[0]) if i!=j],6);gen=torch.Generator().manual_seed(SEED+3);random_dirs=torch.randn(6,w.numel(),generator=gen);random_dirs=random_dirs/random_dirs.norm(dim=1,keepdim=True)*amp;direction=sign*w/w.norm()*amp
    selection={'status':'SELECTED','layer':l,'neuron':j,'discovery_exact_mean':winner['exact_mean'],'discovery_predicted_mean':winner['predicted_mean'],'sign':sign,'direction_norm':amp,'direction':tensor_list(direction),'random_neurons_same_layer':controls,'random_directions':tensor_list(random_dirs),'protocol_sha256':digest(out/'protocol.json'),'discovery_sha256':digest(out/'discovery.json')};write_json(out/'selection.json',selection)
    result={'status':'MEASURED','selection_sha256':digest(out/'selection.json'),'validation_executed':True,'selection':{k:selection[k] for k in ('layer','neuron','sign','direction_norm')},'validation':{}}
    for key in ('validation_positive','validation_control'):
        b=batches[key];base=baseline(model,b);bm=margin(base,target,foil);_,preds,_=local_scores(model,b,target,foil);delta=bm-margin(ablate(model,b,l,j),target,foil);ctrl=[tensor_list(bm-margin(ablate(model,b,l,n),target,foil)) for n in controls];cross=[]
        for layer in range(len(p)):
            chosen=margin(inject(model,b,layer,direction),target,foil)-bm;rnd=[tensor_list(margin(inject(model,b,layer,d),target,foil)-bm) for d in random_dirs];random_mean=[statistics.mean(x) for x in zip(*rnd)]
            cross.append({'layer':layer,'chosen_delta':tensor_list(chosen),'random_delta':rnd,'random_mean_delta':random_mean,'chosen_minus_random_mean':tensor_list(chosen-torch.tensor(random_mean))})
        result['validation'][key]={'baseline_margin':tensor_list(bm),'baseline_expected_token_top1_count':int((base[:,-1,:].argmax(-1)==(target if key.endswith('positive') else foil)).sum()),'exact_ablation_margin_decrease':tensor_list(delta),'first_order_prediction':tensor_list(preds[l][:,j]),'random_neuron_margin_decrease':ctrl,'random_neuron_mean':statistics.mean([v for row in ctrl for v in row]),'mean_exact_ablation':float(delta.mean()),'all_exact_positive':bool((delta>0).all()),'cross_layer':cross,'mechanism_checks':audit_probe(model,b,target,foil,l,j)}
    result['mechanism_checks_passed']=all(v['mechanism_checks']['passed'] for v in result['validation'].values());result['status']='MEASURED' if result['mechanism_checks_passed'] else 'BLOCKED_MECHANISM_CHECK';return result

def configure():
    torch.set_num_threads(1);torch.manual_seed(SEED);random.seed(SEED);torch.use_deterministic_algorithms(True)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--mode',choices=['fixture','pretrained'],default='fixture');ap.add_argument('--out',type=Path,required=True);ap.add_argument('--model-dir',type=Path);ap.add_argument('--replay-weights',type=Path);args=ap.parse_args();configure();args.out.mkdir(parents=True,exist_ok=False)
    if args.mode=='fixture':
        from safetensors.torch import save_file,load_file
        model=Fixture();train,rows=fixture_data()
        if args.replay_weights:model.load_state_dict(load_file(str(args.replay_weights)),strict=True);losses=None
        else:losses=train_fixture(model,train)
        model.eval();save_file({k:v.detach().contiguous() for k,v in model.state_dict().items()},str(args.out/'fixture.safetensors'))
        if losses is not None:write_json(args.out/'training.json',{'losses':losses,'steps':220,'train_context_pairs':train})
        batches={k:simple_batch(r) for k,r in rows.items()};target,foil=25,26;meta={'model':'locally trained synthetic next-token transformer','not_pretrained':True,'weights_sha256':digest(args.out/'fixture.safetensors'),'training_context_pairs':len(train),'discovery_context_pairs':12,'validation_context_pairs':12,'split':'disjoint ordered context pairs; tokens overlap; matched positive/control rows share each context','train_steps':220,'model_architecture':'2 causal attention blocks, 32 residual dims, 64 neurons per MLP, 27-token vocab'}
    else:
        if not args.model_dir or args.replay_weights:ap.error('pretrained requires --model-dir only')
        model,batches,target,foil,meta=pretrained_batches(args.model_dir)
    r=run_study(model,batches,target,foil,args.out,meta);write_json(args.out/'results.json',r);print(json.dumps({'status':r['status'],'mode':args.mode,'selection':r.get('selection'),'mechanism_checks_passed':r.get('mechanism_checks_passed')},indent=2))
    if r['status']!='MEASURED':sys.exit(2)

if __name__=='__main__':main()

import hashlib,json,tempfile,unittest
from pathlib import Path
import torch
from torch.nn import functional as F
import neuron_probe as n

class TestNeuronProbe(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        n.configure();cls.m=n.Fixture().eval();cls.b=n.simple_batch([[0,8,9,24],[4,10,11,24]])
    def test_split_disjoint(self):
        tr,rows=n.fixture_data();p=set(tr);d={tuple(x[1:3]) for x in rows['discovery_positive']};v={tuple(x[1:3]) for x in rows['validation_positive']}
        self.assertEqual((len(p),len(d),len(v)),(232,12,12));self.assertFalse(p&d or p&v or d&v);self.assertEqual(len(p|d|v),256)
    def test_matched_contexts(self):
        _,r=n.fixture_data()
        for stage in ['discovery','validation']:
            for a,b in zip(r[stage+'_positive'],r[stage+'_control']):self.assertEqual(a[1:],b[1:]);self.assertLess(a[0],4);self.assertGreaterEqual(b[0],4)
    def test_projection_orientation(self):
        for p in n.projections(self.m):self.assertEqual(tuple(p.weight.shape),(64,32))
    def test_zero_only_one_index_and_position(self):
        x=torch.ones(2,4,64);z=n.replace_neuron(x,5);self.assertEqual(int((z==0).sum()),2);self.assertTrue((z[:,-1,5]==0).all());self.assertTrue((x==1).all())
    def test_invalid_neuron(self):
        for j in [-1,64]:
            with self.assertRaises(ValueError):n.replace_neuron(torch.ones(2,4,64),j)
    def test_invalid_direction(self):
        for d in [torch.zeros(33),torch.zeros(3,32),torch.zeros(2,1,32)]:
            with self.assertRaises(ValueError):n.output_delta(torch.zeros(2,4,32),d)
    def test_delta_batch_and_only_final_position(self):
        x=torch.zeros(2,4,32);d=torch.stack([torch.ones(32),-torch.ones(32)]);z=n.output_delta(x,d);self.assertTrue(torch.equal(z[:,-1,:],d));self.assertEqual(int(z[:,:-1,:].count_nonzero()),0);self.assertEqual(int(x.count_nonzero()),0)
    def test_margin_rejects_invalid_targets(self):
        x=torch.zeros(2,4,27)
        for a,b in [(1,1),(-1,1),(1,27)]:
            with self.assertRaises(ValueError):n.margin(x,a,b)
    def test_noop(self):self.assertTrue(torch.equal(n.baseline(self.m,self.b),n.inject(self.m,self.b,0,torch.zeros(32))))
    def test_projection_reconstruct(self):
        _,a,z=n.capture(self.m,self.b)
        for i,p in enumerate(n.projections(self.m)):torch.testing.assert_close(z[i],F.linear(a[i],p.weight.T,p.bias),atol=1e-6,rtol=1e-6)
    def test_ablate_matches_subtract(self):
        _,a,_=n.capture(self.m,self.b)
        for i,p in enumerate(n.projections(self.m)):
            d=-a[i][:,-1,3,None]*p.weight.detach()[3];torch.testing.assert_close(n.ablate(self.m,self.b,i,3),n.inject(self.m,self.b,i,d),rtol=1e-5,atol=1e-5)
    def test_hooks_removed_on_failure(self):
        p=n.projections(self.m)[0];base=n.baseline(self.m,self.b)
        def boom(*args):raise RuntimeError('intentional')
        with self.assertRaises(RuntimeError):
            with n.hooks([(p,'post',boom)]):n.baseline(self.m,self.b)
        self.assertEqual(len(p._forward_hooks),0);self.assertTrue(torch.equal(base,n.baseline(self.m,self.b)))
    def test_local_gradient_matches_finite_difference(self):self.assertTrue(n.audit_probe(self.m,self.b,25,26,0,5)['passed'])
    def test_pins_reject_modified_missing_extra(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);(p/'a').write_bytes(b'good');pins={'a':hashlib.sha256(b'good').hexdigest()};n.verify_pins(p,pins)
            (p/'a').write_bytes(b'bad')
            with self.assertRaises(ValueError):n.verify_pins(p,pins)
            (p/'a').unlink()
            with self.assertRaises(ValueError):n.verify_pins(p,pins)
            (p/'a').write_bytes(b'good');(p/'extra').write_bytes(b'x')
            with self.assertRaises(ValueError):n.verify_pins(p,pins)
    def test_no_model_mutation(self):
        before={k:v.clone() for k,v in self.m.state_dict().items()};n.ablate(self.m,self.b,1,12);n.inject(self.m,self.b,0,torch.ones(32));self.assertTrue(all(torch.equal(v,self.m.state_dict()[k]) for k,v in before.items()))

if __name__=='__main__':unittest.main(verbosity=2)

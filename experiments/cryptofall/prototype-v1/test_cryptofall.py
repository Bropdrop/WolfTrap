import hashlib
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
import cryptofall as c

class Lab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='cryptofall-test-')
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.root = Path(cls.tmp.name)
        cls.keys = []
        cls.private = {}
        for role in c.ROLES:
            for alg in c.ALGS:
                key = cls.root / (role+'-'+alg+'.pem')
                pub = key.with_suffix('.der')
                subprocess.run([c.OPENSSL,'genpkey','-algorithm',alg,'-out',str(key)],env=c.ENV,check=True,capture_output=True)
                subprocess.run([c.OPENSSL,'pkey','-in',str(key),'-pubout','-outform','DER','-out',str(pub)],env=c.ENV,check=True,capture_output=True)
                k=c.Key(role,alg,pub.read_bytes())
                cls.keys.append(k)
                cls.private[k.kid]=key
        cls.p = c.Policy('disposable-lab',7,'hybrid',tuple(cls.keys))
        cls.effect = hashlib.sha256(b'disposable-counter:increment:1').hexdigest()
        cls.claim = cls.make_claim(cls.p)
        cls.sigs = cls.sign(cls.p, cls.claim)
    @classmethod
    def make_claim(cls,p,**changes):
        return dict(realm=p.realm,epoch=p.epoch,policy_digest=c.policy_digest(p),request_id='req-001',effect_digest=cls.effect,issued_at=100,expires_at=130)|changes
    @classmethod
    def sign(cls,p,claim):
        signatures=[]
        for k in p.keys:
            msg=cls.root/'msg'; sig=cls.root/'sig'
            msg.write_bytes(c.message(claim,k.role,k.alg,k.kid))
            subprocess.run([c.OPENSSL,'pkeyutl','-sign','-rawin','-inkey',str(cls.private[k.kid]),'-in',str(msg),'-out',str(sig)],env=c.ENV,check=True,capture_output=True)
            signatures.append(c.Signature(k.role,k.alg,k.kid,sig.read_bytes()))
        return tuple(signatures)
    def result(self,p=None,claim=None,sigs=None,**changes):
        return c.evaluate(self.p if p is None else p,self.claim if claim is None else claim,self.sigs if sigs is None else sigs,**(dict(expected_request='req-001',expected_effect=self.effect,now=101,epoch_floor=7)|changes))
    def deny(self,*args,**kw):
        self.assertEqual(self.result(*args,**kw).status,'DENY')
    def test_01_hybrid_real_signatures(self): self.assertEqual(self.result().status,'EVIDENCE_ACCEPTED')
    def test_02_missing_pq(self): self.deny(sigs=tuple(s for s in self.sigs if s.alg=='Ed25519'))
    def test_03_missing_classical(self): self.deny(sigs=tuple(s for s in self.sigs if s.alg=='ML-DSA-65'))
    def test_04_missing_witness(self): self.deny(sigs=tuple(s for s in self.sigs if s.role=='owner'))
    def test_05_duplicate_slot(self): self.deny(sigs=self.sigs[:-1]+(self.sigs[0],))
    def test_06_corrupt_signature(self): self.deny(sigs=(replace(self.sigs[0],value=b'\0'*64),)+self.sigs[1:])
    def test_07_wrong_effect(self): self.deny(expected_effect='0'*64)
    def test_08_wrong_request(self): self.deny(expected_request='req-002')
    def test_09_expired(self): self.deny(now=130)
    def test_10_future(self): self.deny(now=99)
    def test_11_epoch_rollback(self): self.deny(epoch_floor=8)
    def test_12_future_epoch(self): self.deny(epoch_floor=6)
    def test_13_relabel_algorithm(self): self.deny(sigs=(replace(self.sigs[0],alg='ML-DSA-65'),)+self.sigs[1:])
    def test_14_unknown_algorithm(self): self.deny(sigs=(replace(self.sigs[0],alg='RSA'),)+self.sigs[1:])
    def test_15_policy_revocation(self):
        p=replace(self.p,revoked_algorithms=frozenset({'Ed25519'})); q=self.make_claim(p)
        self.deny(p,q,self.sign(p,q))
    def test_16_key_revocation(self):
        p=replace(self.p,revoked_keys=frozenset({self.keys[0].kid})); q=self.make_claim(p)
        self.deny(p,q,self.sign(p,q))
    def test_17_new_pq_epoch(self):
        p=replace(self.p,epoch=8,mode='pq-only',keys=tuple(k for k in self.keys if k.alg=='ML-DSA-65'),revoked_algorithms=frozenset({'Ed25519'})); q=self.make_claim(p)
        self.assertEqual(self.result(p,q,self.sign(p,q),epoch_floor=8).status,'EVIDENCE_ACCEPTED')
        self.deny(p,self.claim,self.sigs,epoch_floor=8)
    def test_18_policy_digest_tamper(self): self.deny(claim=self.claim|{'policy_digest':'0'*64})
    def test_19_reused_key(self): self.deny(p=replace(self.p,keys=self.p.keys[:-1]+(replace(self.keys[1],role='witness'),)))
    def test_20_long_lifetime_even_signed(self):
        q=self.make_claim(self.p,expires_at=131); self.deny(claim=q,sigs=self.sign(self.p,q))
    def test_21_boolean_epoch(self): self.deny(claim=self.claim|{'epoch':True})
    def test_22_extra_claim_field(self): self.deny(claim=self.claim|{'authority':'allow'})
    def test_23_backend_unavailable(self):
        with patch.object(c,'OPENSSL','/nonexistent/openssl'): self.deny()
    def test_24_backend_timeout(self):
        with patch.object(c.subprocess,'run',side_effect=subprocess.TimeoutExpired('openssl',5)): self.deny()
    def test_25_cross_role_signature(self): self.deny(sigs=(replace(self.sigs[0],value=self.sigs[2].value),)+self.sigs[1:])
    def test_26_claim_tampering(self): self.deny(claim=self.claim|{'expires_at':129})
    def test_27_malformed_key_algorithm(self): self.deny(p=replace(self.p,keys=(replace(self.keys[0],public=self.keys[1].public),)+self.p.keys[1:]))
    def test_28_stale_signed_policy(self): self.deny(p=replace(self.p,revoked_keys=frozenset({'a'*64})))
    def test_29_unknown_signer(self): self.deny(sigs=(replace(self.sigs[0],kid='a'*64),)+self.sigs[1:])
    def test_30_replay_is_evidence_only(self):
        a=self.result(); b=self.result(); self.assertEqual(a,b); self.assertIn('no execution authority',a.reason)
    def test_31_bad_signature_type(self): self.deny(sigs=(replace(self.sigs[0],value='bad'),)+self.sigs[1:])
    def test_32_different_realm_even_signed(self):
        q=self.make_claim(self.p,realm='another-lab'); self.deny(claim=q,sigs=self.sign(self.p,q))
    def test_33_same_epoch_policy_change_requires_new_claim(self):
        p=replace(self.p,mode='pq-only',keys=tuple(k for k in self.keys if k.alg=='ML-DSA-65')); self.deny(p=p)

if __name__=='__main__': unittest.main(verbosity=2)

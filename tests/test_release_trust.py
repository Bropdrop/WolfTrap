"""Hostile pre-install boundaries, without importing the candidate application."""
import concurrent.futures
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "release/verifier"), str(ROOT / "release/qualification")]
import release_client as client
import release_core as core
from release_cases import Corpus, EXPECTED
from release_io import Verdict, encode, file_bytes, pack, parse, sha, unzip
del sys.path[:2]


class ReleaseTrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.lab = Corpus(Path(cls.temp.name))
        cls.raw = pack(cls.lab.new)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def cli_args(self, root):
        trust = root / "trust"
        trust.mkdir()
        for n, v in self.lab.trust.items():
            (trust/n).write_bytes(v)
        bundle = root / "input.zip"
        bundle.write_bytes(self.raw)
        return ["--evaluation","--platform","ubuntu-24.04-x86_64-cpython-3.12.14","--bundle",str(bundle),
                "--trust-dir",str(trust),"--policy-sha256",sha(self.lab.trust["policy.json"]),"--minimum-sequence","2","--sequence","2"]

    def cli(self, name, args):
        r = subprocess.run([sys.executable, "-I", ROOT/"release/verifier", name, *args], capture_output=True, text=True, timeout=20)
        return r.returncode, json.loads(r.stdout)

    def test_independent_expected_outcomes_and_deliberate_defects(self):
        result = self.lab.score()
        self.assertEqual({r["id"]:r["observed"] for r in result["cases"]}, EXPECTED)
        self.assertEqual(len(result["defective_verifiers"]), 9)
        self.assertTrue(all(d["observed"] != d["expected"] for d in result["defective_verifiers"].values()))

    def test_current_and_historical_have_distinct_install_purposes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            args = self.cli_args(root)
            self.assertEqual(self.cli("verify",args)[0],0)
            self.assertEqual(self.cli("install",[*args,"--purpose","historical","--venv",str(root/"v")])[1]["reason"],"historical-audit-only")
            self.assertFalse((root/"v").exists())

    def test_missing_or_revoked_evidence_cannot_create_an_environment(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            args = self.cli_args(root)
            (root/"trust/signer.pem").unlink()
            self.assertEqual(self.cli("install",[*args,"--venv",str(root/"v")])[0],2)
            self.assertFalse((root/"v").exists())

    def test_production_mode_and_unqualified_platform_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            args=self.cli_args(root)
            self.assertEqual(self.cli("verify",args[1:])[1]["reason"],"production-signing-and-review-unconfigured")
            args[2]="windows-x64"
            self.assertEqual(self.cli("verify",args)[0],2)

    def test_self_selected_trust_directory_and_hardlink_substitution(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            args=self.cli_args(root)
            args[args.index("--trust-dir")+1]=str(root)
            self.assertEqual(self.cli("verify",args)[1]["reason"],"trust-must-be-independent")
            os.link(root/"input.zip",root/"link")
            with self.assertRaises(Verdict):
                file_bytes(root/"input.zip",len(self.raw))

    def test_symlink_parent_and_special_files_never_open_for_io(self):
        with tempfile.TemporaryDirectory() as d:
            r=Path(d);(r/"real").mkdir();(r/"real/file").write_bytes(b"data");(r/"alias").symlink_to(r/"real")
            with self.assertRaises(OSError):
                file_bytes(r/"alias/file",20)
            (r/"file").symlink_to(r/"real/file")
            os.mkfifo(r/"fifo")
            for p in (r/"fifo",r/"file",r/"real/../real/file"):
                with self.assertRaises(Verdict):
                    file_bytes(p,20)

    def test_input_replaced_after_open_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/"release"
            p.write_bytes(b"original")
            real=os.stat
            def replace(name,*args,**kwargs):
                if name == "release" and kwargs.get("dir_fd") is not None:
                    q=p.with_name("next")
                    q.write_bytes(b"replaced")
                    os.replace(q,p)
                return real(name,*args,**kwargs)
            with patch("release_io.os.stat",side_effect=replace), self.assertRaises(Verdict):
                file_bytes(p,64)

    def test_zip_and_json_budgets_precede_interpretation(self):
        raw=pack({"a":b"z"})
        for data in (raw[:-2],raw+b"suffix",raw[:-22]+struct.pack("<4s4H2IH",b"PK\x05\x06",0,0,1,1,999999,0,0)):
            with self.assertRaises(Verdict):
                unzip(data)
        for raw in (b"["*3000+b"]"*3000,b'{"a":1,"a":2}',b"{}"*150000,encode([0]*6100)):
            with self.assertRaises(Verdict):
                parse(raw)

    def test_one_atomic_custodian_wins_and_never_replaces(self):
        with tempfile.TemporaryDirectory() as d:
            vault=Path(d)
            def writer(value):
                try:
                    client.custody(vault,2,value)
                    return True
                except Verdict:
                    return False
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as workers:
                result=list(workers.map(writer,[self.raw]*4))
            self.assertEqual(sum(result),1)
            file,=vault.iterdir()
            self.assertEqual(file.read_bytes(),self.raw)
            self.assertFalse(writer(b"changed"))
            self.assertEqual(file.read_bytes(),self.raw)

    def test_interrupted_custody_is_recoverable_without_partial_final(self):
        with tempfile.TemporaryDirectory() as d:
            vault=Path(d)
            with patch.object(client.os,"link",side_effect=OSError("fixture")), self.assertRaises(OSError):
                client.custody(vault,2,self.raw)
            self.assertEqual(list(vault.iterdir()),[])
            name=client.custody(vault,2,self.raw)
            self.assertEqual((vault/name).read_bytes(),self.raw)

    def test_interrupted_signing_cannot_reach_custody(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); args=self.cli_args(root); (root/"vault").mkdir(mode=0o700)
            partial=self.lab.new.copy();del partial["provenance.p7s"];(root/"input.zip").write_bytes(pack(partial))
            self.assertEqual(self.cli("retain",[*args,"--vault",str(root/"vault")])[0],2)
            self.assertEqual(list((root/"vault").iterdir()),[])

    def test_historical_audit_checks_the_archived_signature_pin(self):
        a=list(self.lab.variation("historical-audit"));p=parse(a[1]["policy.json"])
        p["releases"][0]["archived_signature_sha256"]="0"*64
        a[1]["policy.json"]=encode(p);a[2]=sha(a[1]["policy.json"])
        with self.assertRaisesRegex(Verdict,"different-archived-signature"):
            core.verify(*a)

    def test_workflow_event_permissions_and_gates(self):
        import yaml
        def workflow(name):
            return yaml.load((ROOT/".github/workflows"/name).read_text(),Loader=yaml.BaseLoader)
        prod=workflow("protected-release.yml")
        qual=workflow("release-trust-qualification.yml")
        self.assertEqual(set(prod["on"]),{"workflow_dispatch"})
        self.assertEqual(set(qual["on"]),{"pull_request"})
        self.assertEqual(qual["on"]["pull_request"]["branches"],["feat/offline-product-foundation-v1"])
        self.assertEqual(prod["permissions"],{"contents":"read"})
        self.assertEqual(qual["permissions"],{"contents":"read"})
        for name,parent in (("build","select"),("qualify","build"),("approval","qualify"),("sign","approval"),("publish","sign")):
            self.assertEqual(prod["jobs"][name]["needs"],parent)
        for name in ("approval","sign","publish"):
            self.assertEqual(prod["jobs"][name]["permissions"],{})
        for name in ("approval","publish"):
            self.assertIn("environment",prod["jobs"][name])
        for name in ("sign","publish"):
            self.assertTrue(prod["jobs"][name]["steps"][0]["run"].strip().endswith("exit 1"))
        for config in (prod,qual):
            for job in config["jobs"].values():
                for step in job["steps"]:
                    if "uses" in step:
                        self.assertRegex(step["uses"],r"@[0-9a-f]{40}$")
                    if step.get("uses","").startswith("actions/checkout@"):
                        self.assertEqual(step["with"]["persist-credentials"],"false")
                        self.assertIn("ref",step["with"])
        select=prod["jobs"]["select"]["steps"][0]["run"]
        def trigger(event,ref,protected,approved,exact):
            return subprocess.run(["bash","-c",select],env=dict(EVENT=event,REF=ref,PROTECTED=protected,APPROVED=approved,EXACT=exact)).returncode
        self.assertEqual(trigger("workflow_dispatch","refs/heads/main","true","a"*40,"a"*40),0)
        for vals in (("pull_request","refs/heads/main","true","a"*40,"a"*40),
                     ("workflow_dispatch","refs/heads/other","true","a"*40,"a"*40),
                     ("workflow_dispatch","refs/heads/main","false","a"*40,"a"*40),
                     ("workflow_dispatch","refs/heads/main","true","b"*40,"a"*40)):
            self.assertNotEqual(trigger(*vals),0)

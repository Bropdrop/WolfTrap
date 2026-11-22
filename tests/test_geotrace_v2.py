"""Independent expectations for the R01 CLI; all resources are private synthetic fixtures."""
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from wolftrap.cli import main

EXAMPLES = Path(__file__).resolve().parents[1] / "qualification/geotrace/r01/examples"


class GeoTraceV2Tests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.root = self.base / "selected"
        self.root.mkdir()
        self.file = self.root / "capture.json"
        self.pol = self.base / "approved.json"
        self.out = self.base / "bundle"
        self.src = json.loads((EXAMPLES / "capture/capture.json").read_bytes())
        self.policy = json.loads((EXAMPLES / "policy/policy.json").read_bytes())
        self.save()

    def save(self):
        self.file.write_text(json.dumps(self.src))
        self.pol.write_text(json.dumps(self.policy))
        self.pin = hashlib.sha256(self.pol.read_bytes()).hexdigest()

    def cli(self, *, verify=False, **extra):
        options = {"root":self.root, "file":"capture.json", "policy":self.pol,
                   "policy-sha256":self.pin, "as-of":"2026-11-22",
                   "evidence-dir" if verify else "output-dir":self.out, **extra}
        args = ["verify-geotrace" if verify else "scan-geotrace"]
        for k, v in options.items():
            args.extend(["--" + k, str(v)])
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main(args)

    def report(self):
        return json.loads((self.out / "geotrace.json").read_bytes())

    def test_distinct_geography_and_no_authority(self):
        self.assertEqual(self.cli(), 0)
        self.assertEqual(self.cli(verify=True), 0)
        rep = self.report()
        row = rep["events"][0]
        self.assertEqual({k:v["countries"] for k,v in row["geography"].items()},
                         dict(provider_origin=["FR"], network_egress=["CA"], destination_hop=["US"],
                              execution_region=["DE"], processing_jurisdiction=["BR"]))
        self.assertEqual([(h["hop"],h["countries"]) for h in row["intermediaries"]], [(1,["JP"]),(2,["SE"])])
        self.assertEqual(row["destination_role"], "gateway_hop")
        self.assertEqual(rep["action_authorization"], "NOT_EVALUATED")
        self.assertEqual(rep["operator_identity"], "UNVERIFIED")
        self.assertEqual(rep["protected_effects_committed"], 0)
        all_bytes = b"".join(f.read_bytes() for f in self.out.iterdir())
        for value in ["192.0.2.10", "api.fr.test", hashlib.sha256(b"192.0.2.10").hexdigest()]:
            self.assertNotIn(value.encode(), all_bytes)

    def test_missing_context_cannot_borrow_network_location(self):
        self.src["observations"] = []
        self.save()
        self.assertEqual(self.cli(), 2)
        self.assertEqual(self.cli(verify=True), 0)
        g = self.report()["events"][0]["geography"]
        for name in ("execution_region","processing_jurisdiction"):
            self.assertEqual((g[name]["state"],g[name]["countries"]),("UNKNOWN",[]))

    def test_context_conflict(self):
        self.src["observations"].append(dict(self.src["observations"][0], source="runtime-b", country="JP"))
        self.save()
        self.assertEqual(self.cli(), 2)
        self.assertEqual(self.report()["events"][0]["geography"]["execution_region"]["state"],"CONFLICTING")

    def test_expired_or_stale(self):
        self.src["observations"][0]["valid_until"] = "2026-11-21"
        self.src["observations"][1]["observed_on"] = "2020-01-01"
        self.save()
        self.assertEqual(self.cli(), 2)
        g = self.report()["events"][0]["geography"]
        self.assertEqual(g["execution_region"]["countries"], [])
        self.assertEqual(g["processing_jurisdiction"]["sources"], [{"observation_index":1,"current":False}])

    def test_hop_gap_inconclusive(self):
        self.src["observations"].pop(2)
        self.save()
        self.assertEqual(self.cli(), 2)
        self.assertEqual(self.report()["events"][0]["policy_results"]["intermediary"], "INCONCLUSIVE")

    def test_changed_destination_invalidates_context(self):
        self.src["capture"]["events"][0]["destination_ip"] = "203.0.113.11"
        self.save()
        self.assertEqual(self.cli(),2)
        self.assertFalse(self.out.exists())

    def test_capture_policy_cannot_widen_owner_policy(self):
        self.policy["allowed"]["network_egress"] = ["JP"]
        self.src["capture"]["policy"] = {"allowed_source_countries":["CA"], "review_unknowns":False}
        self.save()
        self.assertEqual(self.cli(),1)
        self.assertEqual(self.report()["events"][0]["policy_results"]["network_egress"],"REVIEW_REQUIRED")
        self.assertEqual(self.cli(verify=True),0)

    def test_policy_provenance_and_freshness(self):
        self.assertEqual(self.cli(**{"policy-sha256":"0"*64}),2)
        self.assertEqual(self.cli(**{"as-of":"2026-11-24"}),2)
        self.policy["task"] = "other-task"
        self.save()
        self.assertEqual(self.cli(),2)
        self.assertFalse(self.out.exists())

    def test_legacy_capture_advisory(self):
        self.src = self.src["capture"]
        self.policy.update(task="v1-import",workload="unknown")
        self.save()
        self.assertEqual(self.cli(),2)
        row = self.report()["events"][0]
        self.assertEqual(row["geography"]["provider_origin"]["countries"],["FR"])
        self.assertEqual(row["geography"]["processing_jurisdiction"]["state"],"UNKNOWN")

    def test_output_in_source_refused(self):
        self.out = self.root / "evidence"
        self.assertEqual(self.cli(),2)
        self.assertFalse(self.out.exists())

    def test_symlinked_output_parent_refused(self):
        link = self.base / "link"
        link.symlink_to(self.base,target_is_directory=True)
        self.out = link / "redirected"
        self.assertEqual(self.cli(),2)
        self.assertFalse((self.base/"redirected").exists())

    def test_source_selection(self):
        (self.root/"link.json").symlink_to(self.pol)
        (self.root/"linkdir").symlink_to(self.base,target_is_directory=True)
        os.link(self.pol,self.root/"alias.json")
        os.mkfifo(self.root/"fifo.json")
        for f in ("../approved.json", str(self.pol), "link.json", "linkdir/approved.json", "alias.json",
                  "fifo.json","", ".git/config","*.json"):
            with self.subTest(f=f):
                self.assertEqual(self.cli(file=f),2)
                self.assertFalse(self.out.exists())

    def test_separate_policy_and_directory_identity(self):
        (self.root/"policy.json").write_bytes(self.pol.read_bytes())
        self.assertEqual(self.cli(policy=self.root/"policy.json"),2)
        alias = self.base/"alias"
        alias.symlink_to(self.root,target_is_directory=True)
        self.assertEqual(self.cli(root=alias),2)
        self.assertFalse(self.out.exists())

    def test_closed_input(self):
        for raw in (b'{"schema":"a","schema":"b"}',b'[]', b'{"score":NaN}',b'x'*262145):
            self.file.write_bytes(raw)
            self.assertEqual(self.cli(),2)
            self.assertFalse(self.out.exists())

    def test_existing_evidence_immutable_and_rehashed_forgery(self):
        self.assertEqual(self.cli(),0)
        self.assertEqual(self.cli(),2)
        path = self.out/"geotrace.json"
        data = self.report()
        data["action_authorization"] = "GRANTED"
        path.write_text(json.dumps(data))
        manifest = self.out/"manifest.json"
        m = json.loads(manifest.read_bytes())
        m["files"][path.name] = {"bytes":path.stat().st_size,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
        manifest.write_text(json.dumps(m))
        self.assertEqual(self.cli(verify=True),2)

    def test_closed_evidence_and_source_reselection(self):
        self.assertEqual(self.cli(),0)
        (self.root/"same.json").write_bytes(self.file.read_bytes())
        self.assertEqual(self.cli(verify=True,file="same.json"),2)
        extra = self.out/"extra"
        extra.touch()
        self.assertEqual(self.cli(verify=True),2)
        extra.unlink()
        q = self.out/"geotrace.md"
        q.rename(self.base/"original")
        q.symlink_to(self.base/"original")
        self.assertEqual(self.cli(verify=True),2)

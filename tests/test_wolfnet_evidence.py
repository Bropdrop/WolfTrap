"""Exercise subscriber entry points with local paths, hostile bytes and changed evidence."""

import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap import wolfnet_evidence as ev
from wolftrap.cli import main
from wolftrap.cursorial_trace import Gap


class Evidence(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.inputs = self.root / "selected"
        self.out = self.root / "verified"
        self.decision = self.root / "decision"
        examples = Path(__file__).resolve().parents[1] / "examples"
        shutil.copytree(examples / "wolfnet", self.inputs)
        for n in ("architecture", "request", "fixture-registry"):
            shutil.copyfile(examples / "wolfprint" / (n + ".json"), self.inputs / (n + ".json"))

    def path(self, name):
        return self.inputs / (name + ".json")

    @staticmethod
    def sha(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def opts(self, feed="feed", checkpoint=None):
        cp = checkpoint or self.path("checkpoint")
        return ["--feed", self.path(feed), "--trust", self.path("trust"), "--trust-sha256", self.sha(self.path("trust")),
                "--checkpoint", cp, "--checkpoint-sha256", self.sha(cp), "--at", "2030-01-01T00:01:00Z",
                "--trace", self.path("incident-chain"), "--witnesses", self.path("witnesses"),
                "--witness-registry", self.path("incident-registry"), "--witness-registry-sha256", self.sha(self.path("incident-registry"))]

    def evaluation(self, policy="policy", verified=None):
        return ["--verified-feed-dir", verified or self.out, "--policy", self.path(policy), "--policy-sha256", self.sha(self.path(policy)),
                "--manifest", self.path("architecture"), "--request", self.path("request"), "--registry", self.path("fixture-registry"),
                "--registry-sha256", self.sha(self.path("fixture-registry"))]

    def cli(self, cmd="verify-wolfnet-feed", opts=None, out=None, replay=False):
        text = io.StringIO()
        with contextlib.redirect_stdout(text), contextlib.redirect_stderr(text):
            code = main([cmd, "--evidence-dir" if replay else "--output-dir", str(out or self.out),
                         *map(str, self.opts() if opts is None else opts)])
        return code, text.getvalue()

    def doc(self, target=None):
        return json.loads(((target or self.out) / "wolfnet.json").read_bytes())

    def test_authentic_feed_and_both_decisions_replay(self):
        self.assertEqual(self.cli()[0], 0)
        self.assertEqual(self.cli(replay=True)[0], 0)
        for policy, action in (("policy", "MONITOR"), ("policy-opt-in", "DENY")):
            target = self.root / policy
            opts = self.opts() + self.evaluation(policy)
            self.assertEqual(self.cli("evaluate-wolfnet", opts, target)[0], 1)
            self.assertEqual(self.cli("evaluate-wolfnet", opts, target, True)[0], 1)
            d = self.doc(target)["decision"]
            self.assertEqual((d["registry_proposal"], d["host_proposal"], d["enforced"]), (action, "ALLOW", False))
        self.assertEqual(set(p.name for p in self.out.iterdir()), {*ev.MEMBERS, ev.CHECKPOINT})

    def test_withdrawal_and_stale_feed_against_new_checkpoint(self):
        self.assertEqual(self.cli()[0], 0)
        cp = self.out / ev.CHECKPOINT
        advance = self.opts("withdrawn-feed", cp)
        withdrawn = self.root / "withdrawn"
        self.assertEqual(self.cli(opts=advance, out=withdrawn)[0], 0)
        opts = advance + self.evaluation("policy-opt-in", withdrawn)
        self.assertEqual(self.cli("evaluate-wolfnet", opts, self.decision)[0], 0)
        self.assertEqual(self.doc(self.decision)["decision"]["registry_proposal"], "ALLOW")
        self.assertEqual(self.cli(opts=self.opts(checkpoint=withdrawn / ev.CHECKPOINT), out=self.root / "rollback")[0], 2)
        self.assertEqual(self.cli(opts=self.opts(checkpoint=cp), out=self.root / "replay")[0], 2)
        self.assertEqual(self.cli(opts=self.opts(checkpoint=cp) + ["--use-accepted"], out=self.root / "current")[0], 0)

    def test_challenge_replay_and_bad_revision(self):
        head = ev.source_identity(None, required_files=ev.REQUIRED)["commit_sha"]
        self.assertEqual(self.cli("challenge-wolfnet", ["--expected-head", head])[0], 0)
        self.assertEqual(self.cli("verify-wolfnet-challenge", ["--expected-head", head], replay=True)[0], 0)
        self.assertEqual(self.cli("verify-wolfnet-challenge", ["--expected-head", "0" * 40], replay=True)[0], 2)
        report = self.doc()
        self.assertEqual((report["summary"]["cases"], report["summary"]["mismatches"], report["summary"]["defects_caught"]),
                         (427, 0, 11))
        self.assertTrue(all(d["mismatches"] and d["first_counterexample"] for d in report["defective_controls"]))
        (self.out / "wolfnet.sarif").unlink()
        self.assertEqual(self.cli("verify-wolfnet-challenge", [], replay=True)[0], 2)

    def test_original_verification_time_does_not_extend_expiry(self):
        self.assertEqual(self.cli()[0], 0)
        opts = self.opts() + self.evaluation() + ["--verified-at", "2030-01-01T00:01:00Z"]
        pos = opts.index("--at") + 1
        opts[pos] = "2030-01-01T00:01:01Z"
        self.assertEqual(self.cli("evaluate-wolfnet", opts, self.decision)[0], 1)
        opts[pos] = "2030-01-01T00:03:01Z"
        no = self.root / "expired"
        self.assertEqual(self.cli("evaluate-wolfnet", opts, no)[0], 2)
        self.assertNotIn("decision", self.doc(no))

    def test_repairing_unsigned_manifest_cannot_substitute_report(self):
        self.assertEqual(self.cli()[0], 0)
        p = self.out / "wolfnet.json"
        altered = self.doc()
        altered["advisories"][0]["effective_level"] = 4
        p.write_text(json.dumps(altered))
        m = self.out / ev.MEMBERS[-1]
        manifest = json.loads(m.read_bytes())
        manifest["files"][p.name] = {"bytes": p.stat().st_size, "sha256": self.sha(p)}
        m.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
        self.assertEqual(self.cli(replay=True)[0], 2)
        self.assertEqual(self.cli("evaluate-wolfnet", self.opts() + self.evaluation(), self.decision)[0], 2)
        self.assertNotIn("decision", self.doc(self.decision))

    def test_missing_extra_linked_and_oversized_evidence(self):
        self.assertEqual(self.cli()[0], 0)
        p = self.out / "wolfnet.md"
        raw = p.read_bytes()
        p.unlink()
        self.assertEqual(self.cli(replay=True)[0], 2)
        p.symlink_to(self.path("feed"))
        self.assertEqual(self.cli(replay=True)[0], 2)
        p.unlink()
        p.write_bytes(raw + b"x")
        self.assertEqual(self.cli(replay=True)[0], 2)
        p.write_bytes(raw)
        (self.root / "alias").hardlink_to(p)
        self.assertEqual(self.cli(replay=True)[0], 2)
        (self.root / "alias").unlink()
        (self.out / "other").touch()
        self.assertEqual(self.cli(replay=True)[0], 2)
        self.assertEqual(self.cli()[0], 2)

    def test_every_local_pin_must_be_selected_independently(self):
        self.assertEqual(self.cli()[0], 0)
        for role in ("trust", "checkpoint", "witness-registry", "policy", "registry"):
            opts = self.opts() + self.evaluation()
            opts[opts.index("--" + role + "-sha256") + 1] = "d" * 64
            self.assertEqual(self.cli("evaluate-wolfnet", opts, self.decision)[0], 2)
        self.assertFalse(self.decision.exists())

    def test_traversal_links_pipes_and_output_overlap(self):
        opts = self.opts()
        alias = self.inputs / "alias"
        alias.hardlink_to(self.path("feed"))
        self.assertEqual(self.cli(opts=opts)[0], 2)
        alias.unlink()
        alias.symlink_to(self.path("feed"))
        directory = self.root / "linked"
        directory.symlink_to(self.inputs, target_is_directory=True)
        fifo = self.inputs / "pipe"
        os.mkfifo(fifo)
        for value in (alias, directory / "feed.json", str(self.inputs) + "/../selected/feed.json", fifo,
                      "https://example.invalid/feed", ".git/config"):
            self.assertEqual(self.cli(opts=["--feed", value, *opts[2:]])[0], 2)
        self.assertEqual(self.cli(opts=opts, out=self.inputs / "overlap")[0], 2)
        self.assertFalse(self.out.exists())

    def test_duplicate_keys_untrusted_text_and_bounds(self):
        opts = self.opts()
        for i, raw in enumerate((b'{"schema":1,"sch\\u0065ma":2}', b'{"instructions":"unpublishable-fictional-marker"}',
                                 b"[" * 13, b" " * 98305, b"[1e3]", b'{"a":-0}', b"[" + b"0," * 4100 + b"0]")):
            self.path("feed").write_bytes(raw)
            target = self.root / str(i)
            code, msg = self.cli(opts=opts, out=target)
            self.assertEqual(code, 2)
            self.assertNotIn("unpublishable-fictional-marker", msg)
            for f in target.iterdir() if target.exists() else []:
                self.assertNotIn(b"unpublishable-fictional-marker", f.read_bytes())
                self.assertNotIn(os.fsencode(self.root), f.read_bytes())
            self.assertFalse((target / ev.CHECKPOINT).exists())

    def test_correctly_signed_feed_with_missing_observation(self):
        opts = self.opts()[:12]
        self.assertEqual(self.cli(opts=opts)[0], 2)
        self.assertEqual(self.doc()["status"], "SIGNED_FEED_WITH_GAPS")
        self.assertEqual(self.cli("evaluate-wolfnet", opts + self.evaluation(), self.decision)[0], 2)
        self.assertIsNone(self.doc(self.decision)["decision"]["registry_proposal"])

    def test_modified_inputs_or_verified_evidence_during_evaluation(self):
        original = ev._feed
        def change_source(*args):
            result = original(*args)
            with self.path("feed").open("ab") as f:
                f.write(b" ")
            return result
        with patch.object(ev, "_feed", side_effect=change_source):
            self.assertEqual(self.cli()[0], 2)
        self.assertFalse(self.out.exists())
        self.assertEqual(self.cli()[0], 0)
        evaluator = ev.evaluate
        def change_verified(*args):
            result = evaluator(*args)
            (self.out / "wolfnet.md").unlink()
            return result
        with patch.object(ev, "evaluate", side_effect=change_verified):
            self.assertEqual(self.cli("evaluate-wolfnet", self.opts() + self.evaluation(), self.decision)[0], 2)
        self.assertFalse(self.decision.exists())

    def test_no_network_or_arbitrary_process_execution(self):
        original = subprocess.run
        def git_only(argv, **kw):
            self.assertEqual(argv[0], "git")
            self.assertIn(argv[1], ("ls-tree", "rev-parse"))
            self.assertEqual(kw["env"]["GIT_ALLOW_PROTOCOL"], "")
            return original(argv, **kw)
        with patch.object(socket, "socket", side_effect=AssertionError), patch("subprocess.run", side_effect=git_only):
            self.assertEqual(self.cli()[0], 0)
            self.assertEqual(self.cli("evaluate-wolfnet", self.opts() + self.evaluation(), self.decision)[0], 1)

    def test_missing_ed25519_backend_fails_closed_with_status(self):
        with patch("wolftrap.wolfnet_crypto.sodium", side_effect=Gap("BLOCKED-ed25519-backend")):
            code, msg = self.cli()
            self.assertEqual((code, self.doc()["status"]), (2, "BLOCKED"))
            self.assertIn("BLOCKED", msg)
            self.assertFalse((self.out / ev.CHECKPOINT).exists())

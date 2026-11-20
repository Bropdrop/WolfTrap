"""Hostile public entry points, publisher-independent pins and byte replay."""

import contextlib
import hashlib
import io
import json
import os
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap import wolfprint_evidence as ev
from wolftrap.cli import main
from wolftrap.wolfprint_challenge import trace_fixture
from wolftrap.wolfprint_fixtures import fixture


class Evidence(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inputs = self.root / "selected"
        self.inputs.mkdir()
        self.out = self.root / "reports"
        m, q, r, t = trace_fixture(1, "complete")
        self.m = self.put("architecture", m)
        self.q = self.put("request", q)
        self.r = self.put("issuer", r)
        self.t = self.put("chain", t)

    def put(self, name, doc):
        path = self.inputs / (name + ".json")
        path.write_text(json.dumps(doc))
        return path

    @staticmethod
    def hash(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def cli(self, cmd="fingerprint-agent", opts=None, out=None):
        if opts is None:
            opts = self.opts()
        key = "--evidence-dir" if cmd.startswith("verify-") else "--output-dir"
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            code = main([cmd, key, str(out or self.out), *map(str, opts)])
        return code, output.getvalue()

    def opts(self):
        return ["--manifest", self.m, "--request", self.q, "--registry", self.r,
                "--registry-sha256", self.hash(self.r), "--at", 30]

    def test_all_four_commands_and_exact_head(self):
        head = ev.source_identity(None)["commit_sha"]
        for cmd, verify, opts, out in (
                ("challenge-wolfprint", "verify-wolfprint", [], self.out),
                ("fingerprint-agent", "verify-agent-fingerprint", self.opts() + ["--chain", self.t], self.root / "second")):
            opts = [*opts, "--expected-head", head]
            self.assertEqual(self.cli(cmd, opts, out)[0], 0)
            self.assertEqual(self.cli(verify, opts, out)[0], 0)
            self.assertEqual(self.cli(verify, [*opts[:-1], "f" * 40], out)[0], 2)
            self.assertEqual({p.name for p in out.iterdir()}, set(ev.MEMBERS))

    def test_rendered_evidence_redacted_and_reproducible(self):
        m = json.loads(self.m.read_bytes())
        m["framework"] = "sensitive-example-value"
        self.put("architecture", m)
        opts = ["--manifest", self.m]
        self.assertEqual(self.cli(opts=opts)[0], 0)
        other = self.root / "again"
        self.assertEqual(self.cli(opts=opts, out=other)[0], 0)
        for name in ev.MEMBERS:
            raw = (self.out / name).read_bytes()
            self.assertEqual(raw, (other / name).read_bytes())
            for value in (self.root.as_posix().encode(), b"sensitive-example-value"):
                self.assertNotIn(value, raw)
        doc = json.loads((self.out / ev.MEMBERS[0]).read_bytes())
        self.assertIsNone(doc["identity"]["principal_id"])
        self.assertFalse(doc["external_credential_verification"])

    def test_unsigned_hash_replacement_cannot_repair_tampering(self):
        self.assertEqual(self.cli()[0], 0)
        man = self.out / ev.MEMBERS[-1]
        original = man.read_bytes()
        for name in ev.MEMBERS[:-1]:
            path = self.out / name
            raw = path.read_bytes()
            fake = raw + b" "
            path.write_bytes(fake)
            metadata = json.loads(original)
            metadata["files"][name] = {"bytes": len(fake), "sha256": self.hash(path)}
            man.write_text(json.dumps(metadata, sort_keys=True, indent=2) + "\n")
            self.assertEqual(self.cli("verify-agent-fingerprint")[0], 2)
            man.write_bytes(original)
            path.write_bytes(raw)
        man.write_bytes(original.replace(b'"COMPLETE"', b'"PARTIAL","state":"COMPLETE"'))
        self.assertEqual(self.cli("verify-agent-fingerprint")[0], 2)

    def test_wrong_missing_pin_or_clock_and_tampered_registry(self):
        opts = self.opts()
        self.assertEqual(self.cli(opts=opts[:-2])[0], 2)
        self.assertEqual(self.cli(opts=[*opts[:6], "--at", 30])[0], 2)
        self.assertEqual(self.cli(opts=[*opts[:-1], -1])[0], 2)
        self.assertEqual(self.cli(opts=[*opts[:-3], "0" * 64, "--at", 30])[0], 2)
        self.r.write_bytes(self.r.read_bytes() + b" ")
        self.assertEqual(self.cli(opts=opts)[0], 2)
        self.assertFalse(self.out.exists())

    def test_stale_baseline_and_replay_of_earlier_source(self):
        same = [*self.opts(), "--baseline", self.m, "--baseline-sha256", self.hash(self.m)]
        self.assertEqual(self.cli(opts=same, out=self.root / "known-architecture")[0], 0)
        baseline = self.put("prior", json.loads(self.m.read_bytes()))
        opts = [*self.opts(), "--baseline", baseline, "--baseline-sha256", self.hash(baseline)]
        self.assertEqual(self.cli(opts=opts)[0], 0)
        self.assertEqual(self.cli("verify-agent-fingerprint", opts)[0], 0)
        self.m.write_bytes(self.m.read_bytes() + b"\n")
        self.assertEqual(self.cli("verify-agent-fingerprint", opts)[0], 2)
        doc = json.loads(baseline.read_bytes())
        doc["framework_version"] = "0.9"
        self.put("prior", doc)
        self.assertEqual(self.cli(opts=[*opts[:-1], self.hash(baseline)], out=self.root / "stale")[0], 2)

    def test_missing_optional_evidence_and_review_codes(self):
        m, q, r, _ = fixture(1, "unknown-model")
        self.put("architecture", m)
        self.assertEqual(self.cli(opts=["--manifest", self.m])[0], 2)
        self.assertEqual(self.cli("verify-agent-fingerprint", ["--manifest", self.m])[0], 2)
        self.put("request", q)
        self.put("issuer", r)
        other = self.root / "partial"
        self.assertEqual(self.cli(out=other)[0], 1)
        self.assertEqual(self.cli("verify-agent-fingerprint", out=other)[0], 1)

    def test_hostile_json_required_bounded_and_redacted(self):
        for raw in (b'{"schema":"a","sch\\u0065ma":"b"}', b"[" * 13, b"x" * 98305, b'{"a":NaN}',
                    b'{"id":9999999}', b'{"marker":"unpublishable-private-example"}', b'{"n":-0}'):
            self.m.write_bytes(raw)
            result = self.cli()
            self.assertEqual(result[0], 2)
            self.assertNotIn("unpublishable-private-example", result[1])
        self.assertFalse(self.out.exists())

    def test_input_path_traversal_symlinks_hardlinks_and_fifo(self):
        opts = ["--manifest", self.m]
        alias = self.inputs / "alias"
        alias.hardlink_to(self.m)
        self.assertEqual(self.cli(opts=opts)[0], 2)
        alias.unlink()
        alias.symlink_to(self.m)
        self.assertEqual(self.cli(opts=["--manifest", alias])[0], 2)
        parent = self.root / "linked"
        parent.symlink_to(self.inputs, target_is_directory=True)
        for path in (parent / self.m.name, str(self.inputs) + "/../selected/" + self.m.name,
                     "https://fixture.invalid/input", ".git/config"):
            self.assertEqual(self.cli(opts=["--manifest", path])[0], 2)
        pipe = self.inputs / "pipe"
        os.mkfifo(pipe)
        self.assertEqual(self.cli(opts=["--manifest", pipe])[0], 2)
        self.assertEqual(self.cli(opts=opts, out=self.inputs / "overlap")[0], 2)
        self.assertFalse(self.out.exists())

    def test_missing_extra_linked_or_oversized_artifacts(self):
        self.assertEqual(self.cli()[0], 0)
        p = self.out / ev.MEMBERS[1]
        raw = p.read_bytes()
        p.unlink()
        self.assertEqual(self.cli("verify-agent-fingerprint")[0], 2)
        p.symlink_to(self.m)
        self.assertEqual(self.cli("verify-agent-fingerprint")[0], 2)
        p.unlink()
        p.write_bytes(raw * 2)
        self.assertEqual(self.cli("verify-agent-fingerprint")[0], 2)
        p.write_bytes(raw)
        (self.root / "artifact-alias").hardlink_to(p)
        self.assertEqual(self.cli("verify-agent-fingerprint")[0], 2)
        (self.root / "artifact-alias").unlink()
        (self.out / "extra").touch()
        self.assertEqual(self.cli("verify-agent-fingerprint")[0], 2)
        self.assertEqual(self.cli()[0], 2)

    def test_source_swap_before_publication(self):
        original = ev._selected
        def swap(*args):
            row = original(*args)
            self.r.write_bytes(self.r.read_bytes() + b" ")
            return row
        with patch.object(ev, "_selected", side_effect=swap):
            self.assertEqual(self.cli()[0], 2)
        self.assertFalse(self.out.exists())

    def test_output_directory_replacement_is_reported(self):
        from wolftrap import cursorial_evidence as shared

        original = shared._open_directory
        def substitute(path, *, create=False):
            fd = original(path, create=create)
            if create and path == self.out:
                self.out.rename(self.root / "moved")
                self.out.mkdir()
            return fd
        with patch.object(shared, "_open_directory", side_effect=substitute):
            self.assertEqual(self.cli()[0], 2)
        self.assertFalse((self.out / ev.MEMBERS[-1]).exists())

    def test_only_local_revision_queries_and_no_network(self):
        original = subprocess.run
        def git_only(argv, **kw):
            self.assertEqual(argv[0], "git")
            self.assertIn(argv[1], ("ls-tree", "rev-parse"))
            self.assertEqual(kw["env"]["GIT_ALLOW_PROTOCOL"], "")
            self.assertNotIn(str(self.m), str(argv))
            return original(argv, **kw)
        with patch("subprocess.run", side_effect=git_only), patch.object(socket, "socket", side_effect=AssertionError):
            self.assertEqual(self.cli(opts=[*self.opts(), "--chain", self.t])[0], 0)

    def test_identity_profile_cannot_be_downgraded(self):
        opts = ["--chain", self.t, "--registry", self.r, "--registry-sha256", self.hash(self.r), "--require-wolfprint"]
        self.assertEqual(self.cli("challenge-cursorial", opts)[0], 0)
        self.assertEqual(self.cli("verify-cursorial", opts)[0], 0)
        other = self.root / "downgraded"
        self.put("chain", json.loads(self.t.read_bytes())["chain"])
        self.assertEqual(self.cli("challenge-cursorial", ["--chain", self.t, "--require-wolfprint"], other)[0], 2)
        self.assertEqual(self.cli("verify-cursorial", opts)[0], 2)

    def test_missing_and_substituted_identity_witness(self):
        doc = json.loads(self.t.read_bytes())
        doc["identity_witnesses"].clear()
        self.put("chain", doc)
        opts = ["--chain", self.t, "--registry", self.r, "--registry-sha256", self.hash(self.r), "--require-wolfprint"]
        self.assertEqual(self.cli("challenge-cursorial", opts)[0], 2)
        self.assertEqual(self.cli("verify-cursorial", opts)[0], 2)
        p = json.loads((self.out / "cursorial.json").read_bytes())["identity_profile"]
        self.assertEqual(p["behavioral_sha256"], "UNKNOWN")

    def test_unrelated_chain_cannot_supply_selected_identity_behavior(self):
        m, req, r, _ = fixture(1, "restart")
        prior = json.loads(self.r.read_bytes())
        r["bindings"] = prior["bindings"]
        self.put("architecture", m)
        self.put("request", req)
        self.put("issuer", r)
        self.assertEqual(self.cli(opts=[*self.opts(), "--chain", self.t])[0], 2)
        row = json.loads((self.out / "wolfprint.json").read_bytes())
        self.assertEqual((row["identity"]["status"], row["behavioral_sha256"]), ("FIXTURE_ATTESTED", "UNKNOWN"))

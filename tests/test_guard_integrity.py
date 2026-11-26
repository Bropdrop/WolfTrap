"""Publication guard controls with generated disposable indicators."""
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from wolftrap import public_guard as guard

GEO = "qualification/geotrace/r01/wolftrap-api-geotrace-v1/tests/test_api_geotrace.py"
SSH = "qualification/wt_mcp_001/qualify.py"
CATALOG = "qualification/wt_mcp_003/catalog_check.py"
TRANSPORT = "git" + "@github.com:Bropdrop/WolfTrap"
VECTOR = "api.fr.test" + "@evil.test"
CONTACT = "person" + "@outside.test"
ORIGINS = repr(("https://github.com/Bropdrop/WolfTrap", TRANSPORT))
GEO_LOOP = ("def test_deny_url_and_not_confuse_host_with_tld():\n"
            "    for value in " + repr(("https://api.fr.test/v1", "api.fr.test/path", VECTOR, "api.fr.test:443"))
            + ":\n        pass\n")
MANIFEST = b"cryptography==50.0.0\n"
LAB_PATH = "experiments/cryptofall/requirements.txt"


def scan(path, source, lab=False):
    return guard._source_signals(tuple(path.split("/")), source.encode(), False, False, lab)


class GuardIntegrityTests(unittest.TestCase):
    def test_minimal_positive_contexts(self):
        for path, source in [(GEO, GEO_LOOP), (SSH, "remote in " + ORIGINS), (CATALOG, "origin not in " + ORIGINS)]:
            with self.subTest(path=path):
                self.assertEqual(scan(path, source), set())
                self.assertEqual(scan("other.py", source), {"contact-address"})
                self.assertEqual(scan(path, source + "\n# " + CONTACT), {"contact-address"})

    def test_context_cannot_authorize_another_occurrence(self):
        self.assertEqual(scan(GEO, GEO_LOOP + "address = " + repr(VECTOR)), {"contact-address"})
        self.assertEqual(scan(GEO, GEO_LOOP.replace("not_confuse", "accept")), {"contact-address"})
        self.assertEqual(scan(SSH, "remote in " + ORIGINS + "\n# " + TRANSPORT), {"contact-address"})
        self.assertEqual(scan(SSH, "origin in " + ORIGINS), {"contact-address"})
        self.assertEqual(scan(SSH, "remote not in " + ORIGINS), {"contact-address"})
        self.assertEqual(scan(CATALOG, "origin not in " + ORIGINS.replace("WolfTrap", "Other")), {"contact-address"})
        self.assertEqual(scan(SSH, "remote in " + ORIGINS.replace("git" + "@", "owner" + "@")), {"contact-address"})
        self.assertEqual(guard._report_content_signals(TRANSPORT, ".txt"), {"contact-address"})

    def test_utf8_offsets_and_newlines(self):
        for sep in ["\n", "\r", "\r\n"]:
            text = "# résumé" + sep + "'é'; remote in " + ORIGINS
            self.assertEqual(scan(SSH, text), set())
            self.assertEqual(scan(SSH, text + " # " + CONTACT), {"contact-address"})

    def test_other_sensitive_data_stays_visible(self):
        token = "gh" + "p_" + "A" * 36
        self.assertEqual(scan(SSH, "remote in " + ORIGINS + " # " + token), {"credential-shape"})
        self.assertIn("report-local-path", guard._report_content_signals("/" + "home/synthetic/file", ".txt"))
        self.assertIn("contact-address", scan(GEO, GEO_LOOP.replace(VECTOR, CONTACT)))

    def test_manifest_requires_scope_content_and_opt_in(self):
        for path, raw, lab in [(LAB_PATH, MANIFEST, False), ("requirements.txt", MANIFEST, True),
                               (LAB_PATH, MANIFEST + b"other==1\n", True)]:
            self.assertIn("unreviewed-dependency-manifest", scan(path, raw.decode(), lab))
        self.assertFalse(scan(LAB_PATH, MANIFEST.decode(), True))

    def test_evidence_is_bound_to_both_files_and_scope(self):
        # Model the read-only Git boundary. The separate qualification replays
        # the real target Git tree using the public CLI.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            files = {"lock": b"locked", "proof": b"publication"}
            for name, raw in files.items():
                (root / name).write_bytes(raw)
            pins = {name: hashlib.sha256(raw).hexdigest() for name, raw in files.items()}
            def run(tree, workflows=True):
                result = guard.GuardScan()
                with patch.object(guard, "_git_object", return_value=tree), patch.object(guard, "_git", return_value=b""):
                    guard.scan_source(root, "HEAD", result, workflow_dependencies=workflows, cryptofall_evidence=root)
                return result.signals
            with patch.dict(guard._LAB_EVIDENCE, pins, clear=True):
                self.assertFalse(run(guard._LAB_TREE))
                self.assertIn("laboratory-scope", run("0" * 40))
                self.assertIn("laboratory-scope", run(guard._LAB_TREE, False))
                for name, raw in files.items():
                    (root / name).write_bytes(raw + b"!")
                    self.assertIn("laboratory-evidence", run(guard._LAB_TREE))
                    (root / name).write_bytes(raw)
                (root / "proof").unlink()
                (root / "proof").symlink_to(root / "lock")
                self.assertIn("laboratory-evidence", run(guard._LAB_TREE))

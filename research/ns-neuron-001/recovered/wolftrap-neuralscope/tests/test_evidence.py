import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from neuralscope import evidence
from neuralscope.evidence import seal, verify, write_json


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        write_json(self.root / "result.json", {"a": 1})
        self.pin = seal(self.root, {"experiment": "test"})

    def test_pinned_receipt(self):
        self.assertEqual(verify(self.root, self.pin)["status"], "INTEGRITY_MATCH")
        self.assertFalse(verify(self.root)["publisher_authenticated"])

    def test_changed_payload(self):
        (self.root / "result.json").write_text('{"a":2}\n')
        with self.assertRaises(ValueError):
            verify(self.root, self.pin)

    def test_extra_file(self):
        (self.root / "unexpected").write_text("x")
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_extra_empty_directory(self):
        (self.root / "unexpected").mkdir()
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_symlink(self):
        (self.root / "result.json").unlink()
        (self.root / "result.json").symlink_to("/etc/hosts")
        with self.assertRaises((ValueError, OSError)):
            verify(self.root)

    def test_rewritten_receipt_does_not_match_pin(self):
        (self.root / "manifest.json").write_text('{"schema":"fake"}')
        with self.assertRaises(ValueError):
            verify(self.root, self.pin)

    def test_duplicate_keys(self):
        (self.root / "manifest.json").write_text('{"files":{},"files":{}}')
        with self.assertRaises(ValueError):
            verify(self.root)

    def test_replacement_after_receipt_read_cannot_rebind_retained_digest(self):
        """Old hash-then-reopen accepted this altered manifest under the old pin."""
        manifest_path = self.root / "manifest.json"
        replacement_payload = b'{"a": 999}\n'
        replacement_manifest = json.loads(manifest_path.read_bytes())
        replacement_manifest["files"]["result.json"] = {
            "bytes": len(replacement_payload),
            "sha256": hashlib.sha256(replacement_payload).hexdigest(),
        }
        replacement_bytes = evidence.canonical(replacement_manifest)
        real_open = evidence._open_regular
        manifest_opens = 0

        class ReplaceOnClose:
            def __init__(self, handle):
                self.handle = handle

            def __enter__(self):
                return self.handle.__enter__()

            def __exit__(self, kind, value, traceback):
                result = self.handle.__exit__(kind, value, traceback)
                (self_root / "result.json").write_bytes(replacement_payload)
                manifest_path.write_bytes(replacement_bytes)
                return result

        self_root = self.root

        def opened(path):
            nonlocal manifest_opens
            handle = real_open(path)
            if Path(path) == manifest_path:
                manifest_opens += 1
                if manifest_opens == 1:
                    return ReplaceOnClose(handle)
            return handle

        with patch.object(evidence, "_open_regular", side_effect=opened):
            with self.assertRaisesRegex(ValueError, "inventory|digest mismatch"):
                verify(self.root, self.pin)
        self.assertEqual(manifest_opens, 1)


if __name__ == "__main__":
    unittest.main()

"""Regression checks for the release package's closed skills-only inventory."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from skills_package import ICON, MEMBERS, PLUGIN, ROOT, encode_zip, validate, verify_zip


class SkillsPackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.files = {name: (ROOT / (name if name == "LICENSE" else f"{PLUGIN}/{name}")).read_bytes()
                     for name in MEMBERS}

    def test_reviewed_shape(self):
        self.assertEqual(validate(self.files)["version"], "0.2.0")
        self.assertEqual(encode_zip(self.files), encode_zip(dict(reversed(list(self.files.items())))))

    def test_extra_and_missing_payloads(self):
        for name in ("mcp.json", ".mcp.json", "hooks/hooks.json", "../plugin.json", ".app.json"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(self.files | {name: b"{}"})
        for name in (ICON, "LICENSE", "skills/wolftrap-audit/SKILL.md"):
            with self.subTest(missing=name), self.assertRaises(ValueError):
                validate({key: value for key, value in self.files.items() if key != name})

    def test_manifest_rejections(self):
        original = json.loads(self.files["plugin.json"])
        for change in ("version", "executor", "hook", "icon", "subtitle"):
            with self.subTest(change=change), self.assertRaises(ValueError):
                manifest = copy.deepcopy(original)
                provider = manifest["extensions"]["com.openai"]
                if change == "version":
                    manifest["version"] = "1.0.0"
                elif change == "executor":
                    provider["requires_local_executor"] = False
                elif change == "hook":
                    provider["hooks"] = "./hooks/hooks.json"
                elif change == "icon":
                    provider["interface"]["logo"] = "./assets/missing.png"
                else:
                    provider["interface"]["shortDescription"] = "x" * 31
                validate(self.files | {"plugin.json": json.dumps(manifest).encode()})
        with self.assertRaisesRegex(ValueError, "duplicate"):
            validate(self.files | {"plugin.json": b'{"name":"a","name":"b"}'})

    def test_substituted_zip(self):
        expected = encode_zip(self.files)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "candidate.zip"
            path.write_bytes(expected)
            verify_zip(path, expected)
            for replacement in (expected[:-1], encode_zip(self.files | {"mcp.json": b"{}"}),
                                encode_zip(self.files | {"LICENSE": b"replacement"})):
                path.write_bytes(replacement)
                with self.assertRaisesRegex(ValueError, "differs"):
                    verify_zip(path, expected)


if __name__ == "__main__":
    unittest.main()

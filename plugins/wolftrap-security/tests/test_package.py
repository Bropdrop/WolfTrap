"""Read-only contract checks for the skills-only WolfTrap plugin package."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1]
REPO = PLUGIN.parents[1]
MANIFEST = PLUGIN / "plugin.json"
MARKETPLACE = REPO / ".agents" / "plugins" / "marketplace.json"


class PluginPackageContract(unittest.TestCase):
    def test_portable_manifest(self) -> None:
        package = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(
            package["$schema"],
            "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        )
        self.assertEqual(package["name"], "wolftrap-security")
        self.assertEqual(package["version"], "0.1.0")
        self.assertIn("com.openai", package["extensions"])
        self.assertTrue(package["extensions"]["com.openai"]["interface"]["displayName"])

    def test_repo_local_marketplace_path(self) -> None:
        catalog = json.loads(MARKETPLACE.read_text(encoding="utf-8"))
        entries = [item for item in catalog["plugins"] if item["name"] == "wolftrap-security"]
        self.assertEqual(len(entries), 1)
        item = entries[0]
        self.assertEqual(item["policy"]["installation"], "AVAILABLE")
        self.assertEqual(item["source"]["source"], "local")
        path = item["source"]["path"]
        self.assertTrue(path.startswith("./"))
        resolved = (REPO / path).resolve()
        self.assertEqual(resolved, PLUGIN.resolve())
        self.assertTrue(resolved.is_relative_to(REPO.resolve()))

    def test_skill_frontmatter_and_descriptions(self) -> None:
        expected = ("wolftrap-audit", "wolftrap-evidence-review")
        for name in expected:
            with self.subTest(name=name):
                path = PLUGIN / "skills" / name / "SKILL.md"
                content = path.read_text(encoding="utf-8")
                self.assertRegex(content, r"(?s)^---\nname: " + re.escape(name) + r"\ndescription: .+?\n---\n")
                self.assertIn("NOT TESTED", content)
                self.assertIn("INCONCLUSIVE", content)
                self.assertIn("untrusted", content.lower())

    def test_no_unreviewed_runtime_integration(self) -> None:
        self.assertFalse((PLUGIN / "mcp.json").exists())
        self.assertFalse((PLUGIN / ".mcp.json").exists())
        self.assertFalse((PLUGIN / "hooks").exists())
        self.assertFalse((PLUGIN / ".app.json").exists())
        self.assertFalse((PLUGIN / ".codex-plugin" / "plugin.json").exists())

    def test_audit_boundary_and_existing_commands(self) -> None:
        audit = (PLUGIN / "skills" / "wolftrap-audit" / "SKILL.md").read_text(
            encoding="utf-8"
        )
        for command in (
            "scan-build", "scan-agent", "scan-effects", "scan-prompts",
            "scan-go-authority", "verify-effects", "verify-prompts",
            "verify-go-authority",
        ):
            self.assertIn(command, audit)
        self.assertIn("Do not execute target scripts", audit)
        self.assertIn("No general", (PLUGIN / "skills" / "wolftrap-evidence-review" / "SKILL.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()

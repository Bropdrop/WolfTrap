"""Independent corpus-definition checks; deliberately does not import the scanner."""

from __future__ import annotations

import ast
from collections import Counter
import json
from pathlib import Path, PurePosixPath
import unittest

from wolftrap import agent_corpus
from wolftrap.agent_corpus import corpus_cases


class AgentCorpusTests(unittest.TestCase):
    def test_complete_balanced_independent_labels(self) -> None:
        cases = corpus_cases()
        self.assertEqual(108, len(cases))
        self.assertEqual(108, len({case["id"] for case in cases}))
        self.assertEqual(
            Counter({"positive": 24, "negative": 24, "ambiguous": 36, "evasion": 24}),
            Counter(case["category"] for case in cases),
        )
        semantic = [case for case in cases if case["family"] != "BOUNDARY"]
        self.assertEqual(
            Counter({(rule, category): 8 for rule in agent_corpus.RULE_IDS for category in agent_corpus.CATEGORIES}),
            Counter((case["family"], case["category"]) for case in semantic),
        )
        for case in cases:
            self.assertTrue(case["synthetic_only"])
            self.assertTrue(case["rationale"])
            if case["category"] in {"positive", "evasion"}:
                self.assertEqual("REVIEW_REQUIRED", case["expected_status"])
                self.assertEqual([case["family"]], case["expected_rules"])
            elif case["category"] == "negative":
                self.assertEqual("NO_PATTERN_MATCH", case["expected_status"])
                self.assertEqual([], case["expected_rules"])
            else:
                self.assertEqual("INCONCLUSIVE", case["expected_status"])
                self.assertEqual([], case["expected_rules"])

    def test_seed_changes_order_only_and_replay_is_serializable(self) -> None:
        a, b, c = corpus_cases(7), corpus_cases(7), corpus_cases(8)
        self.assertEqual(a, b)
        self.assertNotEqual([case["id"] for case in a], [case["id"] for case in c])
        self.assertEqual({x["id"]: x for x in a}, {x["id"]: x for x in c})
        self.assertEqual(a, json.loads(json.dumps(a, sort_keys=True)))
        a[0]["files"]["changed"] = "tampered"
        self.assertEqual(b, corpus_cases(7))
        for seed in (-1, True, 2**32, 1.1, "7"):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                corpus_cases(seed)

    def test_fixture_write_paths_are_bounded_and_escape_is_selection_only(self) -> None:
        for case in corpus_cases():
            for filename, body in case["files"].items():
                path = PurePosixPath(filename)
                self.assertFalse(path.is_absolute())
                self.assertNotIn("..", path.parts)
                self.assertIsInstance(body, str)
                self.assertLess(len(body.encode("utf-8")), 4096)
            for directive in case["directives"]:
                self.assertIn(directive["kind"], {
                    "missing", "invalid_utf8", "oversized", "symlink",
                    "symlink_directory", "path_escape",
                })
                if directive["kind"] == "path_escape":
                    self.assertIn(directive["path"], case["selected_files"])
                    self.assertNotIn(directive["path"], case["files"])
                else:
                    path = PurePosixPath(directive["path"])
                    self.assertFalse(path.is_absolute())
                    self.assertNotIn("..", path.parts)
                if directive["kind"] == "oversized":
                    self.assertEqual(262145, directive["count"])
                    self.assertEqual(" ", directive["character"])
                if directive["kind"] in {"symlink", "symlink_directory"}:
                    target = PurePosixPath(directive["target"])
                    self.assertFalse(target.is_absolute())
                    self.assertNotIn("..", target.parts)

    def test_labels_do_not_depend_on_detector_imports_or_results(self) -> None:
        tree = ast.parse(Path(agent_corpus.__file__).read_text(encoding="utf-8"))
        imported = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                imported.append(node.module or "")
        self.assertEqual({"__future__", "copy", "hashlib", "typing"}, set(imported))
        semantic_sources = [
            next(iter(case["files"].values())) for case in corpus_cases()
            if case["family"] != "BOUNDARY"
        ]
        self.assertEqual(96, len(set(semantic_sources)))


if __name__ == "__main__":
    unittest.main()

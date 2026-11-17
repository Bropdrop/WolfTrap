from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from wolftrap.public_guard import GuardScan, main, scan_reports, scan_source


class PublicSourceGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "-q")
        self.git("config", "user.email", "wolftrap@example.org")
        self.git("config", "user.name", "WolfTrap Synthetic Test")

    def git(self, *arguments: str) -> str:
        return subprocess.run(
            ["git", *arguments], cwd=self.root, check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ).stdout.strip()

    def write(self, name: str, content: str) -> Path:
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")
        return file

    def commit(self) -> None:
        self.git("add", "--all")
        self.git("commit", "-qm", "synthetic guard fixture")

    def test_source_identity_and_snapshot_are_taken_from_git(self) -> None:
        file = self.write("safe.py", "import json\n")
        self.write("docs/ground-truth-conformance.md", "Public synthetic contract overview.\n")
        self.commit()
        file.write_text("import hercules\n", encoding="utf-8")
        scan = GuardScan()
        scan_source(self.root, "HEAD", scan)
        self.assertEqual(scan.commit, self.git("rev-parse", "HEAD"))
        self.assertEqual(scan.tree, self.git("rev-parse", "HEAD^{tree}"))
        self.assertEqual(scan.source_entries, 2)
        self.assertEqual(scan.result(False)["status"], "NO_PATTERN_MATCH")

    def test_detects_imports_private_paths_contacts_and_credential_shapes(self) -> None:
        credential = "gh" + "p_" + "A" * 36
        email = "fictional" + "@" + "outside-domain.test"
        self.write("bad.py", 'import importlib\nimportlib.import_module("vendor.ground_truth.runtime")\n')
        self.write("bad.ts", 'import { helper } from "@scope/mobipute";\n')
        self.write("Truth-Pute/snapshot.md", "placeholder")
        self.write("build.env", f"{credential}\n{email}\n")
        self.commit()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["--repo", str(self.root)]), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["status"], "STATIC REVIEW SIGNAL")
        self.assertEqual(result["signals"], {
            "contact-address": 1,
            "credential-shape": 1,
            "private-import": 2,
            "private-path": 1,
        })
        for withheld in (credential, email, "Truth-Pute", "bad.py", str(self.root)):
            self.assertNotIn(withheld, output.getvalue())

    @unittest.skipUnless(hasattr(os, "symlink"), "requires symlink support")
    def test_symlink_and_case_collisions_are_inconclusive(self) -> None:
        self.write("Mixed/a.txt", "safe")
        self.write("mixed/b.txt", "safe")
        (self.root / "public-link").symlink_to("/unreadable/synthetic-path")
        self.commit()
        scan = GuardScan()
        scan_source(self.root, "HEAD", scan)
        self.assertEqual(scan.unknown, {"colliding-tracked-path": 1, "unsafe-tracked-mode": 1})
        self.assertEqual(scan.result(False)["status"], "INCONCLUSIVE")

    def test_new_dependency_declarations_require_review(self) -> None:
        self.write("pyproject.toml", '[project]\ndependencies = ["independent-test-package"]\n')
        self.write("requirements-dev.txt", "independent-test-package")
        self.commit()
        scan = GuardScan()
        scan_source(self.root, "HEAD", scan)
        self.assertEqual(scan.signals, {
            "unreviewed-dependency-manifest": 1,
            "unreviewed-package-dependency": 1,
        })

    def test_from_import_checks_the_imported_module_name(self) -> None:
        self.write("fixture.py", "from vendor import ground_truth as synthetic_runtime\n")
        self.commit()
        scan = GuardScan()
        scan_source(self.root, "HEAD", scan)
        self.assertEqual(scan.signals, {"private-import": 1})

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "requires optional YAML parser")
    def test_workflow_checks_flow_mapping_uses_and_unapproved_install(self) -> None:
        self.write(
            ".github/workflows/new.yml",
            "name: Synthetic test\n"
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            '      - {"uses": "fixture-org/independent-action@' + "0" * 40 + '"}\n'
            "      - run: python -m pip install independent-test-package\n",
        )
        self.commit()
        scan = GuardScan()
        scan_source(self.root, "HEAD", scan, workflow_dependencies=True)
        self.assertEqual(scan.signals, {
            "unreviewed-workflow-action": 1,
            "unreviewed-workflow-install": 1,
        })
        self.assertFalse(scan.unknown)

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "requires optional YAML parser")
    def test_workflow_duplicate_keys_are_inconclusive(self) -> None:
        self.write(".github/workflows/new.yml", "jobs: {}\njobs: {}\n")
        self.commit()
        scan = GuardScan()
        scan_source(self.root, "HEAD", scan, workflow_dependencies=True)
        self.assertEqual(scan.unknown, {"unsupported-source-content": 1})

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "requires optional YAML parser")
    def test_hash_locked_qualification_dependency_is_bound_to_path_and_digest(self) -> None:
        workflow = self.write(
            ".github/workflows/qualification.yml",
            "jobs:\n"
            "  test:\n"
            "    steps:\n"
            "      - run: |\n"
            "          python -I -m pip --isolated install --no-cache-dir --no-deps --only-binary=:all: "
            "--require-hashes --index-url https://pypi.org/simple -r .github/qualification-requirements.txt\n",
        )
        lock = self.write(
            ".github/qualification-requirements.txt",
            "# Reviewed wheel\n"
            "PyYAML==6.0.3 --hash=sha256:ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc\n",
        )
        self.commit()
        scan = GuardScan()
        scan_source(self.root, "HEAD", scan, workflow_dependencies=True)
        self.assertEqual(scan.result(True)["status"], "NO_PATTERN_MATCH")

        lock.write_text(lock.read_text(encoding="utf-8").replace("ba1cc", "aa1cc"), encoding="utf-8")
        self.commit()
        scan = GuardScan()
        scan_source(self.root, "HEAD", scan)
        self.assertEqual(scan.signals, {"unreviewed-dependency-manifest": 1})

        lock.unlink()
        self.commit()
        scan = GuardScan()
        scan_source(self.root, "HEAD", scan, workflow_dependencies=True)
        self.assertEqual(scan.signals, {"unreviewed-workflow-install": 1})

        workflow.write_text(
            workflow.read_text(encoding="utf-8").replace("qualification-requirements.txt", "other.txt"),
            encoding="utf-8",
        )
        self.commit()
        scan = GuardScan()
        scan_source(self.root, "HEAD", scan, workflow_dependencies=True)
        self.assertEqual(scan.signals, {"unreviewed-workflow-install": 1})

    def test_invalid_git_revision_is_redacted(self) -> None:
        scan = GuardScan()
        scan_source(self.root, "--fictional-private-ref", scan)
        self.assertEqual(scan.unknown, {"git-input": 1})
        self.assertNotIn("fictional", json.dumps(scan.result(False)))


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd, "requires descriptor-relative open")
class PublicReportGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_clean_and_sensitive_reports_are_distinguished(self) -> None:
        (self.root / "clean.json").write_text(
            '{"client_secret": "[REDACTED]", "contact": "demo@example.org"}',
            encoding="utf-8",
        )
        (self.root / "sensitive.json").write_text(
            r'{"\u0063lient_secret": "fixture value", "location": "\u002fhome\u002fdemo\u002finput"}',
            encoding="utf-8",
        )
        scan = GuardScan()
        scan_reports(self.root, ["clean.json", "sensitive.json"], scan)
        self.assertEqual(scan.report_entries, 2)
        self.assertEqual(scan.signals, {"report-local-path": 1, "report-sensitive-field": 1})
        self.assertFalse(scan.unknown)

    def test_traversal_symlinks_hardlinks_and_binary_inputs_fail_closed(self) -> None:
        file = self.root / "regular.json"
        file.write_text("{}", encoding="utf-8")
        (self.root / "linked-directory").symlink_to(self.root, target_is_directory=True)
        (self.root / "link.json").symlink_to(file)
        (self.root / "hardlink.json").hardlink_to(file)
        (self.root / "binary.zip").write_bytes(b"PK")
        scan = GuardScan()
        scan_reports(self.root, [
            "../regular.json", "linked-directory/regular.json", "link.json", "hardlink.json",
            "binary.zip",
        ], scan)
        self.assertEqual(scan.unknown, {"unsupported-report-input": 5})

    def test_duplicate_keys_are_inconclusive(self) -> None:
        (self.root / "duplicate.json").write_text(
            '{"client_secret": "fictional value", "client_secret": ""}',
            encoding="utf-8",
        )
        scan = GuardScan()
        scan_reports(self.root, ["duplicate.json"], scan)
        self.assertEqual(scan.unknown, {"unsupported-report-input": 1})

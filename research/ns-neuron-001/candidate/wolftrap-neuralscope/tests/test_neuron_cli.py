"""Check lazy CLI integration, input protection and non-success exit statuses."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from neuralscope.__main__ import main


class NeuronCommandTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.base = Path(directory.name)
        self.model = self.base / "model"
        self.model.mkdir()
        self.output = self.base / "run"

    def invoke(self, output=None):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(["neuron", "--model-dir", str(self.model), "--out", str(output or self.output)])
        return code, json.loads(stdout.getvalue() or stderr.getvalue())

    def test_help_in_core_environment(self):
        result = subprocess.run([sys.executable, "-S", "-m", "neuralscope", "neuron", "--help"],
                                text=True, capture_output=True, check=True,
                                cwd=Path(__file__).resolve().parents[1])
        self.assertIn("--model-dir", result.stdout)
        self.assertNotIn("--download", result.stdout)

    def test_incomplete_model_stops_before_evidence_directory(self):
        code, result = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertFalse(self.output.exists())

    def test_output_inside_model_is_rejected(self):
        output = self.model / "nested" / "run"
        code, result = self.invoke(output)
        self.assertEqual(code, 2)
        self.assertIn("outside the pinned model", result["reason"])
        self.assertEqual(list(self.model.iterdir()), [])

    def test_existing_evidence_is_preserved(self):
        self.output.mkdir()
        sentinel = self.output / "results.json"
        sentinel.write_bytes(b"unchanged")
        with patch("neuralscope.neuron_run.verify_model", return_value={"revision": "test"}):
            code, result = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(result["error_type"], "FileExistsError")
        self.assertEqual(sentinel.read_bytes(), b"unchanged")

    def test_measurement_exit_status(self):
        for status, expected in (("MEASURED", 0), ("NO_SELECTION", 2), ("BLOCKED_MECHANISM_CHECK", 2)):
            with self.subTest(status=status), patch("neuralscope.neuron_run.run_neuron", return_value={"status": status}):
                code, result = self.invoke()
                self.assertEqual(code, expected)
                self.assertEqual(result["status"], status)

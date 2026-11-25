import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np

from neuralscope.__main__ import demo_cases, main, run_demo
from neuralscope.core import make_demo_model
from neuralscope.evidence import seal, verify
from neuralscope.experiment import evaluate, replay, validate_cases, _save_arrays
from neuralscope.report import render_report


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.model, self.demo = make_demo_model()
        self.spec = demo_cases(self.demo)

    def test_discovery_selects_planted_head_and_validation_confirms(self):
        result = evaluate(self.model, self.spec)
        self.assertEqual(result["status"], "MEASURED")
        self.assertEqual(result["selected_site_using_discovery_only"], self.demo["causal_site"])
        for summary in result["site_summary"]:
            expected = 1.0 if summary["site"] == self.demo["causal_site"] else 0.0
            for split in ("discovery", "validation"):
                self.assertEqual(summary[split]["cases"], 3)
                self.assertAlmostEqual(summary[split]["mean_restoration"], expected, places=6)
                self.assertEqual(summary[split]["self_patch_max_abs_delta"], 0.0)

    def test_all_relevant_controls_are_recorded(self):
        result = evaluate(self.model, self.spec)
        for case in result["cases"]:
            active = case["interventions"][0]
            self.assertAlmostEqual(active["normalized_reverse"], 1.0, places=6)
            self.assertAlmostEqual(active["ablated_margin"], 0.0, places=6)

    def test_unusable_gap_is_inconclusive(self):
        for case in self.spec["cases"]:
            case["corrupt_ids"] = case["clean_ids"].copy()
        result = evaluate(self.model, self.spec)
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertIsNone(result["selected_site_using_discovery_only"])
        self.assertTrue(all(row["normalized_restoration"] is None for case in result["cases"] for row in case["interventions"]))

    def test_cross_split_duplicate_rejected(self):
        duplicate = copy.deepcopy(self.spec["cases"][0])
        duplicate.update(id="same_case_hidden", split="validation")
        self.spec["cases"][1] = duplicate
        with self.assertRaisesRegex(ValueError, "duplicate paired"):
            evaluate(self.model, self.spec)

    def test_invalid_site_or_position_rejected_cleanly(self):
        for bad in ({}, [], 3, None):
            spec = copy.deepcopy(self.spec)
            spec["sites"] = [bad]
            with self.assertRaises(ValueError):
                validate_cases(spec, self.model)
            spec = copy.deepcopy(self.spec)
            spec["cases"][0]["positions"] = [bad]
            with self.assertRaises(ValueError):
                validate_cases(spec, self.model)

    def test_normalization_floor_predeclared(self):
        self.spec["minimum_gap"] = 1000
        self.assertEqual(evaluate(self.model, self.spec)["status"], "INCONCLUSIVE")

    def test_report_escapes_model_strings(self):
        result = evaluate(self.model, self.spec)
        result["model_origin"] = "<script>alert(1)</script>"
        page = render_report(result)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("default-src 'none'", page)

    def test_full_bundle_integrity_and_numeric_replay(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "run"
            summary = run_demo(path)
            self.assertEqual(verify(path, summary["manifest_sha256"])["status"], "INTEGRITY_MATCH")
            reproduced = replay(path, summary["manifest_sha256"])
            self.assertEqual(reproduced["status"], "NUMERIC_REPLAY_MATCH")
            self.assertTrue(reproduced["numeric_traces_replayed"])
            self.assertTrue(reproduced["same_source_files"])
            with self.assertRaises(FileExistsError):
                run_demo(path)

    def test_forged_trace_rejected_even_with_new_unpinned_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "run"
            run_demo(path)
            trace = path / "traces/prefix_0.npz"
            with np.load(trace, allow_pickle=False) as archive:
                arrays = {name: archive[name] for name in archive.files}
            arrays["clean.final_logits"] = arrays["clean.final_logits"] + 1.0
            trace.unlink()
            _save_arrays(trace, arrays)
            (path / "manifest.json").unlink()
            seal(path, {"forged_for_test": True})
            self.assertEqual(verify(path)["status"], "INTEGRITY_MATCH")
            with self.assertRaisesRegex(ValueError, "activation or logits differ"):
                replay(path)

    def test_cli_api_run_is_dry_without_live_flag(self):
        config = Path(__file__).parents[1] / "examples/api-pilot.json"
        with tempfile.TemporaryDirectory() as temporary, patch("neuralscope.api_lab._http_transport") as network:
            with patch("sys.stdout", new=io.StringIO()):
                code = main(["api-run", "--config", str(config), "--out", str(Path(temporary) / "dry")])
            self.assertEqual(code, 0)
            network.assert_not_called()
            result = json.loads((Path(temporary) / "dry/result.json").read_text())
            self.assertEqual(result["mode"], "DRY_RUN")
            self.assertFalse(result["api_key_read"])

    def test_invalid_api_config_is_not_exported(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            config = base / "invalid.json"
            config.write_text(json.dumps({"api_key": "nonstandard-sensitive-value"}))
            with patch("sys.stdout", new=io.StringIO()):
                code = main(["api-run", "--config", str(config), "--out", str(base / "out")])
            self.assertEqual(code, 2)
            self.assertFalse((base / "out/config.redacted.json").exists())
            for path in (base / "out").rglob("*"):
                if path.is_file():
                    self.assertNotIn("nonstandard-sensitive-value", path.read_text())


if __name__ == "__main__":
    unittest.main()

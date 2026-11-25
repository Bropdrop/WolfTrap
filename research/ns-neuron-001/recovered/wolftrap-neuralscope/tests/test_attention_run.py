"""Workflow boundaries that numeric unit tests alone cannot establish."""
import copy
import hashlib
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from neuralscope import attention_run as runner
from neuralscope.evidence import canonical, digest, read_json, seal, write_json


class AttentionWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.protocol = {"model_identity": {"revision": "fixed", "files": {}}, "sites": ["head"],
                         "forward_pass_counts": {
            "discovery_unique_baselines": 12, "discovery_candidate_restore_passes": 864,
            "discovery_candidate_total": 876, "discovery_reference_hooked_baselines": 12,
            "discovery_reference_unhooked_baselines": 12, "discovery_reference_restore_passes": 72,
            "discovery_reference_total": 96, "validation_unique_baselines": 12,
            "validation_candidate_interventions": 60, "validation_candidate_total": 72,
            "validation_reference_hooked_baselines": 12, "validation_reference_unhooked_baselines": 12,
            "validation_reference_interventions": 60, "validation_reference_total": 84}}
        self.selection = {"status": "SELECTED", "selected_site": "blocks.2.attn.head.1", "ranking": []}
        self.config = {"epsilon": 1e-5, "vocab_size": 16}
        self.identity = {"revision": "fixed"}
        self.candidate = SimpleNamespace(parameter_count=100)
        self.reference = SimpleNamespace(provenance=lambda: {"version": "fixture"})
        self.events = []
        self.fail_discovery = False
        self.validation_calls = 0
        self.selection_calls = 0

        patches = [
            patch.object(runner, "_checked_registration", return_value=(
                self.config, object(), self.protocol, self.identity)),
            patch.object(runner, "_models", return_value=(self.candidate, self.reference, [])),
            patch.object(runner, "source_identity", return_value={"test": "fixed"}),
            patch.object(runner, "select_head", side_effect=self.choose),
            patch.object(runner, "assess_validation", side_effect=lambda rows, proto, site: {
                "status": "MEASURED" if site else "NOT_RUN_NO_SELECTION", "selected_site": site,
                "descriptive_criteria_met": True if site else None}),
            patch("neuralscope.attention_measure.discovery", side_effect=self.discovery),
            patch("neuralscope.attention_measure.validation", side_effect=self.validation),
            patch("neuralscope.attention_report.render_attention_report", return_value="<!doctype html><title>fixture</title>"),
        ]
        for item in patches:
            item.start()
            self.addCleanup(item.stop)

    def phase(self, name, success=True):
        interventions = 864 if name == "discovery" else 60
        ref = 72 if name == "discovery" else 60
        counts = {"candidate_baseline": 12, "candidate_intervention": interventions,
                  "reference_baseline": 12, "reference_unhooked": 12, "reference_intervention": ref,
                  "candidate_total": interventions + 12, "reference_total": ref + 24}
        return {"stage": name, "status": "PASS" if success else "FAIL", "completed": success,
                "records": [{"earlier_logits_unchanged": True} for _ in range(interventions)],
                "baseline_records": [{} for _ in range(12)], "counts": counts,
                "parity": {"status": "PASS", "baseline_comparisons": 12, "intervention_comparisons": ref,
                           "reference_hooks_bitwise_invariant": True,
                           "maximum_logit_absolute_error": 0.0, "maximum_logit_rmse": 0.0,
                           "maximum_activation_absolute_error": 0.0, "maximum_activation_scaled_error": 0.0}}

    def discovery(self, *args, output=None, replay=None, **kwargs):
        self.events.append("discovery")
        result = self.phase("discovery", not self.fail_discovery)
        if output is not None:
            write_json(Path(output) / "result.json", result)
        return result

    def choose(self, records, protocol):
        self.selection_calls += 1
        self.events.append("selection")
        return copy.deepcopy(self.selection)

    def validation(self, *args, output=None, replay=None, **kwargs):
        self.validation_calls += 1
        parent = (Path(output) if output is not None else Path(replay)).parent
        frozen = read_json(parent / "selection.json")
        self.assertEqual(frozen, self.selection)
        self.assertEqual(digest(parent / "selection.json")["sha256"],
                         hashlib.sha256(canonical(self.selection)).hexdigest())
        self.events.append("validation")
        result = self.phase("validation")
        if output is not None:
            write_json(Path(output) / "result.json", result)
        return result

    def run_fixture(self):
        output = self.base / "run"
        result = runner.run_attention("model", "protocol", output)
        return output, result

    def rewrite_and_reseal(self, output, name, mutation):
        # Deliberately construct internally consistent but scientifically forged
        # evidence. Replay must reject it even without an external receipt pin.
        manifest = read_json(output / "manifest.json")
        value = read_json(output / name)
        mutation(value)
        (output / name).unlink()
        write_json(output / name, value)
        (output / "manifest.json").unlink()
        seal(output, manifest["context"])

    def test_selection_written_and_hashed_before_validation(self):
        output, result = self.run_fixture()
        self.assertEqual(self.events, ["discovery", "selection", "validation"])
        self.assertEqual(result["counts"]["candidate_total"], 948)
        self.assertEqual(result["counts"]["reference_total"], 180)
        self.assertEqual(result["selection_sha256"], digest(output / "selection.json")["sha256"])
        replay = runner.replay_attention(output, "model", result["manifest_sha256"])
        self.assertEqual(replay["status"], "ATTENTION_NUMERIC_REPLAY_MATCH")
        self.assertTrue(replay["same_source_files"])

    def test_failed_control_stops_selection_even_when_numeric_parity_passes(self):
        self.fail_discovery = True
        output, result = self.run_fixture()
        self.assertEqual(result["status"], "INCONCLUSIVE")
        self.assertEqual(self.selection_calls, 0)
        self.assertEqual(self.validation_calls, 0)
        self.assertFalse((output / "selection.json").exists())
        self.assertFalse((output / "validation").exists())

    def test_none_is_frozen_without_replacement_or_validation(self):
        self.selection.update(status="NO_ELIGIBLE_HEAD", selected_site=None)
        output, result = self.run_fixture()
        self.assertEqual(result["status"], "MEASURED")
        self.assertEqual(self.validation_calls, 0)
        self.assertIsNone(read_json(output / "selection.json")["selected_site"])
        replay = runner.replay_attention(output, "model")
        self.assertFalse(replay["validation_replayed"])

    def test_forged_skip_flag_cannot_skip_required_replay(self):
        output, _ = self.run_fixture()
        self.rewrite_and_reseal(output, "result.json", lambda value: value.update(validation_executed=False))
        with self.assertRaisesRegex(ValueError, "validation_executed"):
            runner.replay_attention(output, "model")
        self.assertEqual(self.validation_calls, 2)

    def test_changed_selection_rejected_before_validation(self):
        output, _ = self.run_fixture()
        self.rewrite_and_reseal(output, "selection.json", lambda value: value.update(selected_site=None))
        with self.assertRaisesRegex(ValueError, "selection differs"):
            runner.replay_attention(output, "model")
        self.assertEqual(self.validation_calls, 1)

    def test_forged_top_level_scientific_summary_rejected(self):
        output, _ = self.run_fixture()
        self.rewrite_and_reseal(output, "result.json", lambda value: value["validation_summary"].update(
            descriptive_criteria_met=False))
        with self.assertRaisesRegex(ValueError, "descriptive_criteria_met"):
            runner.replay_attention(output, "model")

    def test_tiny_configuration_change_rejected_exactly(self):
        output, _ = self.run_fixture()
        self.rewrite_and_reseal(output, "config.json", lambda value: value.update(epsilon=1e-5+1e-12))
        with self.assertRaisesRegex(ValueError, "exact pinned input"):
            runner.replay_attention(output, "model")
        self.assertEqual(self.validation_calls, 1)

    def test_success_with_short_or_retyped_counts_is_rejected(self):
        stage = self.phase("discovery")
        stage["counts"]["candidate_total"] = 875
        with self.assertRaisesRegex(ValueError, "forward-pass counts"):
            runner._selection(stage, self.protocol)
        stage = self.phase("discovery")
        stage["counts"]["candidate_baseline"] = 12.0
        with self.assertRaisesRegex(ValueError, "forward-pass counts"):
            runner._selection(stage, self.protocol)

    def test_forged_execution_order_rejected(self):
        output, _ = self.run_fixture()
        self.rewrite_and_reseal(output, "execution-order.json", lambda value: value["events"].reverse())
        with self.assertRaisesRegex(ValueError, "phase order"):
            runner.replay_attention(output, "model")


if __name__ == "__main__":
    unittest.main()

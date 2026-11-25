import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from neuralscope.evidence import canonical
from neuralscope.study import PATTERNS, assess_behavior, build_repetition_study, write_registration


class FixedTokenizer:
    def __init__(self, encoding_object=False):
        words = sorted({word for _, _, *triple in PATTERNS for word in triple})
        self.vocabulary = {word: i + 1 for i, word in enumerate(words)}
        self.calls = []
        self.encoding_object = encoding_object

    def encode(self, text, add_special_tokens):
        if add_special_tokens:
            raise AssertionError("study must not add special tokens")
        self.calls.append(text)
        ids = [self.vocabulary[word] for word in text.split()]
        if self.encoding_object:
            return type("Encoding", (), {"ids": ids})()
        return ids


def registration():
    config = {"model_type": "gpt2", "n_layer": 6, "n_head": 12, "n_embd": 768, "vocab_size": 50257}
    pin = {"repo_id": "distilbert/distilgpt2", "revision": "a" * 40,
           "files": {name: {"bytes": 1, "sha256": "b" * 64} for name in
                     ("config.json", "model.safetensors", "tokenizer.json")}}
    return build_repetition_study(FixedTokenizer(), config, pin), config, pin


def result_for(spec, *, clean=1.0, corrupt=-1.0, negative=False):
    sites = spec["sites"]
    rows = []
    gap = clean-corrupt
    valid = gap > max(spec["minimum_gap"], 1e-5 * max(abs(clean), abs(corrupt), 1))
    for case in spec["cases"]:
        interventions = []
        for i, site in enumerate(sites):
            effect = (i+1) / 10 * (-1 if negative else 1)
            interventions.append({"site": site, "restored_margin": corrupt+gap*effect,
                                  "normalized_restoration": effect if valid else None})
        rows.append({"id": case["id"], "split": case["split"], "clean_margin": clean,
                     "corrupt_margin": corrupt, "baseline_gap": gap, "normalization_valid": valid,
                     "interventions": interventions})
    return {"schema": "wolftrap.neuralscope.local-result/v1", "cases": rows,
            "selected_site_using_discovery_only": sites[-1] if valid and not negative else None}


class StudyTests(unittest.TestCase):
    def test_fixed_spec_encodes_all_cases_without_inference(self):
        expected, config, pin = registration()
        tok = FixedTokenizer(encoding_object=True)
        actual = build_repetition_study(tok, config, pin)
        self.assertEqual(actual, expected)
        self.assertEqual(len(tok.calls), 24)
        self.assertFalse(actual["builder_performs_inference"])
        self.assertEqual([c["split"] for c in actual["cases"]["cases"]], ["discovery"]*3+["validation"]*3)
        self.assertTrue(all(c["positions"] == [4] for c in actual["cases"]["cases"]))
        self.assertEqual(actual["protocol"]["study_forward_passes"], 192)
        self.assertEqual(actual["reference_comparison"]["total_reference_forward_passes"], 69)
        self.assertEqual(actual["reference_comparison"]["intervention_case"], "repeat_colors")

    def test_invalid_tokenization_stops_instead_of_dropping_case(self):
        _, config, pin = registration()
        class SplitTokenizer(FixedTokenizer):
            def encode(self, text, add_special_tokens):
                ids = super().encode(text, add_special_tokens)
                return ids + [999] if "Paris" in text else ids
        with self.assertRaisesRegex(ValueError, "single-token words: cities"):
            build_repetition_study(SplitTokenizer(), config, pin)

    def test_wrong_or_incomplete_provenance_rejected(self):
        _, config, pin = registration()
        for field, value in (("repo_id", "another/model"), ("revision", "main"), ("files", {})):
            wrong = copy.deepcopy(pin)
            wrong[field] = value
            with self.assertRaises(ValueError):
                build_repetition_study(FixedTokenizer(), config, wrong)

    def test_pin_is_copied_and_registration_refuses_overwrite(self):
        spec, _, pin = registration()
        pin["files"]["tokenizer.json"]["sha256"] = "c"*64
        self.assertEqual(spec["model_identity"]["files"]["tokenizer.json"]["sha256"], "b"*64)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/"registration.json"
            digest = write_registration(path, spec)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
            self.assertEqual(path.read_bytes(), canonical(spec))
            with self.assertRaises(FileExistsError):
                write_registration(path, spec)

    def test_positive_contrast_does_not_imply_both_answer_preferences(self):
        spec, _, _ = registration()
        report = assess_behavior(result_for(spec["cases"], clean=1.0, corrupt=0.5), spec)
        self.assertEqual(report["split_summary"]["validation"]["positive_normalizable_contrasts"], 3)
        self.assertEqual(report["split_summary"]["validation"]["both_answer_preferences_present"], 0)
        self.assertTrue(all(row["clean_prefers_target"] for row in report["cases"]))
        self.assertTrue(all(not row["corrupt_prefers_alternative"] for row in report["cases"]))

    def test_validation_does_not_choose_selected_site(self):
        spec, _, _ = registration()
        result = result_for(spec["cases"])
        for row in result["cases"][3:]:
            row["interventions"][0]["restored_margin"] = 19.0
            row["interventions"][0]["normalized_restoration"] = 10.0
            row["interventions"][-1]["restored_margin"] = -1.8
            row["interventions"][-1]["normalized_restoration"] = -0.4
        report = assess_behavior(result, spec)
        self.assertEqual(report["selected_site"], "blocks.5.mlp_out")
        self.assertAlmostEqual(report["selected_validation_mean"], -0.4)
        self.assertEqual(report["case_count"], 6)

    def test_negative_discovery_effects_select_nothing_and_are_retained(self):
        spec, _, _ = registration()
        report = assess_behavior(result_for(spec["cases"], negative=True), spec)
        self.assertIsNone(report["selected_site"])
        self.assertTrue(all(row["discovery_mean"] < 0 for row in report["tested_sites"]))
        self.assertEqual(report["case_count"], 6)

    def test_zero_baseline_gap_is_retained_but_not_normalized(self):
        spec, _, _ = registration()
        report = assess_behavior(result_for(spec["cases"], clean=0.0, corrupt=0.0), spec)
        self.assertIsNone(report["selected_site"])
        self.assertTrue(all(row["discovery_mean"] is None for row in report["tested_sites"]))
        self.assertEqual(report["case_count"], 6)

    def test_omitted_case_site_or_changed_split_rejected(self):
        spec, _, _ = registration()
        result = result_for(spec["cases"])
        result["cases"].pop()
        with self.assertRaisesRegex(ValueError, "every registered case"):
            assess_behavior(result, spec)
        result = result_for(spec["cases"])
        result["cases"][0]["interventions"].pop()
        with self.assertRaisesRegex(ValueError, "every registered intervention"):
            assess_behavior(result, spec)
        result = result_for(spec["cases"])
        result["cases"][0]["split"] = "validation"
        with self.assertRaisesRegex(ValueError, "split assignments"):
            assess_behavior(result, spec)

    def test_forged_normalization_or_nonfinite_margin_rejected(self):
        spec, _, _ = registration()
        result = result_for(spec["cases"])
        result["cases"][0]["interventions"][0]["normalized_restoration"] = 1.0
        with self.assertRaisesRegex(ValueError, "normalization differs"):
            assess_behavior(result, spec)
        result = result_for(spec["cases"])
        result["cases"][0]["clean_margin"] = float("nan")
        with self.assertRaisesRegex(ValueError, "invalid baseline"):
            assess_behavior(result, spec)


if __name__ == "__main__":
    unittest.main()

import unittest

from neuralscope.pretrained_report import render_pretrained_report


class PretrainedReportTests(unittest.TestCase):
    def registration(self):
        return {"model_identity": {}, "cases": {"minimum_gap": 0.05, "cases": [
            {"id": "fixed", "split": "validation", "clean_text": " red blue red blue red",
             "corrupt_text": " red green red green red", "target_text": " blue", "alternative_text": " green",
             "clean_ids": [1,2,1,2,1], "corrupt_ids": [1,3,1,3,1], "target_id":2, "alternative_id":3, "positions":[4]}]},
            "reference_comparison": {"intervention_case": "fixed", "intervention_sites": ["blocks.0.mlp_out"],
                "intervention_operations": ["restore"], "full_logit_max_abs_error": 0.001,
                "full_logit_rmse": 0.0001, "activation_atol": 0.0002, "activation_rtol": 0.0002,
                "self_patch_margin_atol": 0.000001}}

    def test_failed_parity_and_absent_study_render_honestly(self):
        result = {"status": "INCONCLUSIVE", "parity": {"status":"FAIL"}, "study": None,
                  "study_executed":False, "api_requests":0,"api_credit_spent_usd":0}
        page = render_pretrained_report(result, self.registration(), None)
        self.assertIn("Reference mismatch: interpretation stopped", page)
        self.assertIn("Study not executed", page)
        self.assertIn("NOT EXECUTED", page)
        self.assertNotIn("Selected-site validation mean", page)
        self.assertIn(" red blue red blue red", page)

    def test_untrusted_text_escaped_in_all_report_areas(self):
        attack = '<script>alert("attack")</script>'
        reg = self.registration()
        reg["cases"]["cases"][0]["clean_text"] = attack
        reg["reference_comparison"]["intervention_case"] = attack
        reg["reference_comparison"]["intervention_sites"] = [attack]
        result = {"version":attack, "protocol_sha256":attack,"parity":{"status":attack},
                  "model":{"repo_id":attack,"revision":attack,"files":{attack:{"bytes":attack,"sha256":attack}}},
                  "reference":{"implementation":attack,"modeling_gpt2_sha256":attack}}
        page = render_pretrained_report(result, reg, None)
        self.assertNotIn("<script>",page)
        self.assertIn("&lt;script&gt;",page)
        self.assertIn("default-src 'none'",page)
        self.assertNotIn('src="http',page)
        self.assertNotIn('href="http',page)

    def test_negative_validation_is_retained_and_not_presented_as_probability(self):
        site = "blocks.0.mlp_out"
        stats = {"mean_restoration": 0.7,"usable_cases":1,"cases":1,"self_patch_max_abs_delta":0.0}
        validation = {**stats,"mean_restoration":-0.3}
        study = {"status":"MEASURED","self_patch_controls_pass":True,
                 "site_summary":[{"site":site,"discovery":stats,"validation":validation}],
                 "cases":[{"id":"fixed","split":"validation","clean_margin":1.0,"corrupt_margin":-1.0,
                           "baseline_gap":2.0,"normalization_valid":True,"interventions":[{
                               "site":site,"restored_margin":-1.6,"normalized_restoration":-0.3,
                               "normalized_reverse":0.1,"ablated_margin":0.2,"self_patch_max_abs_delta":0.0}]}]}
        result = {"parity":{"status":"PASS"},"study":{"selected_site":site,
                  "selected_validation_mean":-0.3,"selected_validation_usable_cases":1,"selected_validation_cases":1}}
        page = render_pretrained_report(result,self.registration(),study)
        self.assertIn("-0.3",page)
        self.assertIn("Every validation case at the selected site",page)
        self.assertIn("not percentages of safety",page)
        self.assertIn("Largest self-copy",page)


if __name__ == "__main__":
    unittest.main()

import copy
import math
import re
import unittest

from neuralscope.attention_report import render_attention_report, _condition_summary, _heatmap


class AttentionReportTests(unittest.TestCase):
    def fixtures(self):
        site = "blocks.5.attn.head.11"
        cases = []
        for split, groups in (("discovery", ("fruit", "weather", "transport")),
                              ("validation", ("drinks", "metals", "royalty"))):
            for group in groups:
                for condition in ("repeat", "control"):
                    for orientation in ("forward", "reverse"):
                        cases.append({"id": "_".join((group, condition, orientation)),
                                      "group_id": group, "split": split, "condition": condition,
                                      "orientation": orientation, "clean_text": " A B A B A", "changed_text": " A C A C A",
                                      "clean_ids": [1,2,1,2,1], "changed_ids": [1,3,1,3,1], "target_id":2,"alternative_id":3,
                                      "target_text":" B","alternative_text":" C","positions":[4]})
        ranking = [{"site":f"blocks.{layer}.attn.head.{head}","specificity_score":(layer*12+head-35.5)/100,
                    "repeated_mean":0.4,"control_mean":0.1,
                    "orientation_means":{"forward":{"repeated":0.3},"reverse":{"repeated":0.5}},
                    "positive_group_specificity_count":3,
                    "eligible":layer>=3,"reasons":[] if layer>=3 else ["specificity_floor_met"]}
                   for layer in range(6) for head in range(12)]
        ranking.sort(key=lambda row:-row["specificity_score"])
        selection={"status":"SELECTED","selected_site":site,"ranking":ranking}
        protocol={"cases":cases,"selection":{"minimum_specificity_score":0.01,"rule":"fixed discovery only"},
                  "model_identity":{"repo_id":"distilbert/distilgpt2","revision":"a"*40,"files":{
                      "model.safetensors":{"bytes":352824413,"sha256":"b"*64}}}}
        def make_row(case, operation="restore"):
            before={"target_id":2,"alternative_id":3,"target_rank":10,"top_id":7,"top_token":" other","target_is_global_top":False}
            result={**before,"target_rank":6}
            margin=0.2 if case["condition"]=="repeat" else -1.2
            if operation=="self_changed": margin=-1.0
            if operation=="self_clean": margin=1.0
            if operation=="reverse": margin=-0.3
            if operation=="ablate": margin=0.0
            recipient=-1.0 if operation in ("restore","self_changed") else 1.0
            row={**case,"site":site,"operation":operation,"status":"PASS","clean_margin":1.0,"changed_margin":-1.0,
                 "baseline_gap":2.0,"result_margin":margin,"effect_delta_from_recipient":margin-recipient,
                 "candidate_clean":{**before,"target_rank":2},"candidate_changed":before,"candidate_result":result,
                 "earlier_logits_unchanged":True}
            if operation=="restore": row.update(restored_margin=margin,restoration_delta=margin+1.0)
            if operation.startswith("self_"):row["self_margin_delta"]=0.0
            return row
        discovery={"status":"PASS","records":[make_row(case) for case in cases if case["split"]=="discovery"],
                   "parity":{"status":"PASS","baseline_comparisons":12,"intervention_comparisons":72,
                             "maximum_logit_absolute_error":0.0001,"maximum_logit_rmse":0.00001,
                             "maximum_activation_scaled_error":0.2,"reference_hooks_bitwise_invariant":True},
                   "counts":{"candidate_total":876,"reference_total":96}}
        validation={"status":"PASS","records":[make_row(case,operation) for case in cases if case["split"]=="validation"
                    for operation in ("restore","reverse","self_clean","self_changed","ablate")],
                    "parity":{**discovery["parity"],"intervention_comparisons":60},
                    "counts":{"candidate_total":72,"reference_total":84}}
        result={"version":"0.3.0a1","status":"MEASURED","selection":selection,
                "selection_sha256":"c"*64,"protocol_sha256":"d"*64,
                "validation_summary":{"descriptive_criteria_met":False,"specificity_score":-0.2,
                                      "repeated_mean":0.1,"control_mean":0.3,"positive_group_specificity_count":1,
                                      "threshold_flags":{"specificity_floor_met":False}},
                "learned_parameter_elements":81912576,"reference":{"transformers":"test","torch":"test"},
                "api_requests":0,"api_credit_spent_usd":0,"network_requests_during_experiment":0}
        return result,protocol,discovery,validation

    def test_full_signed_heatmap_has_72_cells_without_clipping(self):
        result,_,_,_=self.fixtures()
        page=_heatmap(result["selection"]["ranking"],result["selection"]["selected_site"])
        self.assertEqual(page.count('class="heat-cell'),72)
        self.assertEqual(len(re.findall(r'data-site="blocks\.\d\.attn\.head\.\d+"',page)),72)
        self.assertIn('-0.355',page)
        self.assertIn('+0.355',page)
        self.assertIn('background:rgb(126,65,96)',page)
        self.assertIn('background:rgb(26,111,92)',page)
        self.assertEqual(page.count('class="heat-cell chosen"'),1)
        self.assertIn('symmetric around zero',page)

    def test_margin_flip_is_not_reported_as_global_top_change(self):
        _,_,_,validation=self.fixtures()
        rows=[row for row in validation["records"] if row["operation"]=="restore"]
        summaries=_condition_summary(rows)
        self.assertEqual(summaries[0][0],"repeat")
        self.assertEqual(summaries[0][3],"6/6")
        self.assertEqual(summaries[0][4],"0/6")
        self.assertEqual(summaries[0][5],"0/6")
        self.assertEqual(summaries[1][3],"0/6")

    def test_top_score_tie_uses_recorded_target_identity(self):
        _,_,_,validation=self.fixtures()
        row=copy.deepcopy(validation["records"][0])
        row.pop("target_id")
        row["candidate_result"]["target_is_global_top"]=True
        row["candidate_result"]["global_top_tie_count"]=2
        row["candidate_result"]["top_id"]=7
        summary=_condition_summary([row])[0]
        self.assertEqual(summary[4],"0/1")
        self.assertEqual(summary[5],"1/1")

    def test_negative_validation_is_retained_with_unmet_flags(self):
        result,protocol,discovery,validation=self.fixtures()
        page=render_attention_report(result,protocol,discovery,validation)
        self.assertIn('Descriptive validation criteria: Not met.',page)
        self.assertIn('-0.2',page)
        self.assertIn('at least two of the three groups',page)
        self.assertIn('three groups and their two orientations',page)
        self.assertIn('All 72 head scores',page)
        self.assertIn('All selected-head validation controls',page)
        self.assertIn('Target newly shares the top score',page)
        self.assertIn('1 and sharing the top score include exact ties',page)

    def test_no_selection_and_incomplete_selection_are_distinguished(self):
        result,protocol,discovery,_=self.fixtures()
        result["selection"]["status"]="NO_ELIGIBLE_HEAD"
        result["selection"]["selected_site"]=None
        page=render_attention_report(result,protocol,discovery,None)
        self.assertIn('No eligible head selected',page)
        self.assertIn('Validation not executed.',page)
        self.assertNotIn('Complete validation restoration records',page)
        result["selection"]={}
        discovery["status"]="FAIL"
        page=render_attention_report(result,protocol,discovery,None)
        self.assertIn('Selection not completed',page)
        self.assertNotIn('No eligible head selected',page)
        self.assertIn('Discovery did not produce a completed selection.',page)

    def test_failed_validation_cannot_get_unqualified_claim(self):
        result,protocol,discovery,validation=self.fixtures()
        validation["status"]="FAIL"
        page=render_attention_report(result,protocol,discovery,validation)
        self.assertIn('do not support a qualified validation claim',page)
        self.assertIn('Validation: FAIL',page)

    def test_untrusted_text_escaped_everywhere_no_active_resources(self):
        result,protocol,discovery,validation=self.fixtures()
        attack='<script>alert("test")</script><img src=x onerror="alert(1)">'
        result["version"]=attack
        result["protocol_sha256"]=attack
        result["selection_sha256"]=attack
        result["reference"]["torch"]=attack
        result["selection"]["ranking"][0]["reasons"]=[attack]
        protocol["cases"][0]["clean_text"]=attack
        protocol["selection"]["rule"]=attack
        protocol["model_identity"]["repo_id"]=attack
        validation["records"][0]["candidate_result"]["top_token"]=attack
        page=render_attention_report(result,protocol,discovery,validation)
        self.assertNotIn('<script',page)
        self.assertNotIn('<img',page)
        self.assertNotIn('<iframe',page)
        self.assertIn('&lt;script&gt;',page)
        self.assertIn("default-src 'none'",page)
        self.assertNotIn('src="http',page)
        self.assertNotIn('@import',page)
        self.assertIn('width=device-width',page)
        self.assertIn('role="region"',page)

    def test_nonfinite_heat_values_do_not_enter_styles(self):
        page=_heatmap([{"site":"blocks.0.attn.head.0","specificity_score":math.nan}],None)
        self.assertIn('invalid numeric value',page)
        self.assertNotIn('rgb(nan',page)
        self.assertNotIn('rgb(inf',page)


if __name__=='__main__':
    unittest.main()

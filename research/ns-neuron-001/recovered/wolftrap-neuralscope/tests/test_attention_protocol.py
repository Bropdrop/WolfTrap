import copy
import hashlib
from pathlib import Path
import tempfile
import unittest

from neuralscope.attention_protocol import (
    CONDITIONS, GROUPS, OPERATIONS, ORIENTATIONS, SITES,
    assess_validation, build_attention_protocol, select_head, write_protocol,
)


class FixedTokenizer:
    def __init__(self):
        self.words = {word: i+1 for i, word in enumerate(sorted({w for _, _, *triple in GROUPS for w in triple}))}
        self.calls = []

    def encode(self, text, add_special_tokens=False):
        if add_special_tokens:
            raise AssertionError("special tokens must remain disabled")
        self.calls.append(text)
        return type("Encoding", (), {"ids": [self.words[word] for word in text.split()]})()


def build():
    config = {"model_type":"gpt2", "n_layer":6, "n_head":12, "n_embd":768, "vocab_size":50257}
    pin = {"repo_id":"distilbert/distilgpt2", "revision":"a"*40,
           "files":{name:{"bytes":1, "sha256":"b"*64} for name in
                    ("config.json", "model.safetensors", "tokenizer.json")}}
    tokenizer = FixedTokenizer()
    return build_attention_protocol(tokenizer, config, pin), tokenizer, config, pin


def discovery(protocol, effects=None, repeat_gap=2.0, control_gap=2.0):
    effects = effects or {}
    rows = []
    for case in protocol["cases"]:
        if case["split"] != "discovery":
            continue
        gap = repeat_gap if case["condition"] == "repeat" else control_gap
        clean, changed = gap/2, -gap/2
        for site in SITES:
            effect = effects.get((site, case["condition"], case["orientation"]),
                                 effects.get((site, case["condition"]), 0.0))
            rows.append({key:case[key] for key in ("id","group_id","split","condition","orientation")}
                        | {"site":site,"operation":"restore","clean_margin":clean,"changed_margin":changed,
                           "baseline_gap":gap,"restored_margin":changed+effect,"restoration_delta":effect})
    return rows


def validation(protocol, site, *, group_effects=None, self_error=0.0):
    group_effects = group_effects or {}
    rows = []
    for case in protocol["cases"]:
        if case["split"] != "validation":
            continue
        effect = group_effects.get((case["group_id"],case["condition"],case["orientation"]),
                                   0.08 if case["condition"] == "repeat" else 0.01)
        for operation in OPERATIONS:
            result = {"restore":-1+effect, "reverse":1-effect,
                      "self_clean":1+self_error, "self_changed":-1, "ablate":0}[operation]
            row = {key:case[key] for key in ("id","group_id","split","condition","orientation")}
            row.update(site=site, operation=operation, clean_margin=1.0, changed_margin=-1.0,
                       baseline_gap=2.0, result_margin=result)
            if operation == "restore":
                row.update(restored_margin=result,restoration_delta=effect)
            rows.append(row)
    return rows


class AttentionProtocolTests(unittest.TestCase):
    def test_fixed_counterbalance_and_frequency_matching_without_inference(self):
        protocol, tokenizer, _, _ = build()
        self.assertFalse(protocol["builder_performs_inference"])
        self.assertEqual(len(tokenizer.calls), 42)
        self.assertEqual(len(protocol["cases"]), 24)
        self.assertEqual(protocol["sites"], list(SITES))
        cases = {(c["group_id"],c["condition"],c["orientation"]):c for c in protocol["cases"]}
        for group, *_ in GROUPS:
            for condition in CONDITIONS:
                forward, reverse = (cases[(group,condition,o)] for o in ORIENTATIONS)
                self.assertEqual(forward["clean_ids"],reverse["changed_ids"])
                self.assertEqual(forward["changed_ids"],reverse["clean_ids"])
                self.assertEqual(forward["target_id"],reverse["alternative_id"])
                self.assertEqual(forward["alternative_id"],reverse["target_id"])
            for side in ("clean_ids","changed_ids"):
                self.assertEqual(sorted(cases[(group,"repeat","forward")][side]),
                                 sorted(cases[(group,"control","forward")][side]))

    def test_counts_and_closed_selection_before_validation_policy(self):
        protocol, _, _, _ = build()
        counts = protocol["forward_pass_counts"]
        self.assertEqual(counts["discovery_candidate_total"], 12+3*2*2*72)
        self.assertEqual(counts["maximum_candidate_total"], 948)
        self.assertEqual(counts["maximum_reference_total"], 180)
        self.assertEqual(counts["maximum_combined_total"], 1128)
        self.assertIn("before any validation forward",protocol["selection"]["validation_access"])
        self.assertFalse(protocol["evidence_policy"]["orientations_independent"])

    def test_failed_tokenization_rejects_entire_protocol(self):
        _, tokenizer, config, pin = build()
        encode = tokenizer.encode
        def changed(text, add_special_tokens=False):
            out = encode(text,add_special_tokens)
            if "copper" in text:
                out.ids.append(999)
            return out
        tokenizer.encode = changed
        with self.assertRaisesRegex(ValueError,"single tokens: metals"):
            build_attention_protocol(tokenizer, config, pin)

    def test_frozen_protocol_digest_and_no_overwrite(self):
        protocol, _, _, _ = build()
        with tempfile.TemporaryDirectory() as temporary:
            path=Path(temporary)/"protocol.json"
            receipt=write_protocol(path,protocol)
            self.assertEqual(receipt,hashlib.sha256(path.read_bytes()).hexdigest())
            with self.assertRaises(FileExistsError):
                write_protocol(path,protocol)

    def test_selection_ranks_specificity_not_raw_repeat_effect_and_ties_are_fixed(self):
        protocol, _, _, _ = build()
        effects={(SITES[0],"repeat"):0.9,(SITES[0],"control"):0.89,
                 (SITES[1],"repeat"):0.08,(SITES[1],"control"):0.01,
                 (SITES[2],"repeat"):0.08,(SITES[2],"control"):0.01}
        result=select_head(discovery(protocol,effects),protocol)
        self.assertEqual(result["selected_site"],SITES[1])
        self.assertEqual(result["heads_considered"],72)
        self.assertEqual(result["discovery_records"],864)
        self.assertEqual(len(result["ranking"]),72)
        self.assertFalse(result["selection_uses_validation"])

    def test_one_direction_failure_rejects_positive_aggregate(self):
        protocol, _, _, _ = build()
        effects={(SITES[0],"repeat","forward"):0.1,(SITES[0],"repeat","reverse"):-0.01}
        result=select_head(discovery(protocol,effects),protocol)
        self.assertEqual(result["status"],"NO_ELIGIBLE_HEAD")
        row=next(r for r in result["ranking"] if r["site"]==SITES[0])
        self.assertGreater(row["specificity_score"],0.01)
        self.assertIn("both_orientation_repeated_means_positive",row["reasons"])

    def test_repeat_gap_floor_is_strict_but_control_gap_can_be_negative(self):
        protocol, _, _, _ = build()
        effects={(SITES[0],"repeat"):0.08,(SITES[0],"control"):0.01}
        self.assertIsNone(select_head(discovery(protocol,effects,repeat_gap=0.05),protocol)["selected_site"])
        result=select_head(discovery(protocol,effects,control_gap=-2),protocol)
        self.assertEqual(result["selected_site"],SITES[0])

    def test_missing_duplicate_nonfinite_or_heldout_discovery_data_rejected(self):
        protocol, _, _, _ = build()
        for mutate in (
            lambda rows: rows.pop(),
            lambda rows: rows.__setitem__(0,copy.deepcopy(rows[1])),
            lambda rows: rows[0].__setitem__("restoration_delta",float("nan")),
            lambda rows: rows[0].__setitem__("group_id","drinks"),
            lambda rows: rows[0].__setitem__("restoration_delta",2.0),
            lambda rows: rows[0].__setitem__("status","FAIL"),
        ):
            rows=discovery(protocol)
            mutate(rows)
            with self.assertRaises(ValueError):
                select_head(rows,protocol)

    def test_counterbalanced_margins_must_match_swapped_inputs(self):
        protocol, _, _, _ = build()
        rows=discovery(protocol)
        for row in rows:
            if row["group_id"]=="fruit" and row["condition"]=="repeat" and row["orientation"]=="reverse":
                row["clean_margin"]=2.0
                row["changed_margin"]=0.0
                row["restored_margin"]=0.0
        with self.assertRaisesRegex(ValueError,"counterbalanced baseline"):
            select_head(rows,protocol)

    def test_validation_keeps_negative_groups_and_uses_frozen_head(self):
        protocol, _, _, _ = build()
        changes={("metals","repeat",o):-0.02 for o in ORIENTATIONS}
        result=assess_validation(validation(protocol,SITES[7],group_effects=changes),protocol,SITES[7])
        self.assertEqual(result["selected_site"],SITES[7])
        self.assertEqual(result["positive_group_specificity_count"],2)
        self.assertEqual(result["records"],60)
        self.assertEqual(len(result["cases"]),12)
        self.assertFalse(result["replacement_selection"])
        self.assertTrue(result["descriptive_criteria_met"])
        metal=next(g for g in result["group_effects"] if g["group_id"]=="metals")
        self.assertLess(metal["specificity_score"],0)

    def test_validation_requires_two_positive_groups_not_only_positive_grand_mean(self):
        protocol, _, _, _ = build()
        changes={(group,"repeat",o):(-0.02 if group!="drinks" else 0.3)
                 for group in ("drinks","metals","royalty") for o in ORIENTATIONS}
        result=assess_validation(validation(protocol,SITES[7],group_effects=changes),protocol,SITES[7])
        self.assertGreater(result["specificity_score"],0.01)
        self.assertFalse(result["descriptive_criteria_met"])
        self.assertEqual(result["positive_group_specificity_count"],1)

    def test_self_copy_failure_and_changed_head_do_not_hide(self):
        protocol, _, _, _ = build()
        result=assess_validation(validation(protocol,SITES[4],self_error=0.01),protocol,SITES[4])
        self.assertFalse(result["threshold_flags"]["self_copy_controls_pass"])
        self.assertFalse(result["descriptive_criteria_met"])
        rows=validation(protocol,SITES[4])
        rows[0]["site"]=SITES[5]
        with self.assertRaisesRegex(ValueError,"selected head"):
            assess_validation(rows,protocol,SITES[4])

    def test_no_selection_skips_validation_and_rejects_hidden_execution(self):
        protocol, _, _, _ = build()
        result=assess_validation([],protocol,None)
        self.assertEqual(result["status"],"NOT_RUN_NO_SELECTION")
        self.assertIsNone(result["descriptive_criteria_met"])
        with self.assertRaisesRegex(ValueError,"previously selected"):
            assess_validation(validation(protocol,SITES[0]),protocol,None)


if __name__ == "__main__":
    unittest.main()

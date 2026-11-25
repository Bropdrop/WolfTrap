"""Offline HTML for the fixed attention-head discovery and validation study.

This renderer displays supplied records; it does not verify their authenticity or
recompute inference. Dynamic text is escaped, and no scripts or remote assets are
needed. The signed heatmap shows the full numerical range without clipping.
"""
from __future__ import annotations

import html
import math
import re


_SITE = re.compile(r"blocks\.(\d+)\.attn\.head\.(\d+)\Z")


def _esc(value):
    return html.escape(str(value), quote=True)


def _finite(value):
    return type(value) in (float, int) and math.isfinite(value)


def _num(value, *, signed=False):
    if value is None:
        return "not available"
    if _finite(value):
        return format(value, "+.6g" if signed else ".6g")
    if type(value) in (float, int):
        return "invalid numeric value"
    return str(value)


def _yes(value):
    return "Yes" if value is True else "No" if value is False else "not available"


def _table(headers, rows, caption, *, css_class=""):
    return ('<div class="scroll ' + _esc(css_class) + '" role="region" aria-label="'
            + _esc(caption) + '" tabindex="0"><table><caption>' + _esc(caption)
            + '</caption><thead><tr>' + ''.join('<th scope="col">' + _esc(item) + '</th>' for item in headers)
            + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join('<td>' + _esc(value) + '</td>' for value in row)
                                             + '</tr>' for row in rows)
            + '</tbody></table></div>')


def _cases(protocol):
    cases = protocol.get("cases") or []
    return cases.get("cases", []) if isinstance(cases, dict) else cases


def _records(stage, site=None, operation=None):
    return [row for row in ((stage or {}).get("records") or [])
            if (site is None or row.get("site") == site)
            and (operation is None or row.get("operation") == operation)]


def _delta(row):
    if "restoration_delta" in row:
        return row["restoration_delta"]
    return row.get("effect_delta_from_recipient")


def _mean(values):
    return sum(values) / len(values) if values and all(_finite(v) for v in values) else None


def _head_name(site):
    match = _SITE.fullmatch(str(site))
    return f"Layer {match[1]} · head {match[2]}" if match else str(site)


def _heatmap(ranking, selected):
    values = [row.get("specificity_score") for row in ranking if _finite(row.get("specificity_score"))]
    scale = max((abs(value) for value in values), default=0.0)
    by_site = {row.get("site"): row for row in ranking}
    rows = []
    for layer in range(6):
        cells = ['<th scope="row">L' + str(layer) + '</th>']
        for head in range(12):
            site = f"blocks.{layer}.attn.head.{head}"
            row = by_site.get(site, {})
            value = row.get("specificity_score")
            amount = abs(value) / scale if _finite(value) and scale else 0.0
            origin = (22, 35, 44)
            endpoint = (26, 111, 92) if _finite(value) and value >= 0 else (126, 65, 96)
            rgb = tuple(round(a + amount * (b-a)) for a, b in zip(origin, endpoint))
            style = "background:rgb(" + ",".join(map(str, rgb)) + ")"
            marker = " chosen" if site == selected else ""
            label = _head_name(site) + "; repeat-minus-control delta " + _num(value, signed=True)
            label += "; eligible " + _yes(row.get("eligible"))
            if site == selected:
                label += "; selected using discovery only"
            cells.append('<td class="heat-cell' + marker + '" style="' + style
                         + '" data-site="' + site + '" title="' + _esc(label) + '" aria-label="'
                         + _esc(label) + '">' + _esc(_num(value, signed=True) if value is not None else "—") + '</td>')
        rows.append('<tr>' + ''.join(cells) + '</tr>')
    return ('<div class="scroll" role="region" aria-label="Discovery heatmap, six layers and twelve heads" tabindex="0">'
            '<table class="heatmap"><caption>Discovery: mean repetition restoration Δ minus mean control restoration Δ, in logits</caption>'
            '<thead><tr><th scope="col">Layer</th>' + ''.join('<th scope="col">H' + str(i) + '</th>' for i in range(12))
            + '</tr></thead><tbody>' + ''.join(rows) + '</tbody></table></div>'
            '<div class="legend"><span>' + _esc(_num(-scale, signed=True)) + '</span>'
            '<span class="gradient" aria-hidden="true"></span><span>' + _esc(_num(scale, signed=True)) + '</span></div>'
            '<p class="note">The continuous color scale is symmetric around zero and spans the largest absolute observed score. '
            'Numbers remain authoritative; a border identifies the frozen selection. Missing measurements use an em dash. '
            'Layer and head indices start at zero. Scroll horizontally on a narrow screen.</p>')


def _condition_summary(rows):
    summary = []
    for condition in ("repeat", "control"):
        chosen = [row for row in rows if row.get("condition") == condition]
        pair_flips = top_changes = target_becomes_top = 0
        known_pairs = known_tops = known_targets = 0
        for row in chosen:
            before, after = row.get("candidate_changed") or {}, row.get("candidate_result") or {}
            margin_before, margin_after = row.get("changed_margin"), row.get("result_margin")
            if _finite(margin_before) and _finite(margin_after):
                known_pairs += 1
                pair_flips += margin_before < 0 < margin_after
            if before.get("top_id") is not None and after.get("top_id") is not None:
                known_tops += 1
                top_changes += before["top_id"] != after["top_id"]
                target = row.get("target_id", after.get("target_id"))
                if target is not None:
                    known_targets += 1
                    was_top = before.get("target_is_global_top", before["top_id"] == target)
                    is_top = after.get("target_is_global_top", after["top_id"] == target)
                    target_becomes_top += was_top is False and is_top is True
        summary.append((condition, len(chosen), _num(_mean([_delta(row) for row in chosen]), signed=True),
                        f"{pair_flips}/{known_pairs}", f"{top_changes}/{known_tops}",
                        f"{target_becomes_top}/{known_targets}"))
    return summary


def _token(snapshot):
    if not snapshot:
        return "not available"
    identity = snapshot.get("top_id")
    text = snapshot.get("top_token")
    return str(identity) + (" " + repr(text) if text is not None else "") if identity is not None else "not available"


def _group_table(rows, caption):
    groups = {}
    for row in rows:
        key = (row.get("group_id"), row.get("orientation"))
        groups.setdefault(key, {})[row.get("condition")] = row
    output = []
    for (group, orientation), pair in groups.items():
        repeat, control = pair.get("repeat", {}), pair.get("control", {})
        r, c = _delta(repeat), _delta(control)
        difference = r-c if _finite(r) and _finite(c) else None
        output.append((group, orientation, _num(repeat.get("baseline_gap")), _num(control.get("baseline_gap")),
                       _num(r, signed=True), _num(c, signed=True), _num(difference, signed=True)))
    return _table(("Lexical group", "Orientation", "Repeat baseline gap", "Control baseline gap", "Repeat Δ", "Control Δ", "Repeat − control"),
                  output, caption)


def _case_table(rows, caption):
    output = []
    for row in rows:
        before, after = row.get("candidate_changed") or {}, row.get("candidate_result") or {}
        b, a = row.get("changed_margin"), row.get("result_margin")
        flip = ("alternative → target" if b < 0 < a else "target → alternative" if a < 0 < b else "no strict sign flip") if _finite(b) and _finite(a) else "not available"
        output.append((row.get("group_id"), row.get("orientation"), row.get("condition"),
                       _num(row.get("clean_margin")), _num(b), _num(a), _num(_delta(row), signed=True),
                       str(before.get("target_rank", "?")) + " → " + str(after.get("target_rank", "?")),
                       _token(before) + " → " + _token(after), flip))
    return _table(("Group", "Orientation", "Pattern", "Clean margin", "Changed margin", "Patched margin", "Restoration Δ", "Target rank before → after", "Top token before → after", "Pair preference"),
                  output, caption)


def _controls(validation, site):
    rows = _records(validation, site)
    self_rows = [row for row in rows if row.get("operation") in ("self_clean", "self_changed", "self_corrupt")]
    values = [row.get("self_margin_delta") for row in self_rows]
    maximum = max((abs(v) for v in values if _finite(v)), default=None)
    unchanged = [row.get("earlier_logits_unchanged") for row in rows]
    output = []
    for row in rows:
        if row.get("operation") == "restore":
            continue
        snapshot = row.get("candidate_result") or {}
        output.append((row.get("group_id"), row.get("orientation"), row.get("condition"), row.get("operation"),
                       _num(row.get("result_margin")), _num(row.get("effect_delta_from_recipient"), signed=True),
                       snapshot.get("target_rank", "not available"), _token(snapshot),
                       _num(row.get("self_margin_delta")), _yes(row.get("earlier_logits_unchanged"))))
    return ('<p>Retained self-copy operations: <b>' + str(len(self_rows)) + '</b>. Largest reported absolute self-copy margin change: <b>'
            + _esc(_num(maximum)) + '</b>. Earlier-position logit invariance: <b>'
            + _esc(str(sum(value is True for value in unchanged))) + '/' + str(len(unchanged)) + '</b> recorded operations.</p>'
            '<details><summary>Every reverse, self-copy, and zero-ablation measurement</summary>'
            + _table(("Group", "Orientation", "Pattern", "Operation", "Result margin", "Δ vs recipient", "Target rank", "Top token", "Self-copy |Δ|", "Earlier logits unchanged"),
                     output, "All selected-head validation controls") + '</details>'
            '<p class="note">Reverse patches copy the changed donor into the clean recipient; zero ablation replaces the selected contribution with zero. '
            'Their signed deltas are measured against their own recipient, not against the restoration recipient. '
            'Zero ablation may move activity outside its ordinary distribution.</p>')


def _parity_rows(stage, label):
    stage = stage or {}
    parity = stage.get("parity") or {}
    return [(label + " stage", stage.get("status", "NOT_RUN")),
            (label + " reference comparison", parity.get("status", "not available")),
            (label + " maximum logit absolute error", _num(parity.get("maximum_logit_absolute_error", parity.get("max_logit_absolute_error")))),
            (label + " maximum logit RMSE", _num(parity.get("maximum_logit_rmse", parity.get("max_logit_rmse")))),
            (label + " maximum activation scaled error", _num(parity.get("maximum_activation_scaled_error", parity.get("max_activation_scaled_error")))),
            (label + " baseline comparisons", parity.get("baseline_comparisons", "not available")),
            (label + " intervention comparisons", parity.get("intervention_comparisons", "not available")),
            (label + " hooked / unhooked baseline logits identical", _yes(parity.get("reference_hooks_bitwise_invariant"))),
            (label + " candidate forward passes", (stage.get("counts") or {}).get("candidate_total", "not available")),
            (label + " reference forward passes", (stage.get("counts") or {}).get("reference_total", "not available"))]


def render_attention_report(result, protocol, discovery, validation=None):
    """Render discovery, frozen selection, and later validation without inference."""
    selection = result.get("selection") or {}
    ranking = selection.get("ranking") or []
    selected = selection.get("selected_site")
    cases = _cases(protocol)
    model = result.get("model") or protocol.get("model_identity") or {}
    reference = result.get("reference") or {}
    status = result.get("status", "NOT_RUN")
    discovery_status = (discovery or {}).get("status", "NOT_RUN")
    validation_status = (validation or {}).get("status", "NOT_RUN")
    selection_rule = protocol.get("selection_rule") or protocol.get("selection") or {}
    selected_row = next((row for row in ranking if row.get("site") == selected), {})
    validation_summary = result.get("validation_summary") or result.get("validation_assessment") or {}
    discovery_restore = _records(discovery, selected, "restore") if selected else []
    validation_restore = _records(validation, selected, "restore") if selected else []
    examined_heads = len({row.get("site") for row in _records(discovery) if row.get("site")})
    eligible_heads = sum(row.get("eligible") is True for row in ranking)
    discovery_groups = len({case.get("group_id") for case in cases if case.get("split") == "discovery"})
    validation_groups = len({case.get("group_id") for case in cases if case.get("split") == "validation"})
    selected_text = (_head_name(selected) if selected else "No eligible head selected"
                     if selection.get("status") == "NO_ELIGIBLE_HEAD" else "Selection not completed")

    intro = ('<header><p class="eyebrow">WOLFTRAP / NEURALSCOPE ' + _esc(result.get("version", ""))
             + '</p><h1>Trace an attention head’s contribution.</h1>'
             '<p class="lead">An alternating continuation, a matched token-count control, and a selection frozen before validation. '
             'The experiment measures how replacing one head’s final-position contribution changes the next-token contrast.</p>'
             '<div class="status-line">Recorded outcome: <strong>' + _esc(status) + '</strong> · Discovery: '
             + _esc(discovery_status) + ' · Validation: ' + _esc(validation_status) + '</div>'
             '<div class="metrics"><div><span>Heads measured in discovery</span><strong>' + str(examined_heads) + '</strong></div>'
             '<div><span>Eligible under the fixed rule</span><strong>' + (str(eligible_heads) if ranking else "not evaluated") + '</strong></div>'
             '<div><span>Lexical groups</span><strong>' + str(discovery_groups) + ' + ' + str(validation_groups)
             + '</strong><small>discovery + validation; two related orientations each</small></div></div></header>')

    methods = ('<section><p class="section-label">01 / WHAT CHANGES</p><h2>A controlled pattern comparison</h2>'
               '<div class="patterns"><div><span>Alternating pattern</span><code>A B A B A → B</code><small>Changed counterpart: A C A C A</small></div>'
               '<div><span>Token-count control</span><code>A A B B A</code><small>Changed counterpart: A A C C A</small></div></div>'
               '<p>Both patterns contain the same token counts and final anchor. The control also changes token positions and distances; '
               'it still contains repeated words. Both orientations swap B and C, so their observations are related within each lexical group.</p>'
               '<p>The outcome is <b>logit(target) − logit(alternative)</b>. Restoration Δ is the patched changed-input margin minus its unpatched margin. '
               'The discovery score is the mean <b>repetition restoration Δ − control restoration Δ</b>, in raw logits. '
               'Positive and negative values are retained. This contrast is not a probability, safety score, or a unique diagnosis of an induction circuit.</p></section>')

    scan = ('<section><p class="section-label">02 / ALL REGISTERED HEADS</p><h2>The full discovery scan</h2>'
            + _heatmap(ranking, selected))
    all_rows = []
    for rank, row in enumerate(ranking, 1):
        orientations = row.get("orientation_means") or {}
        forward, reverse = orientations.get("forward") or {}, orientations.get("reverse") or {}
        all_rows.append((rank, row.get("site"), _num(row.get("specificity_score"), signed=True),
                         _num(row.get("repeated_mean"), signed=True), _num(row.get("control_mean"), signed=True),
                         _num(forward.get("repeated"), signed=True), _num(reverse.get("repeated"), signed=True),
                         _yes(row.get("eligible")), "; ".join(map(str, row.get("reasons") or [])) or "none"))
    scan += ('<details><summary>All ' + str(len(ranking)) + ' head scores, eligibility decisions, and raw effects</summary>'
             + _table(("Order", "Head", "Repeat − control", "Repeat Δ mean", "Control Δ mean", "Forward repeat mean", "Reverse repeat mean", "Eligible", "Exclusion reasons"),
                      all_rows, "Every registered head — discovery only") + '</details></section>')

    selection_section = ('<section><p class="section-label">03 / FROZEN SELECTION</p><h2>' + _esc(selected_text) + '</h2>'
                         '<div class="callout"><p>Selection status: <b>' + _esc(selection.get("status", "NOT_RECORDED"))
                         + '</b>. Discovery repeat-minus-control score: <b>' + _esc(_num(selected_row.get("specificity_score"), signed=True))
                         + '</b>.</p><p class="mono">' + _esc(selected or "NONE") + '</p></div>'
                         '<p>The fixed rule requires a score of at least 0.01 logits, mean repetition restoration of at least 0.01 logits, '
                         'strictly positive mean repetition restoration in each orientation, and every repetition discovery baseline gap above 0.05 logits. '
                         'Among eligible heads, the largest score is selected; ties use ascending layer then head index. '
                         'There is no replacement winner chosen from validation.</p>'
                         '<dl><dt>Protocol SHA-256</dt><dd>' + _esc(result.get("protocol_sha256", "not available"))
                         + '</dd><dt>Selection SHA-256</dt><dd>' + _esc(result.get("selection_sha256", "not available")) + '</dd></dl>'
                         '<p class="note">These are separate content digests. The runner freezes selection before evaluating validation inputs. '
                         'They do not establish an independent timestamp, publisher signature, or human review.</p>')
    if selection_rule:
        selection_section += '<details><summary>Exact retained selection policy</summary><pre>' + _esc(_policy_text(selection_rule)) + '</pre></details>'
    if selected:
        selection_section += _group_table(discovery_restore, "Selected-head discovery: every group and orientation")
        selection_section += ('<details><summary>Discovery margins, target ranks, and top-token changes</summary>'
                              + _case_table(discovery_restore, "Selected-head discovery restoration records") + '</details>')
    else:
        selection_section += '<p class="note">No selected-head effect is inferred. The complete discovery scan remains visible, including all ineligible and negative results.</p>'
    selection_section += '</section>'

    validation_section = '<section><p class="section-label">04 / VALIDATION AFTER SELECTION</p><h2>New lexical groups, the same selected head</h2>'
    if selected and validation is not None:
        if validation_status != "PASS":
            validation_section += '<div class="warning">Validation did not pass its comparison or control checks. The retained observations below do not support a qualified validation claim.</div>'
        criteria = validation_summary.get("descriptive_criteria_met")
        criteria_text = "Met" if criteria is True else "Not met" if criteria is False else "not available"
        comparison_rows = [
            ("Repeat-minus-control Δ", _num(selected_row.get("specificity_score"), signed=True), _num(validation_summary.get("specificity_score"), signed=True)),
            ("Mean repetition restoration Δ", _num(selected_row.get("repeated_mean"), signed=True), _num(validation_summary.get("repeated_mean"), signed=True)),
            ("Mean control restoration Δ", _num(selected_row.get("control_mean"), signed=True), _num(validation_summary.get("control_mean"), signed=True)),
            ("Groups with positive repeat-minus-control Δ", str(selected_row.get("positive_group_specificity_count", "?")) + "/3", str(validation_summary.get("positive_group_specificity_count", "?")) + "/3"),
        ]
        validation_section += ('<p>The selected head is evaluated on all predeclared validation cases. The three groups and their two orientations are kept together; '
                               'they are not six independent population samples.</p>'
                               '<div class="callout neutral"><b>Descriptive validation criteria: ' + _esc(criteria_text) + '.</b> '
                               'The frozen criteria require the registered effect floors, positive repetition means in both orientations, '
                               'positive repeat-minus-control effects in at least two of the three groups, valid repetition gaps, and self-copy controls. '
                               'These are practical thresholds, not a statistical significance test.</div>'
                               + _table(("Selected-head measurement", "Discovery", "Validation"), comparison_rows, "The frozen choice across the two splits")
                               + _table(("Registered validation criterion", "Recorded flag"), [(key, _yes(value)) for key, value in (validation_summary.get("threshold_flags") or {}).items()], "Every descriptive validation flag")
                               + _group_table(validation_restore, "Validation: every group and both orientations")
                               + _table(("Pattern", "Directional records", "Mean restoration Δ", "Alternative → target preference flips", "Top-token changes", "Target newly shares the top score"),
                                        _condition_summary(validation_restore), "Validation restoration outcomes")
                               + '<p class="note">A pair-preference flip concerns only target versus alternative. A top-token change concerns the entire vocabulary. '
                               'Target rank 1 and sharing the top score include exact ties; the displayed top token is the deterministic argmax. Changing a logit margin does not by itself mean that top token changed. Counts use the records with the relevant measurements present.</p>'
                               + '<details open><summary>Every validation margin, target rank, and top token</summary>'
                               + _case_table(validation_restore, "Complete validation restoration records") + '</details>'
                               + '<h3>Reverse, self-copy, and ablation controls</h3>' + _controls(validation, selected))
    else:
        reason = ("No eligible discovery head was selected." if selection.get("status") == "NO_ELIGIBLE_HEAD"
                  else "Discovery did not produce a completed selection." if selected is None
                  else "Validation has not been executed.")
        validation_section += '<div class="callout neutral"><b>Validation not executed.</b> ' + _esc(reason) + ' No validation effect is claimed.</div>'
    validation_section += '</section>'

    parity_section = ('<section><p class="section-label">05 / REFERENCE &amp; EVIDENCE</p><h2>Can the measurement be checked?</h2>'
                      '<p>Recorded comparisons use the pinned model in NeuralScope and the installed Transformers/PyTorch reference. '
                      'Shared weight intake is disclosed; the forward computations are separate. The complete comparison records identify which baselines and interventions were checked.</p>'
                      + _table(("Comparison", "Recorded value"), _parity_rows(discovery, "Discovery") + _parity_rows(validation, "Validation"), "Reference comparison and operation counts"))
    parity_section += ('<dl><dt>Model</dt><dd>' + _esc(model.get("repo_id", "not available")) + '</dd>'
                      '<dt>Revision</dt><dd>' + _esc(model.get("revision", "not available")) + '</dd>'
                      '<dt>Learned parameters</dt><dd>' + _esc(result.get("learned_parameter_elements", "not available")) + '</dd>'
                      '<dt>Reference software</dt><dd>Transformers ' + _esc(reference.get("transformers", "not available"))
                      + ' · PyTorch ' + _esc(reference.get("torch", "not available")) + '</dd></dl>'
                      '<details><summary>Every pinned model and tokenizer file</summary>'
                      + _table(("File", "Bytes", "SHA-256"), [(name, row.get("bytes"), row.get("sha256"))
                               for name, row in sorted((model.get("files") or {}).items())], "External model inputs") + '</details>'
                      '<p>The numeric evidence retains the protocol, selection, discovery scan, validation records when executed, source hashes, and comparison traces. '
                      'The pretrained weights are separate external inputs bound by the file pins above. Replay requires the exact pinned model directory.</p>'
                      '<p>Inventory verification checks bytes against an unsigned receipt. Numeric replay recomputes measurements and reconciles the reported summaries. '
                      'A separately retained receipt digest helps detect replacement of the receipt itself. Rendering this page does not perform either check.</p></section>')

    input_rows = [(case.get("id"), case.get("split"), case.get("group_id"), case.get("orientation"), case.get("condition"),
                   case.get("clean_text"), case.get("changed_text"), str(case.get("target_text")) + " / " + str(case.get("alternative_text"))) for case in cases]
    inputs = ('<section><p class="section-label">06 / COMPLETE INPUTS</p><h2>The fixed text and token cases</h2>'
              '<details><summary>All ' + str(len(cases)) + ' predeclared directional pattern cases</summary>'
              + _table(("Case", "Split", "Group", "Orientation", "Pattern", "Clean text", "Changed text", "Target / alternative"), input_rows, "Predeclared inputs; leading spaces are intentional")
              + _table(("Case", "Clean IDs", "Changed IDs", "Target / alternative", "Patched positions"),
                       [(case.get("id"), case.get("clean_ids"), case.get("changed_ids"),
                         str(case.get("target_id")) + " / " + str(case.get("alternative_id")), case.get("positions")) for case in cases],
                       "Exact token inputs and final-position interventions") + '</details></section>')

    limitations = ('<section class="limits"><h2>How to read the result</h2>'
                   '<p>The experiment can establish a measured contribution from a selected projected head output under these inputs and interventions. '
                   'It does not identify a complete circuit, establish that the head is necessary or sufficient in general, or prove an induction mechanism. '
                   'Attention pattern analysis, broader sequence tests, and further interventions would be different evidence.</p>'
                   '<p>Selection searches 72 candidates; the separate validation groups help test the selected effect but remain a small related synthetic set. '
                   'The report supplies no population confidence interval, security certificate, or inference about intentions. Activation-patching conclusions depend on the chosen contrast and intervention.</p>'
                   '<p>API requests: <b>' + _esc(result.get("api_requests", "not available")) + '</b>. API credit spent: <b>$'
                   + _esc(_num(result.get("api_credit_spent_usd"))) + '</b>. Network requests during the experiment: <b>'
                   + _esc(result.get("network_requests_during_experiment", "not available")) + '</b>.</p></section>')

    return '''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>WolfTrap NeuralScope — attention study</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b1219;color:#e3ecef;font:16px/1.65 system-ui,-apple-system,sans-serif}main{max-width:1190px;margin:auto;padding:44px 26px 68px}header{padding:14px 0 28px;border-bottom:1px solid #2a3c47}.eyebrow,.section-label{font-size:12px;letter-spacing:.14em;color:#8ddac5;font-weight:700}h1{font-size:clamp(32px,5vw,59px);line-height:1.1;max-width:850px;letter-spacing:-.025em;margin:20px 0}h2{font-size:27px;line-height:1.3;margin:8px 0 18px}h3{font-size:20px;margin-top:30px}.lead{font-size:19px;color:#c1d4dd;max-width:950px}p{max-width:1000px}.note{font-size:14px;color:#9eb6c4}.status-line{color:#b5cad4;font-size:14px}.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-top:28px}.metrics>div{background:#12212b;border:1px solid #2b404c;border-radius:12px;padding:18px}.metrics span,.metrics small{display:block;color:#adc3cd;font-size:13px}.metrics strong{display:block;font-size:30px;line-height:1.4}.patterns{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:22px 0}.patterns>div{border:1px solid #304450;background:#13212a;border-radius:10px;padding:18px}.patterns span,.patterns code,.patterns small{display:block}.patterns span{color:#a6c4d1;font-size:13px}.patterns code{font-size:21px;margin:9px 0}.patterns small{color:#a6bbc6}section{margin-top:44px}.scroll{overflow-x:auto;border:1px solid #2a3d49;border-radius:10px;margin:20px 0}table{width:100%;border-collapse:collapse;font-size:12px}caption{text-align:left;padding:13px 15px;background:#152631;color:#c2d9e3;font-weight:650;font-size:13px}th,td{padding:11px 13px;text-align:left;vertical-align:top;border-bottom:1px solid #293c47;font-variant-numeric:tabular-nums}th{background:#12212b;white-space:nowrap;color:#c1d6df}td{overflow-wrap:anywhere}tbody tr:nth-child(even){background:#101d27}tr:last-child td,tr:last-child th{border-bottom:0}.heatmap{min-width:780px;table-layout:fixed;font-size:10px}.heatmap th{padding:11px 3px;text-align:center}.heatmap td{padding:15px 2px;text-align:center;vertical-align:middle;white-space:nowrap;border:2px solid #0b1219;color:#f1f6f7;font-weight:650}.heatmap .chosen{box-shadow:inset 0 0 0 2px #d9e6e9}.legend{display:flex;align-items:center;gap:13px;max-width:470px;margin:0 auto;font-size:12px;color:#b4cbd7}.gradient{height:12px;flex:1;border-radius:4px;background:linear-gradient(90deg,rgb(126,65,96),rgb(22,35,44),rgb(26,111,92))}.callout{padding:18px 22px;background:#142a2b;border-left:3px solid #74bba5;border-radius:7px;margin:20px 0}.neutral{background:#1a2530;border-color:#7d9bb0}.warning{padding:16px 20px;border-left:3px solid #d4a06c;background:#2a251f;border-radius:6px;color:#e9cfaf}.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;color:#b7dbd6}.mono{overflow-wrap:anywhere}dl{display:grid;grid-template-columns:190px 1fr;gap:10px 18px;font-size:14px}dt{color:#a8c0cc}dd{margin:0;overflow-wrap:anywhere;font-family:ui-monospace,monospace;font-size:12px}details{margin:23px 0}summary{cursor:pointer;font-weight:600;color:#9ddac7;padding:6px 0}pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:16px;border:1px solid #2a3d49;border-radius:8px;font-size:12px;max-height:540px;overflow:auto}.limits{background:#101e28;border:1px solid #2c414d;border-radius:12px;padding:24px;font-size:14px}footer{margin-top:30px;color:#839dab;font-size:12px}@media(max-width:650px){main{padding:24px 15px 44px}.metrics{grid-template-columns:1fr}.metrics>div{padding:13px 16px}.metrics strong{font-size:25px}.patterns{grid-template-columns:1fr}h2{font-size:23px}dl{grid-template-columns:1fr;gap:4px}dd{margin-bottom:12px}.callout{padding:15px 17px}}
</style></head><body><main>''' + intro + methods + scan + selection_section + validation_section + parity_section + inputs + limitations + '<footer>WolfTrap NeuralScope · Experimental research software · Self-contained report; no scripts or remote assets.</footer></main></body></html>'


def _policy_text(value):
    import json
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)

"""Self-contained, escaped HTML for the pinned pretrained-model experiment."""
from __future__ import annotations

import html
import math


def _esc(value):
    return html.escape(str(value), quote=True)


def _num(value):
    if value is None:
        return "not available"
    if type(value) in (int, float) and math.isfinite(value):
        return f"{value:.7g}"
    return str(value)


def _yes(value):
    return "Yes" if value is True else "No" if value is False else "not available"


def _table(headers, rows, caption):
    return ('<div class="scroll" role="region" aria-label="' + _esc(caption) + '" tabindex="0">'
            '<table><caption>' + _esc(caption) + '</caption><thead><tr>'
            + ''.join('<th scope="col">' + _esc(v) + '</th>' for v in headers)
            + '</tr></thead><tbody>'
            + ''.join('<tr>' + ''.join('<td>' + _esc(v) + '</td>' for v in row) + '</tr>' for row in rows)
            + '</tbody></table></div>')


def render_pretrained_report(result, registration, study):
    """Render retained measurements without scripts, assets, or network access.

    ``study`` is the complete local-result, or None when parity failed. The
    result's smaller behavior summary is used for discovery/validation claims.
    All dynamic strings pass through HTML escaping, including table cells and
    numeric fallbacks. This renderer does not verify or certify its inputs.
    """
    parity = result.get("parity") or {}
    behavior = result.get("study") or {}
    model = result.get("model") or registration.get("model_identity") or {}
    gates = registration.get("reference_comparison") or {}
    reference = result.get("reference") or {}
    spec = registration.get("cases") or {}
    cases = spec.get("cases") or []
    selected = behavior.get("selected_site")
    status = parity.get("status", "NOT_RUN")
    passed = status == "PASS"
    measured = study is not None
    color = "pass" if passed else "fail"
    headline = ("A pretrained model, checked from the inside"
                if passed else "Reference mismatch: interpretation stopped")
    outcome = ("NeuralScope's NumPy computation matched the reference within the predeclared numerical bounds on these inputs and interventions."
               if passed else "The reference comparison did not pass. The behavior study is not interpreted as evidence about this model.")
    selected_text = selected if selected is not None else "No positive discovery selection"

    criterion_rows = [
        ("Largest absolute logit error", _num(parity.get("maximum_logit_absolute_error")),
         "at most " + _num(gates.get("full_logit_max_abs_error"))),
        ("Largest logit RMSE", _num(parity.get("maximum_logit_rmse")),
         "at most " + _num(gates.get("full_logit_rmse"))),
        ("Largest activation error / allowance", _num(parity.get("maximum_activation_scaled_error")), "at most 1"),
        ("Largest absolute activation error", _num(parity.get("maximum_activation_absolute_error")),
         "elementwise allowance: " + _num(gates.get("activation_atol")) + " + " + _num(gates.get("activation_rtol")) + " × |reference|"),
        ("Observed reference logits equal unhooked logits bitwise", _yes(parity.get("reference_hooks_bitwise_invariant")), "Yes"),
        ("Cross-engine baseline sequences", parity.get("baseline_sequences", 0), "both sides of every registered pair"),
        ("Cross-engine intervention comparisons", parity.get("intervention_comparisons", 0), "fixed sites and operations on the first discovery pair"),
    ]
    reference_section = ('<section><p class="section-label">01 / REFERENCE COMPUTATION</p>'
        '<h2>Does the instrument reproduce the model?</h2>'
        '<p>The same pinned weights and token IDs run through NeuralScope and the installed Transformers GPT-2 implementation. '
        'The comparison covers complete logits and captured internal activations. Intervention comparisons use each engine’s own '
        'captured donor and recipient, following the same registered operation.</p>'
        + _table(("Measurement", "Observed", "Predeclared criterion"), criterion_rows, "Reference comparison")
        + '<p class="note">Maximum activation error is reported for context; its gate uses the elementwise absolute-plus-relative allowance. '
        'A matching winning token alone is insufficient. The reference and candidate share validated intake, while their forward computations differ.</p>'
        '<p>Intervention case: <code>' + _esc(gates.get("intervention_case", "not available"))
        + '</code>. Sites: <span class="mono">' + _esc(', '.join(gates.get("intervention_sites", [])))
        + '</span>. Operations: ' + _esc(', '.join(gates.get("intervention_operations", []))) + '.</p></section>')

    if measured:
        rows = study.get("cases") or []
        baseline_rows = []
        for row in rows:
            clean, corrupt = row.get("clean_margin"), row.get("corrupt_margin")
            preferences = (type(clean) in (int, float) and type(corrupt) in (int, float)
                           and clean > 0 and corrupt < 0)
            baseline_rows.append((row.get("id"), row.get("split"), _num(clean), _num(corrupt),
                                  _num(row.get("baseline_gap")), _yes(row.get("normalization_valid")), _yes(preferences)))
        split_summary = behavior.get("split_summary") or {}
        support = []
        for split in ("discovery", "validation"):
            summary = split_summary.get(split) or {}
            support.append(split + ": " + str(summary.get("both_answer_preferences_present", "?")) + "/"
                           + str(summary.get("cases", "?")) + " pairs have both expected answer preferences")
        study_section = ('<section><p class="section-label">02 / PREDECLARED BEHAVIOR</p>'
            '<h2>Six repeated-token contrasts</h2>'
            '<p>Each pair changes the alternating continuation in a five-token sequence. The measured margin is '
            '<b>logit(target) − logit(alternative)</b> at the final input position. A positive clean margin favors the target; '
            'a negative changed margin favors the alternative.</p>'
            '<p>' + _esc('; '.join(support)) + '.</p>'
            + _table(("Pair", "Split", "Clean margin", "Changed margin", "Gap", "Usable gap", "Both preferences"),
                     baseline_rows, "Every baseline pair — logits")
            + '<p class="note">A positive clean-minus-changed gap can exist even when both expected preferences are absent. '
            'Those observations remain in the report. Ratios require a gap above the registered floor of '
            + _esc(_num(spec.get("minimum_gap"))) + ' logits and the relative floor.</p></section>')

        ranking = sorted(study.get("site_summary") or [],
                         key=lambda r: (r.get("discovery", {}).get("mean_restoration") is None,
                                        -(r.get("discovery", {}).get("mean_restoration") or 0)))
        site_rows = []
        for i, row in enumerate(ranking, 1):
            discovery, validation = row.get("discovery") or {}, row.get("validation") or {}
            controls = [v for v in (discovery.get("self_patch_max_abs_delta"), validation.get("self_patch_max_abs_delta"))
                        if type(v) in (int, float)]
            site_rows.append((i, row.get("site"), _num(discovery.get("mean_restoration")),
                              str(discovery.get("usable_cases", "?")) + "/" + str(discovery.get("cases", "?")),
                              _num(validation.get("mean_restoration")),
                              str(validation.get("usable_cases", "?")) + "/" + str(validation.get("cases", "?")),
                              _num(max(controls) if controls else None)))
        study_section += ('<section><p class="section-label">03 / INTERNAL INTERVENTIONS</p>'
            '<h2>Which tested MLP output changes the contrast?</h2>'
            '<div class="callout"><span class="muted">Selected using discovery cases only</span><br><strong class="mono">'
            + _esc(selected_text) + '</strong><p>Selected-site validation mean: <b>'
            + _esc(_num(behavior.get("selected_validation_mean"))) + '</b>. '
            + _esc(str(behavior.get("selected_validation_usable_cases", 0))) + ' of '
            + _esc(str(behavior.get("selected_validation_cases", 0))) + ' selected validation cases were normalizable.</p></div>'
            '<p>Only the final input position is patched. A restoration ratio of 1 recovers the measured clean–changed gap; '
            '0 recovers none. Ratios can be negative or greater than 1. They are <b>effect measurements, not percentages of safety</b>.</p>'
            + _table(("Rank", "Site", "Discovery mean", "Usable", "Validation mean", "Usable", "Largest self-copy Δ"),
                     site_rows, "All six tested MLP sites — normalized restoration")
            + '<p class="note">Ranking uses discovery means. Site selection requires all three discovery cases to be normalizable '
            'and a strictly positive mean. Validation is reported without changing the selected site. A displayed partial-case mean '
            'must be read with its usable-case count.</p>')
        if selected:
            validation_rows = []
            for row in rows:
                if row.get("split") != "validation":
                    continue
                entry = next((x for x in row.get("interventions", []) if x.get("site") == selected), {})
                validation_rows.append((row.get("id"), _num(entry.get("restored_margin")),
                                        _num(entry.get("normalized_restoration")), _num(entry.get("normalized_reverse")),
                                        _num(entry.get("ablated_margin")), _num(entry.get("self_patch_max_abs_delta"))))
            study_section += _table(("Validation pair", "Patched margin", "Restoration", "Reverse effect", "Zero-ablation margin", "Self-copy Δ"),
                                    validation_rows, "Every validation case at the selected site")
        else:
            study_section += '<p>No site met the registered positive discovery-selection rule. The full measurements above remain the result.</p>'
        study_section += ('<p>Self-copy controls passed: <b>' + _esc(_yes(study.get("self_patch_controls_pass")))
                          + '</b>; allowed margin change: <code>' + _esc(_num(gates.get("self_patch_margin_atol")))
                          + '</code>. Reverse patches and zero ablations are retained. No pretrained component is labeled a known inactive control.</p></section>')
    else:
        study_section = ('<section class="callout warning"><p class="section-label">02 / BEHAVIOR STUDY</p>'
                         '<h2>Study not executed</h2><p>The runner stops the interpretation stage when reference parity fails. '
                         'No selected component or validation effect is claimed. The fixed input protocol is retained below.</p></section>')

    input_rows = [(case.get("id"), case.get("split"), case.get("clean_text"), case.get("corrupt_text"),
                   str(case.get("target_text")) + " / " + str(case.get("alternative_text"))) for case in cases]
    token_rows = [(case.get("id"), str(case.get("clean_ids")), str(case.get("corrupt_ids")),
                   str(case.get("target_id")) + " / " + str(case.get("alternative_id")), str(case.get("positions"))) for case in cases]
    inputs_section = ('<section><p class="section-label">04 / FIXED INPUTS</p><h2>Every prompt and answer contrast</h2>'
        '<p>Leading spaces are intentional. These are fixed synthetic continuation patterns, with three discovery and three validation pairs. '
        'They are not independent samples of general language ability.</p>'
        + _table(("Pair", "Split", "Clean input", "Changed input", "Target / alternative"), input_rows, "Predeclared text inputs")
        + '<details><summary>Exact token IDs and patch positions</summary>'
        + _table(("Pair", "Clean IDs", "Changed IDs", "Target / alternative ID", "Patched position"), token_rows, "Exact token inputs")
        + '</details></section>')

    file_rows = [(name, record.get("bytes"), record.get("sha256"))
                 for name, record in sorted((model.get("files") or {}).items())]
    provenance_rows = [("Reference implementation", reference.get("implementation", "not available")),
                       ("Transformers", reference.get("transformers", "not available")),
                       ("PyTorch", reference.get("torch", "not available")),
                       ("NumPy", reference.get("numpy", "not available")),
                       ("Arithmetic / attention", str(reference.get("device", "?")) + " / " + str(reference.get("dtype", "?")) + " / " + str(reference.get("attention_implementation", "?"))),
                       ("Reference GPT-2 source SHA-256", reference.get("modeling_gpt2_sha256", "not available"))]
    pins_section = ('<section><p class="section-label">05 / EVIDENCE &amp; REPLAY</p><h2>Exact inputs, retained measurements</h2>'
        '<dl><dt>Model</dt><dd>' + _esc(model.get("repo_id", "not available")) + '</dd>'
        '<dt>Model revision</dt><dd class="mono">' + _esc(model.get("revision", "not available")) + '</dd>'
        '<dt>Protocol SHA-256</dt><dd class="mono">' + _esc(result.get("protocol_sha256", "not available")) + '</dd>'
        '<dt>Learned parameter elements</dt><dd>' + _esc(result.get("learned_parameter_elements", "not available")) + '</dd></dl>'
        + _table(("Pinned file", "Bytes", "SHA-256"), file_rows, "Model, tokenizer, and documentation inventory")
        + '<details><summary>Reference software identity</summary>'
        + _table(("Field", "Recorded value"), provenance_rows, "Reference implementation provenance") + '</details>'
        '<p>The evidence directory retains the protocol, full reference comparisons, numeric traces, study results when executed, '
        'source hashes, runtime measurements, and an unsigned inventory receipt. The pretrained weights remain in a separate directory; '
        'replay requires that directory to match these exact pins.</p>'
        '<p>The local protocol was frozen before inference by the runner. Its digest binds its contents; '
        'no independent timestamp or publisher signature is established. Inventory verification checks bytes, while numeric replay '
        'recomputes the saved measurements.</p></section>')

    limits = ('<section class="limits"><h2>What this result supports</h2>'
        '<p>A passing reference comparison supports this pinned checkpoint, these numerical settings, these inputs, and the tested intervention sites. '
        'A measured intervention demonstrates an effect within that computation. Whole-MLP patches do not isolate individual neurons or establish a complete circuit.</p>'
        '<p>Six related patterns do not establish population-level performance. Zero ablation may move activity outside its ordinary distribution. '
        'These measurements do not establish intention, deception, absence of backdoors, general safety, or access to a proprietary hosted model’s internals.</p>'
        '<p>API requests: <b>' + _esc(result.get("api_requests", "not available")) + '</b>. API credit spent: <b>$'
        + _esc(_num(result.get("api_credit_spent_usd"))) + '</b>. Network requests during the experiment: <b>'
        + _esc(result.get("network_requests_during_experiment", "not available")) + '</b>. Model acquisition is a separate step.</p></section>')

    return ('''<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>WolfTrap NeuralScope — pretrained experiment</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#0b1417;color:#e7f1ef;font:16px/1.65 system-ui,-apple-system,sans-serif}main{max-width:1100px;margin:auto;padding:44px 26px 68px}header{padding:16px 0 32px;border-bottom:1px solid #2c4244}.eyebrow,.section-label{font-size:12px;letter-spacing:.14em;color:#80ddbc;font-weight:700}h1{font-size:clamp(32px,5vw,58px);line-height:1.12;max-width:850px;letter-spacing:-.025em;margin:22px 0}h2{font-size:26px;line-height:1.3;margin:8px 0 18px}p{max-width:930px}.lead{font-size:19px;color:#c7dcd6}.muted,.note{color:#a3bbb5}.note{font-size:14px}.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin:28px 0 4px}.metric{padding:19px 21px;background:#142326;border:1px solid #284548;border-radius:13px}.metric small{display:block;color:#aac4ba}.metric strong{font-size:26px;display:block;line-height:1.35;margin-top:5px}.pass{color:#87e8ad}.fail{color:#ffb4a3}section{margin-top:42px}.callout{background:#162b2a;border-left:4px solid #82d9b0;border-radius:6px;padding:20px 24px;margin:22px 0}.callout strong{font-size:22px}.warning{background:#2b2220;border-color:#e6a289}.scroll{overflow-x:auto;margin:20px 0;border:1px solid #2b4244;border-radius:10px}table{width:100%;border-collapse:collapse;font-size:13px}caption{text-align:left;font-size:13px;font-weight:700;padding:13px 16px;background:#17282a;color:#bbd9cf}th,td{padding:12px 14px;text-align:left;vertical-align:top;border-bottom:1px solid #263b3c}th{font-weight:650;background:#112023;white-space:nowrap;color:#bee0d3}td{font-variant-numeric:tabular-nums;overflow-wrap:anywhere}tr:last-child td{border-bottom:0}tbody tr:nth-child(even){background:#101e21}code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;color:#b2e3ce}code{font-size:.9em}dl{display:grid;grid-template-columns:190px 1fr;gap:9px 18px}dt{color:#aac4ba}dd{margin:0;overflow-wrap:anywhere;font-size:14px}details{margin:22px 0}summary{cursor:pointer;color:#9ce2bf;padding:8px 0;font-weight:600}.limits{padding:25px;background:#101e21;border:1px solid #2b4244;border-radius:12px;font-size:14px}footer{margin-top:35px;color:#8ea9a2;font-size:12px}a{color:#99e2bf}@media(max-width:650px){main{padding:24px 16px 44px}.metrics{grid-template-columns:1fr}.metric{padding:13px 17px}.metric strong{font-size:23px}h2{font-size:23px}dl{grid-template-columns:1fr;gap:3px}dd{margin-bottom:10px}.callout{padding:17px}.lead{font-size:17px}th,td{padding:10px}section{margin-top:34px}}
</style></head><body><main><header><div class="eyebrow">WOLFTRAP / NEURALSCOPE / '''
        + _esc(result.get("version", "research prototype")) + '</div><h1>' + _esc(headline) + '</h1>'
        '<p class="lead">' + _esc(outcome) + '</p><div class="metrics">'
        '<div class="metric"><small>Reference comparison</small><strong class="' + color + '">' + _esc(status) + '</strong></div>'
        '<div class="metric"><small>Predeclared input pairs</small><strong>' + _esc(len(cases)) + '</strong></div>'
        '<div class="metric"><small>Behavior study</small><strong>' + _esc(study.get("status", "not available") if measured else "NOT EXECUTED") + '</strong></div>'
        '</div></header>' + reference_section + study_section + inputs_section + pins_section + limits
        + '<footer>Generated locally from retained measurements. Static HTML with no scripts, remote assets, analytics, or automatic network requests. '
        'The report is a readable view; use the accompanying JSON and replay tools for verification.</footer></main></body></html>')

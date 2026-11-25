"""A static, offline HTML report; all model-originated strings are escaped."""
import html


def render_report(result):
    esc = lambda value: html.escape(str(value), quote=True)
    fmt = lambda value: "unavailable" if value is None else f"{value:.6f}"
    table = []
    for row in result["site_summary"]:
        discovery, validation = row["discovery"], row["validation"]
        table.append("<tr><th>" + esc(row["site"]) + "</th><td>" + fmt(discovery["mean_restoration"])
                     + "</td><td>" + fmt(validation["mean_restoration"]) + "</td><td>"
                     + fmt(max(discovery["self_patch_max_abs_delta"], validation["self_patch_max_abs_delta"])) + "</td></tr>")
    details = []
    for row in result["cases"]:
        details.append("<tr><td>" + esc(row["id"]) + "</td><td>" + esc(row["split"])
                       + "</td><td>" + fmt(row["clean_margin"]) + "</td><td>" + fmt(row["corrupt_margin"])
                       + "</td><td>" + fmt(row["baseline_gap"]) + "</td></tr>")
    limitations = "".join("<li>" + esc(value) + "</li>" for value in result["limitations"])
    return """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>WolfTrap NeuralScope — experiment report</title>
<style>body{margin:0;background:#10171c;color:#e2e9ed;font:17px/1.65 system-ui,sans-serif}main{max-width:1000px;margin:auto;padding:44px 24px}h1{font-size:40px;line-height:1.2}h2{margin-top:36px;color:#75e4c3}small,.muted{color:#aebfc9}.card{background:#1b272e;border:1px solid #33444f;border-radius:12px;padding:22px;margin:24px 0}table{border-collapse:collapse;width:100%;font-size:14px}td,th{padding:12px;border-bottom:1px solid #33444f;text-align:left}th{font-weight:600}code{color:#a9efdb}.scroll{overflow:auto}.pill{display:inline-block;border:1px solid #75e4c3;padding:4px 12px;border-radius:30px;color:#75e4c3}.foot{font-size:14px;color:#aebfc9}</style>
<main><small>WOLFTRAP / NEURALSCOPE / RESEARCH PROTOTYPE</small>
<h1>A measurable view inside a neural computation</h1>
<p class="pill">""" + esc(result["status"]) + """</p>
<div class="card"><b>Model origin:</b> """ + esc(result["model_origin"]) + """<p><b>Claim scope:</b> """ + esc(result["claim_scope"]) + """</p>
<p>Selected site from discovery cases: <code>""" + esc(result["selected_site_using_discovery_only"]) + """</code>.</p></div>
<h2>What was measured</h2><p>For each matched pair, the runner recorded the model's internal activations, copied one selected component from the clean run into the changed run, and measured the target answer's logit margin. It also applied the reverse patch, self patches, and zero ablation. Patches affect only the predeclared token positions.</p>
<p>A normalized restoration of 1 means this patch recovered the clean-to-changed logit gap for this pair. Zero means it recovered none. This value is not a probability; it can be negative or exceed 1.</p>
<h2>Intervention results</h2><div class="scroll"><table><thead><tr><th>Site</th><th>Discovery mean</th><th>Validation mean</th><th>Largest self-patch change</th></tr></thead><tbody>""" + "".join(table) + """</tbody></table></div>
<h2>Baseline pairs</h2><div class="scroll"><table><thead><tr><th>Pair</th><th>Split</th><th>Clean margin</th><th>Changed margin</th><th>Gap</th></tr></thead><tbody>""" + "".join(details) + """</tbody></table></div>
<h2>Reading this result correctly</h2><ul>""" + limitations + """</ul>
<h2>Reproducible evidence</h2><p>The bundle includes the exact model tensors and configuration, paired token inputs, numerical traces, metrics, code hashes, environment versions, and a closed inventory receipt. The verifier checks byte integrity; replay reruns the recorded computation using the installed code. Neither authenticates a publisher or certifies model safety.</p>
<p class="foot">Generated locally. No JavaScript, external assets, analytics, or network requests in this report. See README.md and DESIGN.md for instructions and the research basis.</p></main></html>"""

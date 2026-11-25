"""Export per-prompt ablation and layer/control contrasts directly from the measured outputs."""
import csv
import json
from pathlib import Path
from statistics import mean

out = Path(__file__).resolve().parent
run = out.parent / "pretrained-runs/study-001"
protocol, results = (json.loads((run / name).read_bytes()) for name in ("protocol.json", "results.json"))
cases, directions = [], []
for group in ("validation_positive", "validation_control"):
    measurements = results["validation"][group]
    for i, prompt in enumerate(protocol["metadata"]["texts"][group]):
        controls = [row[i] for row in measurements["random_neuron_margin_decrease"]]
        cases.append(dict(group=group, case=i+1, prompt=prompt, baseline_margin=measurements["baseline_margin"][i],
                          ablation_decrease=measurements["exact_ablation_margin_decrease"][i],
                          predicted_decrease=measurements["first_order_prediction"][i], mean_random_decrease=mean(controls),
                          **{f"control_{n+1}":c for n,c in enumerate(controls)}))
        for layer in measurements["cross_layer"]:
            controls = [row[i] for row in layer["random_delta"]]
            directions.append(dict(group=group,case=i+1,layer=layer["layer"],chosen_gain=layer["chosen_delta"][i],
                                   mean_random_gain=layer["random_mean_delta"][i],
                                   chosen_minus_random=layer["chosen_minus_random_mean"][i],
                                   **{f"direction_{n+1}":v for n,v in enumerate(controls)}))
for rows, filename in [(cases,"held-out-ablations.csv"),(directions,"cross-layer.csv")]:
    with (out / filename).open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

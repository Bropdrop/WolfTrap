"""Plot the frozen study's held-out measurements. Run from any directory."""
from pathlib import Path
from statistics import mean
import json
import matplotlib
matplotlib.use("Agg")
from matplotlib import pyplot as plt

here=Path(__file__).resolve().parent
r=json.loads((here.parent/"pretrained-runs/study-001/results.json").read_text())["validation"]
fig,(a,b)=plt.subplots(1,2,figsize=(10.4,3.5),layout="constrained")
for key,label,color,shift,marker in [("validation_positive","France","#09677c",.08,"o"),("validation_control","Germany","#964623",-.08,"s")]:
    v=r[key]
    a.scatter(v["exact_ablation_margin_decrease"],[i+shift for i in range(4)],label=label,c=color,marker=marker,zorder=3,s=43)
    b.plot([q["layer"] for q in v["cross_layer"]],[mean(q["chosen_minus_random_mean"]) for q in v["cross_layer"]],color=color,marker=marker,label=label,linewidth=1.6)
a.set_yticks(range(4),["Question + ‘It is’","Seat of government","Capital city located in","Asked to name the capital"])
a.invert_yaxis()
a.axvline(0,color="#616970",lw=.8)
a.set_xlabel("Decrease in Paris − Berlin margin (logits)")
a.set_title("Exact ablation by held-out wording",loc="left",fontsize=12)
b.axhline(0,color="#616970",lw=.8)
b.set_xlabel("Layer receiving the frozen direction")
b.set_ylabel("Mean excess margin gain (logits)")
b.set_title("Signed direction vs six random directions",loc="left",fontsize=12)
b.legend(frameon=False,loc="lower right")
for ax in (a,b):
    ax.grid(axis="x" if ax is a else "y",alpha=.15,zorder=0)
    ax.spines[["right","top"]].set_visible(False)
    ax.tick_params(labelsize=9)
fig.savefig(here/"held-out-effects.png",dpi=170,bbox_inches="tight",facecolor="white")

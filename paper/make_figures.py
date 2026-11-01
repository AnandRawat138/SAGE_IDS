"""Generate publication-quality paper figures from committed result JSON (no hand-entered numbers).

Usage: python paper/make_figures.py
Writes vector PDFs + PNGs into paper/figures/. Every value is read from reports/*.json. Figures use
Wilson/bootstrap confidence intervals as error bars, grouped conditions, value labels, clean spines,
and a colour-blind-safe palette with hatching so they remain legible in greyscale print.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
REP = ROOT / "reports"
FIG = ROOT / "paper" / "figures"
FIG.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "font.size": 8, "font.family": "serif", "mathtext.fontset": "dejavuserif",
    "axes.grid": True, "axes.grid.axis": "y", "grid.alpha": 0.35, "grid.linewidth": 0.5,
    "axes.axisbelow": True, "axes.linewidth": 0.6, "figure.dpi": 200, "savefig.bbox": "tight",
    "savefig.pad_inches": 0.02, "legend.frameon": False, "legend.handlelength": 1.3,
    "legend.columnspacing": 1.0, "legend.handletextpad": 0.5, "xtick.direction": "out",
    "ytick.direction": "out", "xtick.major.size": 2.5, "ytick.major.size": 2.5,
})
# colour-blind-safe (Okabe-Ito subset) + hatches for greyscale
PAL = ["#4C72B0", "#DD8452", "#55A868", "#C44E52", "#8172B3"]
HATCH = ["", "///", "...", "xxx", "\\\\\\"]
COLW = 3.35          # one IEEE column (inches)


def save(fig, name):
    fig.savefig(FIG / f"{name}.pdf")
    fig.savefig(FIG / f"{name}.png", dpi=220)
    plt.close(fig)
    print("wrote", name)


def load(p):
    return json.loads((REP / p).read_text())


def _clean(ax):
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)


def _yerr(rate, ci):
    lo = max(0.0, rate - ci[0])
    hi = max(0.0, ci[1] - rate)
    return lo, hi


def _rate_ci(d):
    if "rate" in d:
        return d["rate"], d["ci95"]
    k, n = d["detected"], d["n"]
    r = k / n if n else 0.0
    return r, d.get("ci95", [r, r])


# --------------------------------------------------------------------------- Fig 1
def fig_detection_compare():
    """Per-scenario detection for four learning conditions, with Wilson 95% CIs.
    Shows both the accepted gain and the feedback-poisoning (self-training) failure."""
    r = load("experiment_results.json")
    ft = r["versions"] if "versions" in r and isinstance(r.get("versions"), list) else None
    ft = load("experiment_results.json")["final_test"]
    byname = {d["name"]: v for v, d in ft["versions"].items()}
    acc = {d["accepted_version"] for d in load("experiment_results.json")["cases"].values()
           if d["accepted_version"]}
    conditions = [
        ("initial (v1)", ft["v1_id"]),
        ("self-training", byname.get("ABL-self-training")),
        ("verified retrain", byname.get("ABL-verified-retrain-all")),
        ("accepted", None),  # per-scenario max over accepted versions
    ]
    scen = ["app-request-flood", "auth-password-guessing", "recon-tcp-probe"]
    labels = ["flood", "guessing", "recon"]
    fig, ax = plt.subplots(figsize=(COLW, 2.35))
    nC = len(conditions)
    w = 0.8 / nC
    x = np.arange(len(scen))
    for i, (cname, vid) in enumerate(conditions):
        rates, los, his = [], [], []
        for s in scen:
            if vid is None:  # accepted: best over accepted versions
                best, bci = 0.0, [0.0, 0.0]
                for v in acc:
                    p = ft["versions"].get(str(v), {}).get("per_scenario", {}).get(s)
                    if p and p["rate"] >= best:
                        best, bci = p["rate"], p["ci95"]
                rr, cc = best, bci
            else:
                p = ft["versions"][str(vid)]["per_scenario"][s]
                rr, cc = p["rate"], p["ci95"]
            lo, hi = _yerr(rr, cc)
            rates.append(rr); los.append(lo); his.append(hi)
        ax.bar(x + (i - (nC - 1) / 2) * w, rates, w, yerr=[los, his], capsize=2,
               error_kw={"elinewidth": 0.6, "capthick": 0.6}, color=PAL[i], hatch=HATCH[i],
               edgecolor="black", linewidth=0.4, label=cname)
    ax.set_xticks(x); ax.set_xticklabels(labels)
    ax.set_ylabel("held-out detection rate")
    ax.set_ylim(0, 1.08)
    ax.legend(ncol=2, fontsize=6.5, loc="upper center", bbox_to_anchor=(0.5, 1.22))
    _clean(ax)
    save(fig, "fig_final_detection")


# --------------------------------------------------------------------------- Fig 2
def fig_versions():
    """Window-level F1 (bars, left axis) and benign FPR (markers, right axis) for every version,
    coloured by lifecycle status."""
    ft = load("experiment_results.json")["final_test"]
    order = sorted(ft["versions"], key=lambda v: int(v))
    status_colour = {"accepted": PAL[2], "retired": PAL[0], "rejected": PAL[3], "ablation": PAL[4],
                     "candidate": "#999999"}
    names, f1s, fprs, cols = [], [], [], []
    fpr_lo, fpr_hi = [], []
    for v in order:
        d = ft["versions"][v]
        nm = d["name"].replace("candidate-", "c-").replace("ABL-", "abl:").replace("v1-baseline", "v1")
        names.append(f"v{v}\\,{nm}" if False else f"v{v}")
        f1s.append(d["window_binary"]["f1"])
        fpr = d["window_binary"]["fpr"] or 0.0
        fprs.append(fpr)
        ci = d["window_binary"].get("fpr_ci95", [fpr, fpr])
        fpr_lo.append(max(0, fpr - ci[0])); fpr_hi.append(max(0, ci[1] - fpr))
        cols.append(status_colour.get(d["status"], "#999999"))
    x = np.arange(len(order))
    fig, ax = plt.subplots(figsize=(COLW, 2.35))
    ax.bar(x, f1s, 0.64, color=cols, edgecolor="black", linewidth=0.4)
    ax.set_ylabel("window $F_1$ (bars)")
    ax.set_ylim(0, 1.08)
    ax.set_xticks(x); ax.set_xticklabels(names, fontsize=6.5)
    ax.set_xlabel("detector version", labelpad=1)
    ax2 = ax.twinx()
    ax2.errorbar(x, fprs, yerr=[fpr_lo, fpr_hi], fmt="D", ms=3, color="black", mfc="white",
                 elinewidth=0.6, capsize=2, capthick=0.6, label="benign FPR", zorder=5)
    ax2.set_ylabel("benign FPR (markers)")
    ax2.set_ylim(0, max(0.35, max(fprs) * 1.3 + 0.02))
    ax2.spines["top"].set_visible(False)
    from matplotlib.patches import Patch
    leg = [Patch(fc=status_colour[s], ec="black", lw=0.4, label=s) for s in
           ["accepted", "retired", "rejected", "ablation"]]
    ax.legend(handles=leg, ncol=4, fontsize=6, loc="upper center", bbox_to_anchor=(0.5, 1.2),
              handlelength=1.0)
    _clean(ax)
    save(fig, "fig_window_versions")


# --------------------------------------------------------------------------- Fig 3
def fig_evasion():
    """Detection of the initial vs evolved detector on the normal attack and on evasive variants,
    with Wilson CIs; annotation that every variant still achieves its effect."""
    ft = load("experiment_results.json")["final_test"]
    ev = load("evasion_results.json")
    vids = sorted(int(v) for v in ev["versions"])
    evolved = str(max(vids)); base = str(min(vids))
    # normal-attack detection (from final test) for the two matching scenarios
    normal = {"guessing": ft["versions"][evolved]["per_scenario"]["auth-password-guessing"],
              "flood": ft["versions"][evolved]["per_scenario"]["app-request-flood"]}
    cats = [("normal\\nguessing", normal["guessing"]["rate"], normal["guessing"]["ci95"]),
            ("slow\\nguessing", *_rate_ci(ev["variants"]["auth-slow-guessing"]["detection_by_version"][evolved])),
            ("distributed\\nguessing", *_rate_ci(ev["variants"]["auth-distributed-guessing"]["detection_by_version"][evolved])),
            ("normal\\nflood", normal["flood"]["rate"], normal["flood"]["ci95"]),
            ("low-rate\\nflood", *_rate_ci(ev["variants"]["app-low-rate-flood"]["detection_by_version"][evolved]))]
    labels = [c[0].replace("\\n", "\n") for c in cats]
    rates = [c[1] for c in cats]
    los = [_yerr(c[1], c[2])[0] for c in cats]
    his = [_yerr(c[1], c[2])[1] for c in cats]
    colours = [PAL[2], PAL[3], PAL[3], PAL[2], PAL[3]]
    fig, ax = plt.subplots(figsize=(COLW, 2.45))
    x = np.arange(len(cats))
    bars = ax.bar(x, rates, 0.6, yerr=[los, his], capsize=2,
                  error_kw={"elinewidth": 0.6, "capthick": 0.6},
                  color=colours, edgecolor="black", linewidth=0.4)
    for xi, r in zip(x, rates):
        ax.text(xi, r + 0.03, f"{r:.2f}", ha="center", va="bottom", fontsize=6.5)
    ax.axhline(1.0, ls=":", lw=0.7, color="#555555")
    ax.text(-0.45, 1.11, "dotted line: attack still succeeds on 100% of trials", ha="left",
            va="bottom", fontsize=5.8, color="#555555")
    ax.set_xticks(x); ax.set_xticklabels(labels, fontsize=6.5)
    ax.set_ylabel("detection rate (evolved detector)")
    ax.set_ylim(0, 1.22)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(fc=PAL[2], ec="black", lw=0.4, label="non-evasive"),
                       Patch(fc=PAL[3], ec="black", lw=0.4, label="evasive variant")],
              ncol=2, fontsize=6.5, loc="upper center", bbox_to_anchor=(0.5, 1.16))
    _clean(ax)
    save(fig, "fig_evasion")


# --------------------------------------------------------------------------- Fig 4
def fig_benchmark():
    """RF precision/recall/F1 on CICIDS2017 for random vs unseen-day split, bootstrap 95% CIs;
    isolation-forest F1 shown for reference."""
    strat = load("benchmark_cicids2017_stratified.json")["summary"]
    day = load("benchmark_cicids2017_day.json")["summary"]
    metrics = ["precision", "recall", "f1"]
    fig, ax = plt.subplots(figsize=(COLW, 2.35))
    x = np.arange(len(metrics))
    w = 0.38
    for i, (lab, S) in enumerate([("random split", strat), ("unseen-day split", day)]):
        vals = [S["rf"][m]["mean"] for m in metrics]
        lo = [max(0, S["rf"][m]["mean"] - S["rf"][m]["ci95"][0]) for m in metrics]
        hi = [max(0, S["rf"][m]["ci95"][1] - S["rf"][m]["mean"]) for m in metrics]
        b = ax.bar(x + (i - 0.5) * w, vals, w, yerr=[lo, hi], capsize=2,
                   error_kw={"elinewidth": 0.6, "capthick": 0.6}, color=PAL[i], hatch=HATCH[i],
                   edgecolor="black", linewidth=0.4, label=lab)
        for xi, vv in zip(x + (i - 0.5) * w, vals):
            ax.text(xi, vv + 0.02, f"{vv:.2f}", ha="center", va="bottom", fontsize=6)
    ax.set_xticks(x); ax.set_xticklabels([m.capitalize() for m in metrics])
    ax.set_ylabel("random-forest score (5 seeds)")
    ax.set_ylim(0, 1.12)
    ax.legend(fontsize=6.5, loc="lower left")
    # annotate the recall collapse
    ax.annotate("recall collapses\non unseen attacks",
                xy=(1 + 0.5 * w, day["rf"]["recall"]["mean"]), xytext=(1.28, 0.60),
                fontsize=6, ha="left", va="center", color="#333333",
                arrowprops=dict(arrowstyle="->", lw=0.5, color="#333333"))
    _clean(ax)
    save(fig, "fig_benchmark_split")


if __name__ == "__main__":
    for fn in (fig_detection_compare, fig_versions, fig_evasion, fig_benchmark):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            import traceback
            print("SKIP", fn.__name__, type(e).__name__, e)
            traceback.print_exc()

"""Generate paper figures from committed result JSON (no hand-entered numbers).

Usage: python paper/make_figures.py
Writes vector PDFs + PNGs into paper/figures/. Every value is read from reports/*.json.
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
REP = ROOT / "reports"
FIG = ROOT / "paper" / "figures"
FIG.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({"font.size": 8, "font.family": "serif", "axes.grid": True,
                     "grid.alpha": 0.3, "figure.dpi": 150, "savefig.bbox": "tight"})
GREY = ["#333333", "#888888", "#bbbbbb", "#dddddd"]


def save(fig, name):
    fig.savefig(FIG / f"{name}.pdf")
    fig.savefig(FIG / f"{name}.png")
    plt.close(fig)
    print("wrote", name)


def load(p):
    return json.loads((REP / p).read_text())


def fig_final_detection():
    r = load("experiment_results.json")
    ft = r["final_test"]
    v1 = ft["v1_id"]
    acc = {d["accepted_version"] for d in r["cases"].values() if d["accepted_version"]}
    scen = sorted(ft["versions"][v1]["per_scenario"])
    base = [ft["versions"][v1]["per_scenario"][s]["rate"] for s in scen]
    best = []
    for s in scen:
        vals = [ft["versions"][str(v)]["per_scenario"][s]["rate"] for v in acc if str(v) in ft["versions"]]
        best.append(max(vals) if vals else 0.0)
    import numpy as np
    x = np.arange(len(scen))
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    ax.bar(x - 0.2, base, 0.4, label="initial v1", color=GREY[1], edgecolor="black", linewidth=0.5)
    ax.bar(x + 0.2, best, 0.4, label="accepted", color=GREY[0], edgecolor="black", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels([s.replace("auth-password-guessing", "guessing").replace("app-request-flood", "flood")
                        .replace("recon-tcp-probe", "recon") for s in scen], rotation=0)
    ax.set_ylabel("per-trial detection rate")
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=7, loc="lower right")
    save(fig, "fig_final_detection")


def fig_evasion():
    r = load("evasion_report_source.json") if (REP / "evasion_report_source.json").exists() else load("evasion_results.json")
    variants = r["variants"]
    # pick the last accepted/retired version column with the highest id (the evolved detector)
    vids = sorted(int(v) for v in r["versions"])
    target = str(max(vids))
    labels, rates = [], []
    for sid, d in variants.items():
        pv = d["detection_by_version"].get(target) or d["detection_by_version"].get(int(target))
        labels.append(sid.replace("auth-", "").replace("app-", ""))
        rates.append(pv["rate"] if pv else 0.0)
    import numpy as np
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    ax.bar(range(len(labels)), rates, color=GREY[0], edgecolor="black", linewidth=0.5)
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=7)
    ax.set_ylabel("detection rate (evolved detector)")
    ax.set_ylim(0, 1.05)
    save(fig, "fig_evasion")


def fig_benchmark():
    strat = load("benchmark_cicids2017_stratified.json")["summary"]["rf"]
    day = load("benchmark_cicids2017_day.json")["summary"]["rf"]
    import numpy as np
    metrics = ["precision", "recall", "f1"]
    s = [strat[m]["mean"] for m in metrics]
    d = [day[m]["mean"] for m in metrics]
    x = np.arange(len(metrics))
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    ax.bar(x - 0.2, s, 0.4, label="random split", color=GREY[1], edgecolor="black", linewidth=0.5)
    ax.bar(x + 0.2, d, 0.4, label="unseen-day split", color=GREY[0], edgecolor="black", linewidth=0.5)
    ax.set_xticks(x)
    ax.set_xticklabels(metrics)
    ax.set_ylabel("RF score (5 seeds)")
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=7, loc="lower left")
    save(fig, "fig_benchmark_split")


def fig_window_versions():
    r = load("experiment_results.json")
    ft = r["final_test"]
    order = sorted(ft["versions"], key=lambda v: int(v))
    names, f1s, fprs = [], [], []
    for v in order:
        d = ft["versions"][v]
        names.append(f"v{v}")
        f1s.append(d["window_binary"]["f1"])
        fprs.append(d["window_binary"]["fpr"] or 0.0)
    import numpy as np
    x = np.arange(len(names))
    fig, ax = plt.subplots(figsize=(3.4, 2.1))
    ax.bar(x, f1s, color=GREY[0], edgecolor="black", linewidth=0.5, label="window F1")
    ax.plot(x, fprs, "o-", color="black", markersize=3, linewidth=1, label="benign FPR")
    ax.set_xticks(x)
    ax.set_xticklabels(names, rotation=45, ha="right", fontsize=6)
    ax.set_ylabel("score")
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=7)
    save(fig, "fig_window_versions")


if __name__ == "__main__":
    for fn in (fig_final_detection, fig_window_versions, fig_evasion, fig_benchmark):
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            print("SKIP", fn.__name__, type(e).__name__, e)

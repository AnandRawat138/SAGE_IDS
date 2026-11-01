"""Benchmark pipeline (CICIDS2017 primary, UNSW-NB15 optional). Separate model + schema from the lab model.

Order of operations (leakage prevention):
  load -> schema check -> quality report -> clean & DEDUPLICATE (before split) -> split ->
  cross-split overlap assertion -> fit preprocessing (constant-column removal) on TRAIN only ->
  imbalance handling on TRAIN only (class weights) -> fit -> choose decision threshold on VALIDATION
  -> evaluate once on TEST.  Repeated over seeds; artifacts and manifests versioned together.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (confusion_matrix, precision_recall_curve, precision_recall_fscore_support,
                             roc_auc_score)

from ..audit import canonical, sha256_hex
from ..config import PROJECT_ROOT
from ..evaluation.stats import bootstrap_ci
from . import cicids2017, unsw_nb15
from .leakage import assert_disjoint, constant_columns, day_split, stratified_split


def _binary_metrics(y: np.ndarray, pred: np.ndarray, score: np.ndarray | None = None) -> dict:
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {"precision": float(p), "recall": float(r), "f1": float(f), "fpr": float(fp / (fp + tn)) if fp + tn else None,
           "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)}
    if score is not None and len(np.unique(y)) == 2:
        out["roc_auc"] = float(roc_auc_score(y, score))
    return out


def _run_seed(train, val, test, features, seed: int, out: Path, n_estimators: int) -> dict:
    const = constant_columns(train, features)
    feats = [f for f in features if f not in const]
    Xtr, Xva, Xte = (d[feats].to_numpy(dtype="float32") for d in (train, val, test))
    ytr, yva, yte = ((d["Label"] != "BENIGN").astype(int).to_numpy() for d in (train, val, test))
    t0 = time.perf_counter()
    rf = RandomForestClassifier(n_estimators=n_estimators, min_samples_leaf=1, class_weight="balanced_subsample",
                                n_jobs=-1, random_state=seed).fit(Xtr, ytr)
    train_s = time.perf_counter() - t0
    # decision threshold chosen on VALIDATION only (max F1); test is touched once
    pv = rf.predict_proba(Xva)[:, 1]
    prec, rec, thr = precision_recall_curve(yva, pv)
    f1 = 2 * prec * rec / np.clip(prec + rec, 1e-12, None)
    th = float(thr[np.nanargmax(f1[:-1])]) if len(thr) else 0.5
    t0 = time.perf_counter()
    pt = rf.predict_proba(Xte)[:, 1]
    infer_s = time.perf_counter() - t0
    res = {"seed": seed, "threshold_from_validation": th, "dropped_constant_columns_train": const,
           "train_rows": int(len(train)), "val_rows": int(len(val)), "test_rows": int(len(test)),
           "rf": _binary_metrics(yte, (pt >= th).astype(int), pt),
           "rf_default_0.5": _binary_metrics(yte, (pt >= 0.5).astype(int), pt),
           "train_seconds": train_s, "inference_ms_per_1k": 1000 * infer_s / max(len(test), 1) * 1000}
    # multi-class model for class-wise metrics (same train data, same seed)
    mc = RandomForestClassifier(n_estimators=n_estimators, class_weight="balanced_subsample", n_jobs=-1,
                                random_state=seed).fit(Xtr, train["Label"])
    mp = mc.predict(Xte)
    labels = sorted(set(train["Label"]) | set(test["Label"]))
    p, r, f, s = precision_recall_fscore_support(test["Label"], mp, labels=labels, zero_division=0)
    res["per_class"] = {lbl: {"precision": float(p[i]), "recall": float(r[i]), "f1": float(f[i]), "support": int(s[i])}
                        for i, lbl in enumerate(labels)}
    res["macro_f1"] = float(np.mean([v["f1"] for v in res["per_class"].values() if v["support"] > 0]))
    res["confusion_matrix"] = {"labels": labels, "matrix": confusion_matrix(test["Label"], mp, labels=labels).tolist()}
    # optional anomaly detector: Isolation Forest on TRAIN benign; threshold = 99th pct of train benign scores
    ben = Xtr[ytr == 0]
    ben = ben[np.random.default_rng(seed).choice(len(ben), size=min(len(ben), 100_000), replace=False)]
    iso = IsolationForest(n_estimators=200, random_state=seed).fit(ben)
    thr_if = float(np.quantile(-iso.score_samples(ben), 0.99))
    st = -iso.score_samples(Xte)
    res["iforest"] = _binary_metrics(yte, (st >= thr_if).astype(int), st)
    res["top_features"] = sorted(zip(feats, map(float, rf.feature_importances_)), key=lambda x: -x[1])[:10]
    d = out / f"seed_{seed}"
    d.mkdir(parents=True, exist_ok=True)
    joblib.dump(rf, d / "rf_binary.joblib")
    (d / "preprocessing.json").write_text(json.dumps({"features_used": feats, "dropped_constant": const,
                                                      "label_positive": "not BENIGN", "threshold": th}, indent=2))
    (d / "metrics.json").write_text(json.dumps(res, indent=2))
    return res


def run_benchmark(dataset: str, data_dir: Path, split: str, seeds: list[int], out_dir: Path,
                  max_rows: int | None = None, n_estimators: int = 100, artifacts_root: Path | None = None) -> dict:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    art = (artifacts_root or PROJECT_ROOT / "artifacts") / "benchmark" / dataset / stamp
    art.mkdir(parents=True, exist_ok=True)
    if dataset == "cicids2017":
        df, manifest = cicids2017.load(data_dir, max_rows=max_rows)
        feats = cicids2017.FEATURES
        quality = cicids2017.quality_report(df, feats)
        df, cleaning = cicids2017.clean(df, feats)
        splits_fn = (lambda sd: day_split(df, sd)) if split == "day" else (lambda sd: stratified_split(df, sd))
    else:
        tr_raw, te_raw, manifest = unsw_nb15.load(data_dir)
        Xtr, Xte, feats = unsw_nb15.encode(tr_raw, te_raw)
        tr_all = pd.concat([Xtr, tr_raw[["Label"]]], axis=1)
        te_all = pd.concat([Xte, te_raw[["Label"]]], axis=1)
        quality = {"train": cicids2017.quality_report(tr_all, feats), "test": cicids2017.quality_report(te_all, feats)}
        tr_all, c1 = cicids2017.clean(tr_all, feats)
        te_all, c2 = cicids2017.clean(te_all, feats)
        # remove test rows identical to training rows (known cross-partition duplicates)
        from .leakage import row_hashes
        dup = row_hashes(te_all[feats]).isin(set(row_hashes(tr_all[feats])))
        te_all = te_all[~dup].reset_index(drop=True)
        cleaning = {"train": c1, "test": c2, "test_rows_removed_as_duplicates_of_train": int(dup.sum())}

        def splits_fn(sd):
            from sklearn.model_selection import train_test_split
            tr, va = train_test_split(tr_all, test_size=0.2, stratify=tr_all["Label"], random_state=sd)
            return tr.reset_index(drop=True), va.reset_index(drop=True), te_all
        split = "official-partition"
    per_seed, leakage = [], {}
    for sd in seeds:
        tr, va, te = splits_fn(sd)
        leakage[sd] = assert_disjoint({"train": tr, "val": va, "test": te}, feats)
        per_seed.append(_run_seed(tr, va, te, feats, sd, art, n_estimators))

    def agg(key, sub="rf"):
        vals = [r[sub][key] for r in per_seed if r[sub].get(key) is not None]
        m, lo, hi = bootstrap_ci(vals)
        return {"mean": m, "ci95": [lo, hi], "values": vals}
    summary = {"dataset": dataset, "split": split, "seeds": seeds, "rows_after_cleaning": cleaning,
               "rf": {k: agg(k) for k in ("precision", "recall", "f1", "fpr", "roc_auc")},
               "iforest": {k: agg(k, "iforest") for k in ("precision", "recall", "f1", "fpr")},
               "macro_f1_multiclass": bootstrap_ci([r["macro_f1"] for r in per_seed])[:3],
               "inference_ms_per_1k": float(np.mean([r["inference_ms_per_1k"] for r in per_seed]))}
    result = {"summary": summary, "manifest": manifest, "quality": quality, "cleaning": cleaning,
              "leakage_overlaps": leakage, "per_seed": per_seed, "artifacts": str(art),
              "versions": {"sklearn": sklearn.__version__, "numpy": np.__version__, "pandas": pd.__version__},
              "config": {"split": split, "seeds": seeds, "max_rows_per_file": max_rows, "n_estimators": n_estimators}}
    result["result_hash"] = sha256_hex(canonical(result))
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"benchmark_{dataset}_{split}.json").write_text(json.dumps(result, indent=2, default=str))
    _write_md(result, out_dir / f"benchmark_{dataset}_{split}.md")
    return result


def _write_md(r: dict, path: Path) -> None:
    s = r["summary"]
    L = [f"# Benchmark: {s['dataset']} ({s['split']} split)", "",
         "Generated from actual execution; separate model and feature schema from the laboratory model.", "",
         f"- Seeds: {s['seeds']}; config: {r['config']}; versions: {r['versions']}",
         f"- Input files: " + ", ".join(f"{f['file']} (sha256 {f['sha256'][:12]}…)" for f in r["manifest"]["files"]),
         f"- Cleaning (before split): {r['cleaning']}",
         f"- Cross-split identical-row overlaps (must be 0): {r['leakage_overlaps']}", "",
         "| detector | precision | recall | F1 | FPR | ROC-AUC |", "|---|---|---|---|---|---|"]
    for det in ("rf", "iforest"):
        row = [det]
        for k in ("precision", "recall", "f1", "fpr", "roc_auc"):
            v = s[det].get(k)
            row.append("—" if not v or v["mean"] != v["mean"] else f"{v['mean']:.4f} [{v['ci95'][0]:.4f}, {v['ci95'][1]:.4f}]")
        L.append("| " + " | ".join(row) + " |")
    L += ["", f"Multi-class macro-F1 (mean, 95% bootstrap CI over seeds): {s['macro_f1_multiclass']}",
          f"Inference: {s['inference_ms_per_1k']:.2f} ms per 1k flows", "", "## Per-class (seed %s)" % r["per_seed"][0]["seed"],
          "", "| class | precision | recall | F1 | support |", "|---|---|---|---|---|"]
    for c, m in r["per_seed"][0]["per_class"].items():
        L.append(f"| {c} | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1']:.4f} | {m['support']} |")
    L += ["", "## Data quality (before cleaning)", "", "```json", json.dumps(r["quality"], indent=1, default=str)[:4000], "```"]
    path.write_text("\n".join(L), encoding="utf-8")

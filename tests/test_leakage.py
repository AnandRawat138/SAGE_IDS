"""Leakage prevention in the benchmark pipeline (uses a tiny SYNTHETIC table in the CICIDS2017 schema)."""
import json

import numpy as np
import pandas as pd
import pytest

from sage_ids.data import cicids2017
from sage_ids.data.benchmark import run_benchmark
from sage_ids.data.leakage import LeakageError, assert_disjoint, constant_columns, stratified_split


def synthetic_cicids(n=1200, seed=0) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    df = pd.DataFrame(rng.random((n, len(cicids2017.FEATURES))) * 100, columns=cicids2017.FEATURES)
    labels = rng.choice(["BENIGN", "DoS Hulk", "PortScan"], size=n, p=[0.7, 0.2, 0.1])
    df.loc[labels == "DoS Hulk", "Flow Packets/s"] += 500
    df.loc[labels == "PortScan", "Destination Port"] += 1000
    df["Label"] = labels
    df["Bwd PSH Flags"] = 0.0                                  # constant column
    return df


def test_clean_removes_duplicates_invalid_and_conflicts():
    df = synthetic_cicids(300)
    df = pd.concat([df, df.iloc[:10]], ignore_index=True)      # exact duplicates
    conf = df.iloc[10:13].copy()
    conf["Label"] = "Bot"                                      # same features, different label
    df = pd.concat([df, conf], ignore_index=True)
    df.loc[100, "Flow Bytes/s"] = np.inf
    q = cicids2017.quality_report(df, cicids2017.FEATURES)
    assert q["exact_duplicate_rows"] == 10 and q["feature_duplicates_with_conflicting_labels"] == 3
    out, rep = cicids2017.clean(df, cicids2017.FEATURES)
    assert rep["dropped_invalid"] == 1 and rep["dropped_exact_duplicates"] == 10
    assert not out.duplicated(subset=cicids2017.FEATURES).any()


def test_split_after_dedup_is_disjoint_and_injected_leak_detected():
    df, _ = cicids2017.clean(synthetic_cicids(), cicids2017.FEATURES)
    tr, va, te = stratified_split(df, seed=1)
    assert sum(assert_disjoint({"train": tr, "val": va, "test": te}, cicids2017.FEATURES).values()) == 0
    leaky = pd.concat([te, tr.iloc[:3]], ignore_index=True)
    with pytest.raises(LeakageError):
        assert_disjoint({"train": tr, "test": leaky}, cicids2017.FEATURES)


def test_preprocessing_fitted_on_train_only():
    df, _ = cicids2017.clean(synthetic_cicids(), cicids2017.FEATURES)
    tr, _, te = stratified_split(df, seed=0)
    te = te.copy()
    te["Bwd PSH Flags"] = np.arange(len(te))                   # varies only in TEST
    assert "Bwd PSH Flags" in constant_columns(tr, cicids2017.FEATURES)


def test_schema_incompatibility(tmp_path):
    df = synthetic_cicids(50).drop(columns=["Flow Duration"])
    df.to_csv(tmp_path / "Monday-WorkingHours.pcap_ISCX.csv", index=False)
    with pytest.raises(cicids2017.SchemaIncompatible):
        cicids2017.load(tmp_path)


def test_benchmark_end_to_end_on_synthetic_fixture(tmp_path):
    d = tmp_path / "cic"
    d.mkdir()
    for day, seed in (("Monday", 0), ("Friday", 1)):
        df = synthetic_cicids(600, seed)
        df.columns = [" " + c if c != "Label" else " Label" for c in df.columns]   # leading spaces as published
        df.to_csv(d / f"{day}-WorkingHours.pcap_ISCX.csv", index=False)
    res = run_benchmark("cicids2017", d, "stratified", [0, 1], tmp_path / "out", n_estimators=20)
    assert all(v == 0 for o in res["leakage_overlaps"].values() for v in o.values())
    assert res["per_seed"][0]["dropped_constant_columns_train"] == ["Bwd PSH Flags"]
    assert 0 <= res["summary"]["rf"]["f1"]["mean"] <= 1
    assert json.loads((tmp_path / "out" / "benchmark_cicids2017_stratified.json").read_text())["result_hash"]

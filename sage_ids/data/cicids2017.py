"""CICIDS2017 (MachineLearningCVE CSVs) loader with schema validation and data-quality checks.

Download (not bundled; ~230 MB zip): Canadian Institute for Cybersecurity, "Intrusion Detection
Evaluation Dataset (CIC-IDS2017)", https://www.unb.ca/cic/datasets/ids-2017.html -> MachineLearningCSV.zip.
Extract the 8 `*.pcap_ISCX.csv` files into one directory and pass it with --data-dir.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

import numpy as np
import pandas as pd

from ..detection.features import SchemaIncompatible

FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std", "Bwd Packet Length Max",
    "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std", "Flow Bytes/s",
    "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags",
    "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets",
    "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
    "Idle Std", "Idle Max", "Idle Min"]
LABEL = "Label"
DUPLICATE_COLUMNS = ["Fwd Header Length.1"]   # exact copy of Fwd Header Length in the published CSVs
SCHEMA_ID = "cicids2017-mlcve-v1"
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]


def _norm_label(x: str) -> str:
    x = str(x).strip()
    # the published CSVs contain a mis-encoded dash ("�" or its latin-1 rendering "ï¿½")
    x = re.sub(r"^Web Attack\s*\S*\s+(?=Brute Force|XSS|Sql Injection)", "Web Attack - ", x)
    return "BENIGN" if x.upper() == "BENIGN" else x


def file_manifest(files: list[Path]) -> list[dict]:
    out = []
    for f in files:
        h = hashlib.sha256()
        with open(f, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        out.append({"file": f.name, "bytes": f.stat().st_size, "sha256": h.hexdigest()})
    return out


def load(data_dir: Path, max_rows: int | None = None, seed: int = 0) -> tuple[pd.DataFrame, dict]:
    files = sorted(data_dir.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"no CICIDS2017 CSV files in {data_dir}")
    frames = []
    for f in files:
        df = pd.read_csv(f, encoding="latin-1", low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        missing = [c for c in FEATURES + [LABEL] if c not in df.columns]
        if missing:
            raise SchemaIncompatible(f"{f.name}: missing CICIDS2017 columns {missing[:5]}… ({len(missing)})")
        df = df[FEATURES + [LABEL]]
        if max_rows and len(df) > max_rows:
            df = df.sample(n=max_rows, random_state=seed)        # documented subsample
        df["day"] = next((d for d in DAYS if d.lower() in f.name.lower()), "unknown")
        df["source_file"] = f.name
        frames.append(df)
    df = pd.concat(frames, ignore_index=True)
    df[LABEL] = df[LABEL].map(_norm_label)
    for c in FEATURES:
        df[c] = pd.to_numeric(df[c], errors="coerce").astype("float32")   # float32 halves memory
    return df, {"files": file_manifest(files), "schema": SCHEMA_ID, "max_rows_per_file": max_rows}


def quality_report(df: pd.DataFrame, features: list[str]) -> dict:
    X = df[features].to_numpy(dtype="float32")
    inf = np.isinf(X).sum(axis=0)
    nan = np.isnan(X).sum(axis=0)
    feat_dups = df.duplicated(subset=features, keep=False)
    conflicting = df[feat_dups].groupby(features, dropna=False)["Label"].nunique()
    return {"rows": int(len(df)),
            "rows_with_inf": int(np.isinf(X).any(axis=1).sum()),
            "rows_with_nan": int(np.isnan(X).any(axis=1).sum()),
            "inf_columns": {f: int(n) for f, n in zip(features, inf) if n},
            "nan_columns": {f: int(n) for f, n in zip(features, nan) if n},
            "exact_duplicate_rows": int(df.duplicated(subset=features + ["Label"]).sum()),
            "feature_duplicates_with_conflicting_labels": int((conflicting > 1).sum()),
            "negative_values_in_nonnegative_columns": {c: int((df[c] < 0).sum()) for c in
                                                       ("Flow Duration", "Flow Bytes/s", "Flow Packets/s")
                                                       if (df[c] < 0).any()},
            "class_counts": df["Label"].value_counts().to_dict()}


def clean(df: pd.DataFrame, features: list[str]) -> tuple[pd.DataFrame, dict]:
    """Remove invalid rows, then exact duplicates and label-conflicting feature duplicates.
    Done BEFORE splitting so identical rows cannot appear in both train and test."""
    n0 = len(df)
    valid = np.isfinite(df[features].to_numpy(dtype="float32")).all(axis=1)   # one mask, no full-table copies
    df = df[valid]
    n_invalid = n0 - len(df)
    n1 = len(df)
    df = df.drop_duplicates(subset=features + ["Label"])
    n_dup = n1 - len(df)
    conflict_mask = df.duplicated(subset=features, keep=False)
    n_conf = int(conflict_mask.sum())
    df = df[~conflict_mask]
    return df.reset_index(drop=True), {"dropped_invalid": n_invalid, "dropped_exact_duplicates": n_dup,
                                       "dropped_conflicting_label_rows": n_conf, "rows_after": int(len(df))}

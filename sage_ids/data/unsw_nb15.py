"""UNSW-NB15 (optional, evaluated SEPARATELY; its schema is never merged with CICIDS2017).

Download: https://research.unsw.edu.au/projects/unsw-nb15-dataset -> "UNSW_NB15_training-set.csv" and
"UNSW_NB15_testing-set.csv". Place both in one directory and pass it with --data-dir.
The official train/test partition is used; categorical encoders are fitted on the training set only.
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

from ..detection.features import SchemaIncompatible
from .cicids2017 import file_manifest

CATEGORICAL = ["proto", "service", "state"]
DROP = ["id", "attack_cat", "label"]
SCHEMA_ID = "unsw-nb15-partition-v1"


def load(data_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    tr, te = data_dir / "UNSW_NB15_training-set.csv", data_dir / "UNSW_NB15_testing-set.csv"
    if not tr.exists() or not te.exists():
        raise FileNotFoundError("expected UNSW_NB15_training-set.csv and UNSW_NB15_testing-set.csv")
    a, b = pd.read_csv(tr), pd.read_csv(te)
    for df, name in ((a, tr.name), (b, te.name)):
        miss = [c for c in CATEGORICAL + ["attack_cat", "label"] if c not in df.columns]
        if miss:
            raise SchemaIncompatible(f"{name}: missing {miss}")
    for df in (a, b):
        df["Label"] = df["attack_cat"].fillna("Normal").str.strip().replace({"Normal": "BENIGN"})
    return a, b, {"files": file_manifest([tr, te]), "schema": SCHEMA_ID}


def encode(train: pd.DataFrame, test: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, list[str]]:
    num = [c for c in train.columns if c not in CATEGORICAL + DROP + ["Label"]]
    cats = {c: sorted(train[c].astype(str).unique()) for c in CATEGORICAL}   # fitted on train only

    def enc(df: pd.DataFrame) -> pd.DataFrame:
        out = df[num].astype("float64").copy()
        for c, vals in cats.items():
            col = df[c].astype(str)
            for v in vals:
                out[f"{c}={v}"] = (col == v).astype("float64")
            out[f"{c}=<unseen>"] = (~col.isin(vals)).astype("float64")
        return out

    Xtr, Xte = enc(train), enc(test)
    return Xtr, Xte, list(Xtr.columns)

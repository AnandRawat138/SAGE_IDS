"""Leakage controls for benchmark experiments."""
from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


class LeakageError(AssertionError):
    pass


def row_hashes(X: pd.DataFrame) -> pd.Series:
    """Exact-value row hashes (same equality as drop_duplicates). Values are widened to float64, which is
    exact for float32, and -0.0 is folded to 0.0. No rounding: DataFrame.round() on float32 columns
    corrupts large values (e.g. 32036248 -> 32036246) and would merge distinct rows."""
    arr = X.to_numpy(dtype="float64", copy=True)
    arr[arr == 0] = 0.0
    return pd.util.hash_pandas_object(pd.DataFrame(arr), index=False)


def overlap_count(a: pd.DataFrame, b: pd.DataFrame) -> int:
    return int(row_hashes(a).isin(set(row_hashes(b))).sum())


def assert_disjoint(splits: dict[str, pd.DataFrame], features: list[str]) -> dict[str, int]:
    names = list(splits)
    out = {}
    for i, x in enumerate(names):
        for y in names[i + 1:]:
            n = overlap_count(splits[x][features], splits[y][features])
            out[f"{x}&{y}"] = n
            if n:
                raise LeakageError(f"{n} identical feature rows appear in both {x} and {y}")
    return out


def stratified_split(df: pd.DataFrame, seed: int, label: str = "Label", test: float = 0.2, val: float = 0.2):
    """60/20/20 stratified split; rare classes (<3 rows) are kept in train only."""
    counts = df[label].value_counts()
    rare = df[label].isin(counts[counts < 5].index)
    common = df[~rare]
    tr, te = train_test_split(common, test_size=test, stratify=common[label], random_state=seed)
    tr, va = train_test_split(tr, test_size=val / (1 - test), stratify=tr[label], random_state=seed)
    tr = pd.concat([tr, df[rare]])
    return tr.reset_index(drop=True), va.reset_index(drop=True), te.reset_index(drop=True)


def day_split(df: pd.DataFrame, seed: int, test_days=("Friday",), label: str = "Label"):
    """Train on earlier capture days, test on held-out later day(s): unseen attack families."""
    te = df[df["day"].isin(test_days)]
    rest = df[~df["day"].isin(test_days)]
    counts = rest[label].value_counts()
    rare = rest[label].isin(counts[counts < 5].index)
    tr, va = train_test_split(rest[~rare], test_size=0.2, stratify=rest[~rare][label], random_state=seed)
    return pd.concat([tr, rest[rare]]).reset_index(drop=True), va.reset_index(drop=True), te.reset_index(drop=True)


def constant_columns(train: pd.DataFrame, features: list[str]) -> list[str]:
    """Determined on TRAIN ONLY."""
    return [f for f in features if np.nanstd(train[f].to_numpy(dtype=float)) == 0.0]

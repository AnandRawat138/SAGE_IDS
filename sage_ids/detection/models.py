"""Laboratory ML detectors: Random Forest (supervised baseline) + Isolation Forest (optional anomaly).

Trained only on windows whose labels are verified by construction (benign generator sources or
executed scenario runs). The bundle is versioned together with its feature schema and label set.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from .features import FEATURES, SCHEMA_HASH, SCHEMA_VERSION, check_feature_schema, feature_matrix


@dataclass
class LabModelBundle:
    rf: RandomForestClassifier
    iforest: IsolationForest | None
    iforest_threshold: float | None
    classes: list[str]
    schema_version: str = SCHEMA_VERSION
    schema_hash: str = SCHEMA_HASH
    card: dict = field(default_factory=dict)

    def predict(self, windows: pd.DataFrame) -> pd.DataFrame:
        check_feature_schema(windows.columns, self.schema_version, self.schema_hash)
        X = feature_matrix(windows)
        proba = self.rf.predict_proba(X)
        idx = proba.argmax(axis=1)
        out = pd.DataFrame({"rf_label": [self.classes[i] for i in idx], "rf_conf": proba.max(axis=1)})
        out["rf_attack_score"] = 1.0 - proba[:, self.classes.index("benign")] if "benign" in self.classes else 1.0
        if self.iforest is not None:
            s = -self.iforest.score_samples(X)          # higher = more anomalous
            out["if_score"] = s
            out["if_alert"] = s >= self.iforest_threshold
        else:
            out["if_score"] = np.nan
            out["if_alert"] = False
        return out


def label_set_digest(window_ids: list[int], labels: list[str]) -> str:
    return hashlib.sha256(json.dumps(sorted(zip(window_ids, labels))).encode()).hexdigest()


def train_bundle(windows: pd.DataFrame, labels: pd.Series, seed: int, if_benign_quantile: float = 0.99,
                 window_ids: list[int] | None = None) -> LabModelBundle:
    if labels.nunique() < 2:
        raise ValueError("training requires at least two verified classes")
    if labels.isna().any():
        raise ValueError("unverified (unlabelled) windows must not enter training")
    X = feature_matrix(windows)
    y = labels.to_numpy()
    rf = RandomForestClassifier(n_estimators=200, min_samples_leaf=2, class_weight="balanced_subsample",
                                random_state=seed, n_jobs=1)
    rf.fit(X, y)
    benign = X[y == "benign"]
    iforest, thr = None, None
    if len(benign) >= 20:
        iforest = IsolationForest(n_estimators=200, random_state=seed, contamination="auto").fit(benign)
        thr = float(np.quantile(-iforest.score_samples(benign), if_benign_quantile))
    counts = pd.Series(y).value_counts().to_dict()
    card = {"schema_version": SCHEMA_VERSION, "schema_hash": SCHEMA_HASH, "features": FEATURES,
            "seed": seed, "n_train": int(len(y)), "label_counts": {k: int(v) for k, v in counts.items()},
            "label_set_digest": label_set_digest(window_ids or list(range(len(y))), list(map(str, y))),
            "sklearn_version": sklearn.__version__, "rf_params": rf.get_params(),
            "iforest_benign_quantile": if_benign_quantile, "iforest_threshold": thr}
    return LabModelBundle(rf=rf, iforest=iforest, iforest_threshold=thr, classes=list(rf.classes_), card=card)


def save_bundle(bundle: LabModelBundle, path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)
    path.with_suffix(".card.json").write_text(json.dumps(bundle.card, indent=2, default=str))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_bundle(path: str | Path, expected_sha256: str | None = None) -> LabModelBundle:
    path = Path(path)
    if expected_sha256 and hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha256:
        raise ValueError(f"model artifact {path} does not match recorded SHA-256 (tampered or replaced)")
    return joblib.load(path)

"""Threshold rule engine over lab-v1 window features (approved rule template: `threshold`).

Rules are data (validated `RuleSpec`), never code. `sliding_crossings` evaluates rules online over a
sliding per-source window; the first crossing is the alert time used for latency measurement.
"""
from __future__ import annotations

import operator

import pandas as pd

from ..schemas import RuleSpec

OPS = {">=": operator.ge, ">": operator.gt}


def rule_fires(rule: RuleSpec, feats: dict) -> bool:
    return OPS[rule.op](float(feats[rule.feature]), rule.threshold)


def evaluate_rules(rules: list[RuleSpec], feats: dict) -> list[RuleSpec]:
    return [r for r in rules if rule_fires(r, feats)]


def sliding_features(src_events: pd.DataFrame, window_s: float):
    """Yield (t, features) after each event of ONE source over the sliding window (t - window_s, t].
    Feature definitions are identical to lab-v1; only the window slides, so an attack is not split
    by a tumbling-window boundary."""
    from collections import Counter, deque

    ev = src_events.sort_values("ts")
    q: deque = deque()
    ports: Counter = Counter()
    c = dict(n_events=0, n_http=0, n_auth=0, n_auth_fail=0, n_http_429=0, n_http_4xx=0,
             n_conn_refused_like=0, n_auth_success=0)

    def contrib(row) -> dict:  # noqa: ANN001
        status = str(row.status)
        is_http = len(status) == 3 and status.isdigit()
        code = int(status) if is_http else 0
        auth = is_http and row.service == "login"
        return dict(n_events=1, n_http=int(is_http), n_auth=int(auth), n_auth_fail=int(auth and code in (401, 423)),
                    n_http_429=int(code == 429), n_http_4xx=int(400 <= code <= 499),
                    n_conn_refused_like=int(status == "conn" and int(row.bytes_out) == 0),
                    n_auth_success=int(auth and code == 200))

    for row in ev.itertuples(index=False):
        t = float(row.ts)
        d = contrib(row)
        q.append((t, int(row.dst_port), d))
        ports[int(row.dst_port)] += 1
        for k, v in d.items():
            c[k] += v
        while q and q[0][0] <= t - window_s:
            t0, p0, d0 = q.popleft()
            ports[p0] -= 1
            if not ports[p0]:
                del ports[p0]
            for k, v in d0.items():
                c[k] -= v
        span = t - q[0][0]
        feats = dict(c, n_distinct_dst_ports=len(ports), req_rate=c["n_http"] / max(span, 1.0),
                     frac_auth_fail=c["n_auth_fail"] / c["n_auth"] if c["n_auth"] else 0.0)
        yield t, feats


def sliding_crossings(rule: RuleSpec, src_events: pd.DataFrame, window_s: float) -> list[float]:
    """Timestamps at which the rule holds on the sliding window (rule alerting + online latency)."""
    return [t for t, f in sliding_features(src_events, window_s) if rule_fires(rule, f)]


def sliding_max(feature: str, events: pd.DataFrame, window_s: float) -> dict[str, float]:
    """Per-source maximum of a feature over all sliding windows (used for threshold calibration)."""
    return {src: max((f[feature] for _, f in sliding_features(g, window_s)), default=0.0)
            for src, g in events.groupby("src_ip")}


def load_rules(raw: list[dict]) -> list[RuleSpec]:
    return [RuleSpec.model_validate(r) for r in raw]

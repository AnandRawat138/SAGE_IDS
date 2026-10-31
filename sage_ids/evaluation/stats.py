"""Statistics used for validation: interval estimates and paired tests (no fabricated numbers)."""
from __future__ import annotations

import math

import numpy as np
from scipy import stats


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float, float]:
    """Point estimate and Wilson score interval for a binomial proportion."""
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float, float]:
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    lo = 0.0 if k == 0 else stats.beta.ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else stats.beta.ppf(1 - alpha / 2, k + 1, n - k)
    return k / n, float(lo), float(hi)


def mcnemar_exact(baseline: list[bool], candidate: list[bool], alternative: str = "greater") -> dict:
    """Exact McNemar test on paired binary outcomes (same trials, two detectors).
    b = baseline missed & candidate detected; c = baseline detected & candidate missed.
    alternative='greater' tests H1: candidate detects more often than baseline."""
    if len(baseline) != len(candidate):
        raise ValueError("paired outcomes must have equal length")
    b = sum((not x) and y for x, y in zip(baseline, candidate))
    c = sum(x and (not y) for x, y in zip(baseline, candidate))
    n = b + c
    if n == 0:
        p = 1.0
    elif alternative == "greater":
        p = float(stats.binomtest(b, n, 0.5, alternative="greater").pvalue)
    else:
        p = float(stats.binomtest(b, n, 0.5, alternative="two-sided").pvalue)
    return {"b_candidate_only": int(b), "c_baseline_only": int(c), "discordant": int(n), "p_value": p,
            "alternative": alternative}


def fisher_greater(k1: int, n1: int, k2: int, n2: int) -> float:
    """One-sided Fisher exact p-value for H1: rate1 > rate2."""
    if n1 == 0 or n2 == 0:
        return 1.0
    return float(stats.fisher_exact([[k1, n1 - k1], [k2, n2 - k2]], alternative="greater").pvalue)


def bootstrap_ci(values, n_boot: int = 2000, alpha: float = 0.05, seed: int = 0) -> tuple[float, float, float]:
    v = np.asarray(list(values), dtype=float)
    if len(v) == 0:
        return float("nan"), float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    means = rng.choice(v, size=(n_boot, len(v)), replace=True).mean(axis=1)
    return float(v.mean()), float(np.quantile(means, alpha / 2)), float(np.quantile(means, 1 - alpha / 2))


def fmt_rate(k: int, n: int) -> str:
    p, lo, hi = wilson(k, n)
    return "n/a (n=0)" if n == 0 else f"{k}/{n} = {p:.3f} [95% CI {lo:.3f}-{hi:.3f}]"

"""Uncertainty for the detection scores: a paired bootstrap that resamples whole replay windows.

The scores are computed on (window, source) pairs, but pairs in the same window (and neighbouring windows of
one attack) are not independent, so resampling single pairs would give intervals that are too narrow. Here the
unit that is resampled is the window, within each slice, and every system is scored on the SAME resampled
windows, so the difference between two systems has a meaningful interval too.

Plain arithmetic, no LLM, no labels beyond the truth keys the grader already built.
"""
from __future__ import annotations

from collections.abc import Collection, Mapping

import numpy as np

Key = tuple[int, str]          # (window index, source address)


def window_counts(pred: Collection[Key], truth: Collection[Key], n_windows: int) -> np.ndarray:
    """Per-window [tp, fp, fn] counts as an (n_windows, 3) integer array."""
    p, t = set(pred), set(truth)
    out = np.zeros((n_windows, 3), dtype=np.int64)
    for w, _ in p & t:
        out[w, 0] += 1
    for w, _ in p - t:
        out[w, 1] += 1
    for w, _ in t - p:
        out[w, 2] += 1
    return out


def prf(tp: float, fp: float, fn: float) -> tuple[float, float, float]:
    """(precision, recall, F1); 0 where undefined."""
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return p, r, (2 * p * r / (p + r) if p + r else 0.0)


def pooled(counts: Mapping[str, np.ndarray]) -> tuple[float, float, float]:
    """Point estimate pooled over slices (the same micro-average the evaluation reports)."""
    tp, fp, fn = np.sum([c.sum(axis=0) for c in counts.values()], axis=0)
    return prf(float(tp), float(fp), float(fn))


def bootstrap(counts: Mapping[str, Mapping[str, np.ndarray]], n: int = 2000, seed: int = 0) -> dict[str, np.ndarray]:
    """Paired window bootstrap of pooled (precision, recall, F1).

    counts: system -> slice -> (n_windows, 3) array from `window_counts`. All systems must cover the same
    slices with the same number of windows. Returns system -> (n, 3) array of draws.
    """
    systems = list(counts)
    slices = sorted(counts[systems[0]])
    for s in systems:
        if sorted(counts[s]) != slices or any(counts[s][sl].shape != counts[systems[0]][sl].shape for sl in slices):
            raise ValueError(f"system '{s}' does not cover the same slices and windows as '{systems[0]}'")
    rng = np.random.default_rng(seed)
    tot = {s: np.zeros((n, 3)) for s in systems}
    for sl in slices:
        nw = counts[systems[0]][sl].shape[0]
        idx = rng.integers(0, nw, size=(n, nw))                  # same resampled windows for every system
        for s in systems:
            tot[s] += counts[s][sl][idx].sum(axis=1)
    out = {}
    for s in systems:
        out[s] = np.array([prf(*row) for row in tot[s]])
    return out


def interval(draws: np.ndarray, level: float = 0.95) -> tuple[float, float]:
    lo = (1 - level) / 2 * 100
    a, b = np.percentile(draws, [lo, 100 - lo])
    return float(a), float(b)


def paired_difference(a: np.ndarray, b: np.ndarray, column: int = 2) -> dict[str, float]:
    """Difference a - b of one metric (default F1) over the shared draws."""
    d = a[:, column] - b[:, column]
    lo, hi = interval(d)
    return {"mean": round(float(d.mean()), 3), "lo": round(lo, 3), "hi": round(hi, 3),
            "share_positive": round(float((d > 0).mean()), 3)}

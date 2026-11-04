"""The saved per-window predictions must reproduce the numbers in results/final.json (no silent drift)."""
import json
from pathlib import Path

import numpy as np

from huntcrew.stats import window_counts

RES = Path(__file__).resolve().parents[1] / "results"


def _micro(systems: list[str]) -> dict[str, tuple[int, int, int]]:
    pred = json.loads((RES / "predictions_test.json").read_text())
    out = {}
    for s in systems:
        tot = np.zeros(3, dtype=int)
        for sl in pred["slices"].values():
            tot += window_counts({tuple(k) for k in sl["systems"][s]}, {tuple(k) for k in sl["truth"]},
                                 sl["windows"]).sum(axis=0)
        out[s] = (int(tot[0]), int(tot[1]), int(tot[2]))
    return out


def test_predictions_reproduce_the_frozen_micro_averages():
    final = json.loads((RES / "final.json").read_text())["micro_average"]
    got = _micro(["b0", "agent", "hybrid"])
    for s, (tp, fp, fn) in got.items():
        assert (tp, fp, fn) == (final[s]["tp"], final[s]["fp"], final[s]["fn"]), s


def test_predictions_reproduce_the_post_hoc_cheap_baselines():
    post = json.loads((RES / "final.json").read_text())["post_hoc_cheap_baselines"]["micro_average"]
    got = _micro(["b2", "b3", "b4"])
    for s, (tp, fp, fn) in got.items():
        assert (tp, fp, fn) == (post[s]["tp"], post[s]["fp"], post[s]["fn"]), s


def test_predictions_reproduce_the_post_hoc_union_result():
    post = json.loads((RES / "final.json").read_text())["post_hoc_union"]["micro_average"]
    tp, fp, fn = _micro(["union"])["union"]
    assert (tp, fp, fn) == (post["tp"], post["fp"], post["fn"])

import numpy as np
import pytest

from huntcrew.stats import bootstrap, interval, paired_difference, pooled, prf, window_counts


def test_window_counts_splits_tp_fp_fn_per_window():
    pred = {(0, "A"), (0, "B"), (2, "A")}
    truth = {(0, "A"), (1, "C"), (2, "A")}
    c = window_counts(pred, truth, 3)
    assert c.tolist() == [[1, 1, 0], [0, 0, 1], [1, 0, 0]]          # w0: tp A, fp B ; w1: fn C ; w2: tp A


def test_prf_edges():
    assert prf(0, 0, 0) == (0.0, 0.0, 0.0)
    assert prf(5, 0, 5) == (1.0, 0.5, pytest.approx(2 / 3))


def test_pooled_matches_the_micro_average_not_the_mean_of_slices():
    counts = {"a": np.array([[9, 1, 0]]), "b": np.array([[0, 0, 10]])}
    p, r, f = pooled(counts)
    assert (p, r) == (0.9, 9 / 19) and f == pytest.approx(prf(9, 1, 10)[2])


def _counts(n_windows=30, seed=0):
    rng = np.random.default_rng(seed)
    return rng.integers(0, 4, size=(n_windows, 3))


def test_identical_systems_have_identical_draws_and_zero_difference():
    c = _counts()
    d = bootstrap({"x": {"s": c}, "y": {"s": c.copy()}}, n=200, seed=1)
    assert np.array_equal(d["x"], d["y"])
    diff = paired_difference(d["x"], d["y"])
    assert diff["mean"] == 0 and diff["lo"] == 0 == diff["hi"]


def test_clearly_better_system_has_interval_above_the_worse_one():
    good = {"s": np.tile([2, 0, 0], (40, 1))}          # always right
    bad = {"s": np.tile([0, 2, 2], (40, 1))}           # always wrong
    d = bootstrap({"good": good, "bad": bad}, n=300, seed=2)
    diff = paired_difference(d["good"], d["bad"])
    assert diff["lo"] > 0 and diff["share_positive"] == 1.0


def test_bootstrap_is_deterministic_for_a_seed_and_changes_with_it():
    c = {"x": {"s": _counts()}}
    a, b = bootstrap(c, n=100, seed=7), bootstrap(c, n=100, seed=7)
    assert np.array_equal(a["x"], b["x"]) and not np.array_equal(a["x"], bootstrap(c, n=100, seed=8)["x"])


def test_interval_contains_the_point_estimate_for_a_stable_system():
    c = {"x": {"s": np.tile([3, 1, 1], (50, 1))}}
    d = bootstrap(c, n=200, seed=0)["x"][:, 2]
    lo, hi = interval(d)
    assert lo <= prf(3, 1, 1)[2] <= hi


def test_mismatched_systems_are_rejected():
    with pytest.raises(ValueError):
        bootstrap({"x": {"s": _counts(10)}, "y": {"s": _counts(11)}}, n=10)
    with pytest.raises(ValueError):
        bootstrap({"x": {"s": _counts(10)}, "y": {"t": _counts(10)}}, n=10)

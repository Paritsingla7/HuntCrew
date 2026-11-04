from dataclasses import replace

import numpy as np
import pandas as pd
import pytest

from huntcrew.cheap_baselines import (
    DETECTORS,
    CheapModel,
    cheap_findings,
    filter_findings,
    flagged_sources,
    source_features,
)
from huntcrew.replay import Window
from huntcrew.schema import Finding

CFG = {"min_flows": 10, "features": ["flows", "dst_ports", "max_ports_per_dst", "top_port_share"],
       "quantile": {"q": 0.99}, "isolation_forest": {"n_estimators": 100, "flag_quantile": 0.97, "random_state": 0}}
W = Window(0, pd.Timestamp("2017-07-03 10:00"), pd.Timestamp("2017-07-03 10:05"))


def _rows(ts, src, n, dst_ports, dst="192.168.10.50"):
    return [dict(ts=pd.Timestamp(ts), src_ip=src, dst_ip=dst, dst_port=dst_ports[i % len(dst_ports)],
                 fwd_bytes=100, syn_count=1, rst_count=0, src_port=1000 + i) for i in range(n)]


def _benign(n_buckets=40, n_sources=15):
    """Ordinary hosts: a few to ~30 flows on 1-6 ports, plus a rare busy-but-benign tail (like a DNS server)."""
    rng = np.random.default_rng(0)
    rows = []
    for b in range(n_buckets):
        ts = pd.Timestamp("2017-07-03 09:00") + pd.Timedelta(minutes=5 * b, seconds=30)
        for s in range(n_sources):
            heavy = rng.random() < 0.03
            n = int(rng.integers(60, 90)) if heavy else int(rng.integers(2, 30))
            ports = list(range(1000, 1000 + (int(rng.integers(8, 14)) if heavy else int(rng.integers(1, 7)))))
            rows += _rows(ts, f"192.168.10.{s + 5}", n, ports)
    return pd.DataFrame(rows).sort_values("ts", kind="stable").reset_index(drop=True)


def _scanner(src="172.16.0.1", n=300):
    return pd.DataFrame(_rows("2017-07-03 10:01", src, n, list(range(1000, 1000 + n))))


@pytest.fixture(scope="module")
def model():
    return CheapModel.fit(_benign(), CFG, 5)


def test_source_features_are_plain_arithmetic():
    f = source_features(pd.concat([_scanner(n=20), pd.DataFrame(_rows("2017-07-03 10:02", "A", 4, [80, 80, 80, 443]))]), 5)
    row = f.droplevel(0).loc["172.16.0.1"]
    assert (row["flows"], row["dst_ports"], row["max_ports_per_dst"]) == (20, 20, 20)
    a = f.droplevel(0).loc["A"]
    assert a["top_port_share"] == 0.75 and a["dst_ips"] == 1


def test_scanner_flagged_by_both_detectors_and_normal_source_is_not(model):
    cur = pd.concat([_scanner(), pd.DataFrame(_rows("2017-07-03 10:02", "192.168.10.5", 12, [80, 443]))])
    for name in ("b2", "b3"):
        got = flagged_sources(model, name, cur)
        assert "172.16.0.1" in got and "192.168.10.5" not in got, name


def test_min_flows_gate_blocks_sources_below_the_floor(model):
    assert "172.16.0.1" in flagged_sources(model, "b2", _scanner(n=300))
    strict = replace(model, cfg={**model.cfg, "min_flows": 301})        # same model, higher floor
    assert flagged_sources(strict, "b2", _scanner(n=300)) == {}
    assert flagged_sources(strict, "b3", _scanner(n=300)) == {}


def test_empty_window_and_unknown_detector(model):
    empty = _benign().iloc[0:0]
    assert flagged_sources(model, "b2", empty) == {}
    with pytest.raises(KeyError):
        flagged_sources(model, "nope", empty)


def test_fit_rejects_empty_benign_and_unknown_feature():
    with pytest.raises(ValueError):
        CheapModel.fit(_benign().iloc[0:0], CFG, 5)
    with pytest.raises(ValueError):
        CheapModel.fit(_benign(), {**CFG, "features": ["flows", "label"]}, 5)


def test_isolation_forest_needs_its_config():
    m = CheapModel.fit(_benign(), {k: v for k, v in CFG.items() if k != "isolation_forest"}, 5)
    with pytest.raises(ValueError):
        flagged_sources(m, "b3", _scanner())


def test_findings_carry_no_technique_and_no_label(model):
    f = cheap_findings(model, "b2", _scanner(), W)
    assert len(f) == 1 and f[0].entity == "172.16.0.1" and f[0].technique_hints == []
    assert f[0].evidence["flows"] == 300.0 and f[0].window_start == W.start


def test_b4_filter_keeps_only_flagged_rule_findings():
    mk = lambda e: Finding(window_start=W.start, window_end=W.end, entity=e, behaviour="rule")  # noqa: E731
    kept = filter_findings([mk("A"), mk("B")], {"B", "C"})
    assert [f.entity for f in kept] == ["B"]


def test_registry_lists_the_configured_detector_names():
    assert {"b2", "b3"} <= set(DETECTORS)


def test_fit_is_deterministic():
    a, b = CheapModel.fit(_benign(), CFG, 5), CheapModel.fit(_benign(), CFG, 5)
    assert a.thresholds.equals(b.thresholds) and a.iso_cut == b.iso_cut

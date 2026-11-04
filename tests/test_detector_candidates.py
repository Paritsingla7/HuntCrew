from types import SimpleNamespace

import pandas as pd
import pytest

from huntcrew import detector as det
from huntcrew.replay import Window

W = Window(0, pd.Timestamp("2017-07-04 14:00"), pd.Timestamp("2017-07-04 14:05"))


def test_merge_notes_keeps_both_sources_of_a_candidate():
    got = det.merge_candidate_notes({"A": "screen note", "B": "only screen"}, {"A": "rule fired: x", "C": "rule fired: y"})
    assert got == {"A": "screen note; rule fired: x", "B": "only screen", "C": "rule fired: y"}


def test_merge_with_one_side_empty_is_unchanged():
    assert det.merge_candidate_notes({"A": "n"}, {}) == {"A": "n"}
    assert det.merge_candidate_notes({}, {"A": "r"}) == {"A": "r"}


def test_order_without_priority_is_plain_sorted_order_as_before():
    assert det.order_candidates({"192.168.10.9": "", "10.0.0.2": "", "172.16.0.1": ""}, set()) == \
        sorted(["192.168.10.9", "10.0.0.2", "172.16.0.1"])


def test_order_puts_priority_first_so_the_cap_drops_screening_only_sources():
    flagged = {f"10.0.0.{i}": "" for i in range(1, 12)} | {"203.0.113.9": "rule"}     # 12 candidates, cap is 8
    kept = det.order_candidates(flagged, {"203.0.113.9"})[: det.MAX_CANDIDATES]
    assert "203.0.113.9" in kept and len(kept) == det.MAX_CANDIDATES
    assert "203.0.113.9" not in det.order_candidates(flagged, set())[: det.MAX_CANDIDATES]   # plain order drops it


def _ctx():
    digest = SimpleNamespace(total_flows=10, entities=[], peers={})
    return SimpleNamespace(window=W, digest=digest, kb=SimpleNamespace(trace=[]), trace_start=0,
                           view=SimpleNamespace(current=lambda: pd.DataFrame()))


def _run(monkeypatch, mode, screened, ruled):
    seen = {}
    monkeypatch.setattr(det, "screen_sources", lambda ctx, llm, minutes: (dict(screened), False))
    monkeypatch.setattr(det, "rule_candidates", lambda ctx, rules, known: dict(ruled))
    monkeypatch.setattr(det, "entity_stats", lambda flows, ip, w: SimpleNamespace(row=lambda ip=ip: f"row {ip}"))
    monkeypatch.setattr(det, "build_tools", lambda ctx: [])

    def fake_agent(llm, tools, prompt, max_iter):
        seen["prompt"] = prompt
        return '{"verdicts": []}'

    monkeypatch.setattr(det, "_run_agent", fake_agent)
    res = det.detect_window(_ctx(), None, set(), 5, candidates_from=mode)
    return res, seen["prompt"]


def test_union_verifies_both_screened_and_rule_candidates(monkeypatch):
    res, prompt = _run(monkeypatch, "union", {"192.168.10.15": "regular beacon-like"}, {"172.16.0.1": "rule fired: ssh"})
    assert res.screened_unusual == ["172.16.0.1", "192.168.10.15"]
    assert "row 172.16.0.1" in prompt and "row 192.168.10.15" in prompt and "rule fired: ssh" in prompt


def test_rules_mode_never_calls_screening_and_screen_mode_never_calls_rules(monkeypatch):
    res, _ = _run(monkeypatch, "rules", {"X": "should be ignored"}, {"172.16.0.1": "rule fired"})
    assert res.screened_unusual == ["172.16.0.1"]
    res, _ = _run(monkeypatch, "screen", {"192.168.10.15": "s"}, {"172.16.0.1": "should be ignored"})
    assert res.screened_unusual == ["192.168.10.15"]


def test_unknown_mode_is_rejected_not_silently_treated_as_screen(monkeypatch):
    with pytest.raises(ValueError):
        _run(monkeypatch, "typo", {}, {})

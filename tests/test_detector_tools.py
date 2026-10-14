from types import SimpleNamespace

import pandas as pd

from huntcrew.detector_tools import DetectorContext, list_sources, search_attack_kb, source_profile
from huntcrew.digest import build_digest, entity_stats
from huntcrew.evidence import verify_finding
from huntcrew.profile import BaselineProfile
from huntcrew.replay import Replay


def _flows():
    rows = []
    # attacker: 12 flows to one port, one per minute-ish, in the current window 14:05-14:10
    for i in range(12):
        rows.append(("2017-07-04 14:0%d" % (5 + i % 5), "172.16.0.1", "192.168.10.50", 22, 100, 50))
    # a quiet client
    rows.append(("2017-07-04 14:06", "192.168.10.9", "8.8.8.8", 53, 10, 10))
    # history flows from the attacker, one window earlier
    for _ in range(3):
        rows.append(("2017-07-04 14:02", "172.16.0.1", "192.168.10.50", 22, 100, 50))
    df = pd.DataFrame(rows, columns=["ts", "src_ip", "dst_ip", "dst_port", "fwd_bytes", "bwd_bytes"])
    df["ts"] = pd.to_datetime(df["ts"])
    df["duration_us"], df["syn_count"], df["rst_count"] = 1000, 1, 0
    return df.sort_values("ts").reset_index(drop=True)


class FakeKB:
    def __init__(self):
        self.trace = []
        self.chunks = {"T1110": object(), "T1046": object()}

    def search(self, query, k=5, include_subtechniques=True):
        self.trace.append({"query": query, "ids": ["T1110"]})
        return [SimpleNamespace(id="T1110", name="Brute Force", tactics=["credential-access"], score=0.61,
                                snippet="Adversaries may use brute force techniques to gain access.")]


def _ctx():
    flows = _flows()
    base = pd.DataFrame({"ts": pd.to_datetime(["2017-07-03 10:00", "2017-07-03 10:01"]),
                         "src_ip": ["192.168.10.9", "192.168.10.9"], "dst_ip": ["8.8.8.8", "8.8.4.4"],
                         "dst_port": [53, 53]})
    r = Replay(flows, "2017-07-04 14:00", "2017-07-04 14:10", 5, 12)
    w = r.windows()[1]
    view = r.view(w)
    return DetectorContext(window=w, view=view, digest=build_digest(view.current(), w), kb=FakeKB(),
                           profile=BaselineProfile(base, 5))


def test_profile_lookup_known_and_unknown():
    p = _ctx().profile
    assert p.lookup("192.168.10.9")["seen_in_baseline"] is True
    assert p.lookup("172.16.0.1") == {"seen_in_baseline": False}
    assert p.destination_known("8.8.8.8") and not p.destination_known("1.2.3.4")


def test_entity_stats_matches_digest_row():
    ctx = _ctx()
    st = entity_stats(ctx.view.current(), "172.16.0.1", ctx.window)
    assert st is not None and st.flows == 12 and st.dst_ports == 1 and st.top_ports == [(22, 12)]
    assert entity_stats(ctx.view.current(), "9.9.9.9", ctx.window) is None


def test_list_sources_ranks_and_rejects_unknown_key():
    ctx = _ctx()
    out = list_sources(ctx, "flows", 2).splitlines()
    assert out[0].startswith("172.16.0.1 flows=12")
    assert "unknown ranking" in list_sources(ctx, "nonsense")


def test_source_profile_includes_history_and_baseline():
    text = source_profile(_ctx(), "172.16.0.1")
    assert "flows=12" in text and "history flows by windows-ago: 1:3" in text
    assert "seen_in_baseline=False" in text and "never seen in baseline" not in text   # dst is private
    assert "no flows as a source" in source_profile(_ctx(), "9.9.9.9")


def test_search_tool_records_trace_for_grounding():
    ctx = _ctx()
    out = search_attack_kb(ctx, "many failed logins")
    assert out.startswith("T1110 Brute Force")
    assert ctx.retrieved_ids() == {"T1110"}


def test_evidence_accepts_true_numbers_and_grounded_hints():
    ctx = _ctx()
    search_attack_kb(ctx, "q")
    v = verify_finding({"entity": "172.16.0.1", "behaviour": "x", "evidence": {"flows": 12, "dst_ports": 1},
                        "technique_hints": [{"id": "T1110"}, {"id": "T1046"}, {"id": "T9999"}],
                        "confidence": 0.9}, ctx, known_ids={"T1110", "T1046"})
    assert v.ok and v.verified == 2 and v.finding is not None
    assert [h.id for h in v.finding.technique_hints] == ["T1110"]        # T1046 not retrieved, T9999 unknown
    assert set(v.dropped_hints) == {"T1046", "T9999"}


def test_evidence_rejects_contradicted_numbers_and_missing_entities():
    ctx = _ctx()
    bad = verify_finding({"entity": "172.16.0.1", "evidence": {"flows": 500}}, ctx, set())
    assert not bad.ok and "claimed 500" in bad.reasons[0] and bad.finding is None
    ghost = verify_finding({"entity": "10.9.9.9", "evidence": {"flows": 1}}, ctx, set())
    assert not ghost.ok and "no flows" in ghost.reasons[0]
    empty = verify_finding({"entity": "172.16.0.1", "evidence": {"bananas": 3}}, ctx, set())
    assert not empty.ok and empty.unverifiable == 1


def test_evidence_tolerates_small_float_rounding():
    ctx = _ctx()
    st = entity_stats(ctx.view.current(), "172.16.0.1", ctx.window)
    assert st is not None
    v = verify_finding({"entity": "172.16.0.1", "evidence": {"per_minute_mean": round(st.per_minute_mean, 1)}},
                       ctx, set())
    assert v.ok


def test_screen_parser_keeps_only_unusual_known_entities():
    from huntcrew.detector import parse_screen_json
    text = ('```json\n{"sources": [{"entity": "A", "unusual": true, "why": "one port"}, '
            '{"entity": "B", "unusual": false, "why": "normal"}, '
            '{"entity": "Z", "unusual": true, "why": "not in chunk"}]}\n```')
    assert parse_screen_json(text, {"A", "B"}) == {"A": "one port"}
    assert parse_screen_json("no json", {"A"}) is None
    assert parse_screen_json('{"sources": "x"}', {"A"}) is None


def test_merge_into_incidents_joins_adjacent_windows_only():
    from datetime import datetime

    from huntcrew.detector import merge_into_incidents
    from huntcrew.schema import Finding

    def f(ent, minute):
        t = datetime(2017, 7, 4, 9, minute)
        return Finding(window_start=t, window_end=t.replace(minute=minute + 5), entity=ent, behaviour="x")

    inc = merge_into_incidents([f("A", 0), f("A", 5), f("A", 10), f("A", 40), f("B", 5)], 5)
    spans = sorted((i.entity, len(i.findings)) for i in inc)
    assert spans == [("A", 1), ("A", 3), ("B", 1)]


def test_verdict_parser_returns_only_confirmed_attacks():
    from huntcrew.detector import parse_findings_json
    text = '{"verdicts": [{"entity": "A", "attack": true}, {"entity": "B", "attack": false}]}'
    assert [x["entity"] for x in parse_findings_json(text) or []] == ["A"]
    assert parse_findings_json('{"findings": [{"entity": "C"}]}') == [{"entity": "C"}]


def test_truncated_answer_still_yields_complete_confirmed_verdicts():
    from huntcrew.detector import parse_findings_json
    cut = ('```json\n{"verdicts": [{"entity": "A", "attack": true, "behaviour": "x", "evidence": {"flows": 5}}, '
           '{"entity": "B", "attack": false, "behaviour": "y", "evidence": {}}, '
           '{"entity": "C", "attack": true, "behaviour": "text that gets cut off here, never closes')
    got = parse_findings_json(cut)
    assert got is not None and [x["entity"] for x in got] == ["A"]
    assert parse_findings_json("```json\n{\"verdicts\": [") is None

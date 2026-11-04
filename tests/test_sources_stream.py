import json
import random

import pandas as pd
import pytest

from huntcrew.approvers import http_approver
from huntcrew.replay import FutureAccessError, Replay
from huntcrew.schema import ProposedAction
from huntcrew.sources import REQUIRED, SOURCES, load_flows, source, validate_flows
from huntcrew.stream import LateFlowError, WindowStream

ZEEK_TSV = (
    "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n"
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\t"
    "conn_state\thistory\torig_pkts\tresp_pkts\n"
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring\tstring\tcount\tcount\n"
    "1499158801.5\tC2\t192.168.10.5\t5353\t8.8.8.8\t53\tudp\tdns\t-\t-\t-\tS0\t-\t1\t0\n"
    "1499158800.0\tC1\t172.16.0.1\t40000\t192.168.10.50\t22\ttcp\tssh\t1.5\t100\t200\tSF\tShADadFf\t6\t5\n"
    "1499158802.0\tC3\t172.16.0.1\t40001\t192.168.10.50\t22\ttcp\tssh\t0.2\t0\t0\tRSTO\tSrR\t2\t1\n"
    "#close\t2017-07-04-09-05-00\n")


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_zeek_tsv_maps_to_the_canonical_table_sorted_and_with_unset_fields_as_zero(tmp_path):
    df = load_flows("zeek_conn", _write(tmp_path, "conn.log", ZEEK_TSV))
    assert list(df.columns[: len(REQUIRED)]) == list(REQUIRED) and len(df) == 3
    assert df["ts"].is_monotonic_increasing and str(df["ts"].iloc[0]) == "2017-07-04 09:00:00"
    first, dns = df.iloc[0], df[df["dst_port"] == 53].iloc[0]
    assert (first["src_ip"], first["dst_port"], first["duration_us"], first["fwd_bytes"], first["bwd_bytes"]) == \
        ("172.16.0.1", 22, 1_500_000, 100, 200)
    assert (first["fwd_pkts"], first["bwd_pkts"], first["syn_count"], first["rst_count"]) == (6, 5, 1, 0)
    assert (dns["duration_us"], dns["fwd_bytes"], dns["syn_count"]) == (0, 0, 0)      # '-' became 0
    assert df.iloc[2]["rst_count"] == 2                                              # history 'SrR' -> r and R


def test_zeek_json_lines_and_timezone_offset(tmp_path):
    rows = [{"ts": 1499158800.0, "id.orig_h": "10.0.0.1", "id.orig_p": 1, "id.resp_h": "10.0.0.2", "id.resp_p": 80,
             "proto": "tcp", "duration": 2.0, "orig_bytes": 10, "resp_bytes": 20, "history": "ShAD", "orig_pkts": 3, "resp_pkts": 2}]
    p = _write(tmp_path, "conn.json", "\n".join(json.dumps(r) for r in rows))
    df = load_flows("zeek_conn", p, tz_offset_hours=5.5)
    assert str(df["ts"].iloc[0]) == "2017-07-04 14:30:00" and df["duration_us"].iloc[0] == 2_000_000


def test_zeek_rejects_a_file_that_is_not_a_zeek_log(tmp_path):
    with pytest.raises(ValueError):
        load_flows("zeek_conn", _write(tmp_path, "x.log", "hello\nworld\n"))


EVE = [
    {"timestamp": "2017-07-04T09:05:00.000000+0000", "event_type": "alert", "src_ip": "1.1.1.1"},      # ignored: not a flow
    {"timestamp": "2017-07-04T09:05:10.000000+0000", "event_type": "flow", "src_ip": "172.16.0.1", "src_port": 4000,
     "dest_ip": "192.168.10.50", "dest_port": 22, "proto": "TCP",
     "flow": {"pkts_toserver": 7, "pkts_toclient": 6, "bytes_toserver": 900, "bytes_toclient": 800,
              "start": "2017-07-04T09:05:00.000000+0000", "age": 3},
     "tcp": {"syn": True, "rst": False}},
]


def test_suricata_eve_keeps_only_flow_events(tmp_path):
    df = load_flows("suricata_eve", _write(tmp_path, "eve.json", "\n".join(json.dumps(e) for e in EVE)))
    assert len(df) == 1
    r = df.iloc[0]
    assert str(r["ts"]) == "2017-07-04 09:05:00" and (r["dst_port"], r["fwd_bytes"], r["bwd_pkts"]) == (22, 900, 6)
    assert (r["duration_us"], r["syn_count"], r["rst_count"]) == (3_000_000, 1, 0)


def test_registry_unknown_kind_and_contract_validation():
    assert {"cic", "zeek_conn", "suricata_eve"} <= set(SOURCES)
    with pytest.raises(KeyError):
        load_flows("netflow9", "x")
    with pytest.raises(ValueError):
        validate_flows(pd.DataFrame({"ts": []}))
    with pytest.raises(ValueError):
        validate_flows(pd.DataFrame({c: [] for c in (*REQUIRED, "attack_label")}))


def test_new_sources_register_by_name(tmp_path):
    @source("unit_test_source")
    def _src(path, **_):
        return pd.DataFrame({c: [0] for c in REQUIRED}).assign(ts=pd.Timestamp("2017-07-04"), src_ip="a", dst_ip="b")
    try:
        assert len(load_flows("unit_test_source", tmp_path)) == 1
    finally:
        SOURCES.pop("unit_test_source")


# --- streaming ----------------------------------------------------------------------------------
def _flows(n=400, seed=0, minutes=60):
    rng = random.Random(seed)
    base = pd.Timestamp("2017-07-04 14:00")
    secs = sorted(rng.uniform(0, minutes * 60) for _ in range(n))
    return pd.DataFrame({"ts": [base + pd.Timedelta(seconds=s) for s in secs],
                         "src_ip": [rng.choice(["172.16.0.1", "192.168.10.5", "192.168.10.6"]) for _ in secs],
                         "dst_ip": "192.168.10.50", "dst_port": [rng.choice([22, 80, 443]) for _ in secs]})


def _split(df, rng):
    cuts = sorted(rng.sample(range(1, len(df)), 7))
    return [df.iloc[a:b] for a, b in zip([0, *cuts], [*cuts, len(df)], strict=True)]


@pytest.mark.parametrize("seed", range(6))
def test_stream_views_equal_the_batch_replay_for_any_batching(seed):
    flows = _flows(seed=seed)
    batch = Replay(flows, "2017-07-04 14:00", "2017-07-04 15:00", 5, 3)
    stream = list(WindowStream(_split(flows, random.Random(seed)), 5, 3, start="2017-07-04 14:00"))
    assert [w.index for w, _ in stream] == [w.index for w in batch.windows()][: len(stream)]
    for (w, sv), (_, bv) in zip(stream, iter(batch), strict=False):
        assert sv.current().reset_index(drop=True).equals(bv.current().reset_index(drop=True)), w.label()
        assert sv.history().reset_index(drop=True).equals(bv.history().reset_index(drop=True)), w.label()


def test_stream_cannot_look_forward_and_buffer_stays_bounded():
    flows = _flows()
    seen_rows = []
    for w, v in WindowStream(_split(flows, random.Random(1)), 5, 2, start="2017-07-04 14:00"):
        with pytest.raises(FutureAccessError):
            v.between(w.end, w.end + pd.Timedelta(minutes=1))
        seen_rows.append(len(v._flows))
    assert max(seen_rows) < len(flows)                    # old windows were dropped from the buffer


def _at(minute, second=0):
    return pd.DataFrame({"ts": [pd.Timestamp("2017-07-04 14:00") + pd.Timedelta(minutes=minute, seconds=second)],
                         "src_ip": "a", "dst_ip": "b", "dst_port": 22})


def test_a_window_is_emitted_only_after_a_flow_at_or_past_its_end_has_been_read():
    read = []

    def batches():
        for i, b in enumerate([_at(0, 10), _at(4, 59), _at(5, 0), _at(11)]):
            read.append(i)
            yield b

    stream = iter(WindowStream(batches(), 5, 2, start="2017-07-04 14:00"))
    first = next(stream)
    assert first[0].index == 0 and read == [0, 1, 2]       # window 0 needed the 14:05:00 flow (third batch)
    assert len(first[1].current()) == 2                    # the 14:00:10 and 14:04:59 flows
    second = next(stream)
    assert second[0].index == 1 and read == [0, 1, 2, 3]   # window 1 needed the 14:11 flow


def test_the_open_window_is_flushed_when_the_stream_ends_and_an_empty_stream_yields_nothing():
    assert [w.index for w, _ in WindowStream([_at(0, 10), _at(1)], 5, 2, start="2017-07-04 14:00")] == [0]
    assert list(WindowStream([], 5, 2)) == [] and list(WindowStream([_at(0).iloc[0:0]], 5, 2)) == []


def test_late_flows_raise_by_default_or_are_dropped_and_counted():
    flows = _flows(n=60, minutes=30)
    late = flows.iloc[:3]
    batches = [flows.iloc[3:], late]
    with pytest.raises(LateFlowError):
        list(WindowStream(batches, 5, 2, start="2017-07-04 14:00"))
    s = WindowStream([flows.iloc[3:30], flows.iloc[30:], late], 5, 2, start="2017-07-04 14:00", late="drop")
    list(s)
    assert s.late_dropped > 0


def test_stream_rejects_label_columns_and_bad_late_option():
    with pytest.raises(ValueError):
        list(WindowStream([_flows(5).assign(attack_label="x")], 5, 2))
    with pytest.raises(ValueError):
        WindowStream([], late="ignore")


def test_stream_without_start_aligns_to_the_window_grid():
    out = list(WindowStream([_flows(30, minutes=20).assign(ts=lambda d: d["ts"] + pd.Timedelta(minutes=2))], 5, 2))
    assert out[0][0].start == pd.Timestamp("2017-07-04 14:00")


# --- approver -----------------------------------------------------------------------------------
ACTION = ProposedAction(type="isolate_host", target="192.168.10.50", justification="scan", mitigation_id=None)


def test_http_approver_posts_the_request_and_approves_only_on_an_explicit_true():
    sent = []
    ok = http_approver("https://approvals.example/api", post=lambda u, p, t: sent.append((u, p, t)) or {"approved": True})
    assert ok(ACTION, "high risk") is True
    url, payload, timeout = sent[0]
    assert url == "https://approvals.example/api" and payload["action"] == "isolate_host" and payload["target"] == "192.168.10.50"
    assert timeout == 30.0


@pytest.mark.parametrize("answer", [{"approved": False}, {"approved": "yes"}, {"approved": 1}, {}, [], None, "ok"])
def test_http_approver_fails_closed_on_anything_but_true(answer):
    assert http_approver("http://x.example", post=lambda u, p, t: answer)(ACTION, "r") is False


def test_http_approver_fails_closed_on_errors_and_rejects_non_http_urls():
    def boom(u, p, t):
        raise TimeoutError("slow")
    assert http_approver("http://x.example", post=boom)(ACTION, "r") is False
    for bad in ("file:///etc/passwd", "ftp://x", "javascript:alert(1)", ""):
        with pytest.raises(ValueError):
            http_approver(bad)


def test_zeek_log_streams_through_the_digest_and_the_rules_end_to_end(tmp_path):
    """A Zeek conn.log with an SSH brute-force burst is detected by the unchanged B0 rule, window by window."""
    from huntcrew.baselines import b0_findings
    from huntcrew.config import load_config
    from huntcrew.digest import build_digest

    head = ("#separator \\x09\n#unset_field\t-\n#path\tconn\n#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\t"
            "duration\torig_bytes\tresp_bytes\thistory\torig_pkts\tresp_pkts\n")
    t0 = 1499158800            # 2017-07-04 09:00:00 UTC
    lines = [f"{t0 + 310 + i * 3}\t172.16.0.1\t{40000 + i}\t192.168.10.50\t22\ttcp\t0.1\t100\t200\tShADadFf\t6\t5" for i in range(80)]
    lines += [f"{t0 + 20 * i}\t192.168.10.5\t{50000 + i}\t192.168.10.3\t53\tudp\t-\t-\t-\t-\t1\t1" for i in range(40)]
    df = load_flows("zeek_conn", _write(tmp_path, "conn.log", head + "\n".join(lines) + "\n"))
    rules = load_config()["baseline_rules"]
    hits = {}
    for w, view in WindowStream([df.iloc[i:i + 17] for i in range(0, len(df), 17)], 5, 12, start="2017-07-04 09:00"):
        cur = view.current()
        for f in b0_findings(cur, w, rules):
            hits.setdefault(f.entity, []).append(w.index)
        if len(cur):
            assert build_digest(cur, w).total_flows == len(cur)
    assert hits == {"172.16.0.1": [1]}                      # 80 SSH flows within window 1 (09:05-09:10); nothing else fires

import pandas as pd

from huntcrew.digest import build_digest, is_private
from huntcrew.replay import Window

W = Window(0, pd.Timestamp("2017-07-04 14:00"), pd.Timestamp("2017-07-04 14:05"))


def _row(ts, src, dst, port, dur=1000, fwd=100, bwd=50, syn=1, rst=0):
    return dict(ts=pd.Timestamp(ts), src_ip=src, dst_ip=dst, dst_port=port, duration_us=dur,
                fwd_bytes=fwd, bwd_bytes=bwd, syn_count=syn, rst_count=rst)


def test_empty_window():
    d = build_digest(pd.DataFrame(columns=["ts"]), W)
    assert d.total_flows == 0 and d.entities == []


def test_basic_statistics_and_regularity():
    rows = [_row(f"2017-07-04 14:0{m}", "172.16.0.1", "192.168.10.50", 22) for m in range(5)]
    rows += [_row("2017-07-04 14:00", "192.168.10.9", "8.8.8.8", 53, fwd=10),
             _row("2017-07-04 14:00", "192.168.10.9", "8.8.4.4", 53, fwd=30),
             _row("2017-07-04 14:03", "192.168.10.9", "192.168.10.3", 445)]
    d = build_digest(pd.DataFrame(rows), W)
    assert d.total_flows == 8 and d.sources == 2
    a = d.entities[0]                      # neutral address order: 172.16.0.1 before 192.168.10.9
    assert a.entity == "172.16.0.1" and a.flows == 5 and a.dst_ports == 1
    assert a.top_ports == [(22, 5)] and a.ext_dst_ips == 0
    assert a.active_minutes == 5 and a.per_minute_cv == 0.0     # one flow every minute: perfectly regular
    b = d.entities[1]
    assert b.entity == "192.168.10.9" and b.ext_dst_ips == 2 and b.dst_ports == 2
    assert b.fwd_bytes == 140
    assert [p for p, _ in b.top_ports][0] == 53


def test_private_listed_public_multi_view_and_remainder_summarised():
    rows = [_row("2017-07-04 14:00", "192.168.10.5", "10.9.9.9", 80)]
    # 12 public sources; one stands out only by many distinct ports, one only by bytes
    rows += [_row("2017-07-04 14:00", f"203.0.113.{i}", "192.168.10.5", 80) for i in range(1, 11)]
    rows += [_row("2017-07-04 14:00", "198.51.100.7", "192.168.10.5", p) for p in range(1000, 1010)]
    rows += [_row("2017-07-04 14:01", "198.51.100.8", "192.168.10.5", 443, fwd=10**9)]
    d = build_digest(pd.DataFrame(rows), W, public_top_k=1)
    listed = {e.entity for e in d.entities}
    assert "192.168.10.5" in listed                       # private always listed
    assert "198.51.100.7" in listed                       # leads on distinct ports, though not on bytes
    assert "198.51.100.8" in listed                       # leads on bytes
    assert d.omitted == d.sources - len(d.entities) and d.omitted > 0
    assert d.omitted_flows == sum(1 for r in rows if r["src_ip"].startswith("203.0.113.")) - \
        sum(1 for e in d.entities if e.entity.startswith("203.0.113."))
    assert "UNLISTED sources=" in d.to_text()


def test_private_cap_is_reported_not_silent():
    rows = [_row("2017-07-04 14:00", f"10.0.0.{i}", "10.0.1.1", 80) for i in range(1, 11)]
    d = build_digest(pd.DataFrame(rows), W, max_private=4)
    assert len(d.entities) == 4 and d.omitted == 6 and d.sources == 10


def test_private_detection():
    assert is_private("192.168.10.3") and is_private("172.16.0.1") and not is_private("205.174.165.73")
    assert not is_private("not-an-ip")
    assert not is_private("198.51.100.7") and not is_private("127.0.0.1") and not is_private("100.64.1.1")


def test_digest_text_has_no_verdict_words():
    d = build_digest(pd.DataFrame([_row("2017-07-04 14:00", "10.0.0.1", "10.0.0.2", 22)]), W)
    text = d.to_text().lower()
    for word in ("suspicious", "attack", "malicious", "scan", "brute"):
        assert word not in text


def test_listing_order_is_by_address_not_by_volume_and_peers_line_present():
    rows = [_row("2017-07-04 14:00", "192.168.10.200", "10.1.1.1", 80)] * 5 + \
           [_row("2017-07-04 14:00", "192.168.10.9", "10.1.1.1", 80)] * 1
    d = build_digest(pd.DataFrame(rows), W)
    assert [e.entity for e in d.entities] == ["192.168.10.9", "192.168.10.200"]
    assert d.peers["flows"] == 3.0
    assert "PEERS(in-network median)" in d.to_text()

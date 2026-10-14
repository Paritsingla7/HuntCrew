from pathlib import Path

import pandas as pd
import pytest

from huntcrew.data_cic import COLUMN_MAP, LABEL_COLUMN, load_cic, parse_timestamps

REAL = Path(__file__).resolve().parents[1] / "data" / "external" / "cic-ids2017" / "CICIDS_Flow.parquet"


def test_parse_mixed_formats_day_first_and_pm_fix():
    raw = pd.Series(["03/07/2017 08:55:58", "5/7/2017 10:58", "5/7/2017 2:09", "7/7/2017 5:02", "4/7/2017 12:10"])
    got = parse_timestamps(raw).tolist()
    assert got == [
        pd.Timestamp("2017-07-03 08:55:58"),
        pd.Timestamp("2017-07-05 10:58"),
        pd.Timestamp("2017-07-05 14:09"),   # 2:09 on a 12h clock, capture is 09:00-17:00 -> PM
        pd.Timestamp("2017-07-07 17:02"),
        pd.Timestamp("2017-07-04 12:10"),   # noon stays noon
    ]


def _tiny_parquet(tmp_path) -> Path:
    n = 4
    data = {src: [0] * n for src in COLUMN_MAP}
    data.update({
        "flow_id": [1, 2, 3, 4],
        "source_ip": ["10.0.0.1", "172.16.0.1", "10.0.0.2", "172.16.0.1"],
        "destination_ip": ["10.0.0.9"] * n,
        "protocol": ["TCP"] * n,
        "Timestamp": ["4/7/2017 3:00", "4/7/2017 9:10", "4/7/2017 9:20", "4/7/2017 2:30"],
        LABEL_COLUMN: ["BENIGN", "FTP-Patator", "BENIGN", "SSH-Patator"],
    })
    p = tmp_path / "tiny.parquet"
    pd.DataFrame(data).to_parquet(p)
    return p


def test_labels_are_split_from_flows_and_aligned(tmp_path):
    d = load_cic(_tiny_parquet(tmp_path))
    assert LABEL_COLUMN not in d.flows.columns and "label" not in d.flows.columns
    assert len(d.labels) == len(d.flows)
    assert d.flows.ts.is_monotonic_increasing
    # row at 09:10 sorts first; its label must travel with it
    assert d.labels.iloc[0] == "FTP-Patator"
    assert list(d.flows.src_ip.iloc[:2]) == ["172.16.0.1", "10.0.0.2"]


def test_select_keeps_alignment_and_resets_index(tmp_path):
    d = load_cic(_tiny_parquet(tmp_path))
    s = d.select(pd.Timestamp("2017-07-04 14:00"), pd.Timestamp("2017-07-04 16:00"))
    assert len(s) == 2 and list(s.flows.index) == [0, 1]
    assert set(s.labels) == {"BENIGN", "SSH-Patator"}


@pytest.mark.skipif(not REAL.exists(), reason="run scripts/fetch_data.py first")
def test_real_dataset_matches_published_counts_and_schedule():
    d = load_cic(REAL)
    assert len(d) == 2_827_677
    assert d.flows.flow_id.is_unique
    counts = d.labels.value_counts()
    assert counts["SSH-Patator"] == 5897 and counts["FTP-Patator"] == 7935
    assert counts["Bot"] == 1956 and counts["PortScan"] == 158_804
    ssh = d.flows.loc[d.labels == "SSH-Patator", "ts"]
    assert ssh.min() >= pd.Timestamp("2017-07-04 13:45") and ssh.max() <= pd.Timestamp("2017-07-04 15:30")
    mon = d.labels[d.flows.ts.dt.day == 3]
    assert set(mon.astype(str)) == {"BENIGN"}        # Monday is benign-only: usable as normal baseline

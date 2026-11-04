"""The fresh split must not change any earlier split's ground truth, and must contain what it was declared to contain."""
from pathlib import Path

import pandas as pd
import pytest

from huntcrew.config import load_config
from huntcrew.data_cic import load_cic
from huntcrew.evaluate import attack_truth
from huntcrew.replay import Replay

ROOT = Path(__file__).resolve().parents[1]
PARQUET = ROOT / "data" / "external" / "cic-ids2017" / "CICIDS_Flow.parquet"
pytestmark = pytest.mark.skipif(not PARQUET.is_file(), reason="CIC-IDS2017 parquet not downloaded")


@pytest.fixture(scope="module")
def world():
    cfg = load_config(ROOT / "config.yaml")
    return cfg, load_cic(PARQUET)


def _truth(cfg, data, s):
    sl = data.select(pd.Timestamp(s["start"]), pd.Timestamp(s["end"]))
    w = Replay(sl.flows, s["start"], s["end"], 5, 12).windows()
    return attack_truth(sl.flows, sl.labels, w, cfg["labels"]["to_technique"], cfg["grading"]["min_attack_flows"])


def test_earlier_splits_keep_exactly_their_frozen_truth(world):
    cfg, data = world
    frozen = {"ftp_patator": 14, "ssh_patator": 14, "bot": 73, "portscan": 8}          # attack-positive pairs in the frozen results
    for group in ("dev", "test"):
        for s in cfg["splits"][group]:
            assert len(_truth(cfg, data, s)) == frozen[s["name"]], s["name"]


def test_fresh_slices_hold_their_declared_attack_family(world):
    cfg, data = world
    expect = {"bot_fresh_pm": "T1071", "portscan_fresh": "T1046", "ddos_fri": "T1499",
              "dos_wed": "T1499", "web_thu": {"T1110", "T1190"}}
    for s in cfg["splits"]["fresh"]:
        t = _truth(cfg, data, s)
        assert len(t) > 0, f"{s['name']} has no attack-positive pairs"
        want = expect[s["name"]]
        assert set(t["technique"]) <= (want if isinstance(want, set) else {want}), s["name"]

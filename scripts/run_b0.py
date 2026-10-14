"""Run the B0 rules baseline on a pre-registered split and print graded results.

    python scripts/run_b0.py dev            # allowed any time
    python scripts/run_b0.py test           # only at evaluation time (ADR-019)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from huntcrew.baselines import b0_findings, known_destinations  # noqa: E402
from huntcrew.config import load_config  # noqa: E402
from huntcrew.data_cic import load_cic  # noqa: E402
from huntcrew.evaluate import attack_truth, score_findings  # noqa: E402
from huntcrew.replay import Replay  # noqa: E402


def run(split: str) -> dict:
    cfg = load_config()
    data = load_cic(cfg["data"]["cic_parquet"])
    base = cfg["splits"]["baseline_benign"]
    known = known_destinations(data.select(pd.Timestamp(base["start"]), pd.Timestamp(base["end"])).flows)
    out = {}
    for s in cfg["splits"][split]:
        sl = data.select(pd.Timestamp(s["start"]), pd.Timestamp(s["end"]))
        rp = Replay(sl.flows, s["start"], s["end"], cfg["replay"]["window_minutes"], cfg["replay"]["history_windows"])
        windows = rp.windows()
        findings = [f for w, v in rp for f in b0_findings(v.current(), w, cfg["baseline_rules"], known)]
        truth = attack_truth(sl.flows, sl.labels, windows, cfg["labels"]["to_technique"],
                             cfg["grading"]["min_attack_flows"])
        out[s["name"]] = {"windows": len(windows), **score_findings(findings, truth, windows)}
    return out


if __name__ == "__main__":
    print(json.dumps(run(sys.argv[1] if len(sys.argv) > 1 else "dev"), indent=2))

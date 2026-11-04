"""Post-hoc no-LLM baselines (ADR-031) on a pre-registered split. No API key or model needed.

    python scripts/run_cheap.py dev
    python scripts/run_cheap.py test --out results/test_cheap.json
    python scripts/run_cheap.py dev --q-sweep 0.99 0.995 0.999      # sensitivity, dev only

Output has the same shape as scripts/run_eval.py so scripts/make_final_results.py can merge it.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from huntcrew.baselines import b0_findings, known_destinations  # noqa: E402
from huntcrew.cheap_baselines import CheapModel, cheap_findings, filter_findings, flagged_sources  # noqa: E402
from huntcrew.config import load_config  # noqa: E402
from huntcrew.data_cic import load_cic  # noqa: E402
from huntcrew.evaluate import attack_truth, score_findings  # noqa: E402
from huntcrew.replay import Replay  # noqa: E402

SYSTEMS = ("b2", "b3", "b4")


def evaluate_split(cfg: dict, data, split: str, model: CheapModel, known: set[str],
                   systems: tuple[str, ...] = SYSTEMS) -> dict:
    minutes = cfg["replay"]["window_minutes"]
    slices: dict = {}
    for s in cfg["splits"][split]:
        sl = data.select(pd.Timestamp(s["start"]), pd.Timestamp(s["end"]))
        rp = Replay(sl.flows, s["start"], s["end"], minutes, cfg["replay"]["history_windows"])
        windows = rp.windows()
        truth = attack_truth(sl.flows, sl.labels, windows, cfg["labels"]["to_technique"],
                             cfg["grading"]["min_attack_flows"])
        found: dict[str, list] = {k: [] for k in systems}
        for w, v in rp:
            cur = v.current()
            if "b2" in systems or "b4" in systems:
                flagged = flagged_sources(model, "b2", cur)
            if "b2" in systems:
                found["b2"] += cheap_findings(model, "b2", cur, w)
            if "b3" in systems:
                found["b3"] += cheap_findings(model, "b3", cur, w)
            if "b4" in systems:
                found["b4"] += filter_findings(b0_findings(cur, w, cfg["baseline_rules"], known), set(flagged))
        entry: dict = {"windows": len(windows)}
        for k in systems:
            det = score_findings(found[k], truth, windows)
            entry[k] = {"detection": {a: b for a, b in det.items() if a != "per_technique"}}
        slices[s["name"]] = entry
    return slices


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["dev", "test", "fresh"])
    ap.add_argument("--out", default=None)
    ap.add_argument("--q-sweep", nargs="+", type=float,
                    help="dev only: also report the quantile baseline (b2) at these q values")
    a = ap.parse_args()
    if a.q_sweep and a.split != "dev":
        ap.error("--q-sweep is allowed on the dev split only (ADR-031: no tuning on test)")

    cfg = load_config()
    cb, minutes = cfg["cheap_baselines"], cfg["replay"]["window_minutes"]
    data = load_cic(cfg["data"]["cic_parquet"])
    b = cfg["splits"]["baseline_benign"]
    benign = data.select(pd.Timestamp(b["start"]), pd.Timestamp(b["end"])).flows
    known = known_destinations(benign)

    t0 = time.time()
    model = CheapModel.fit(benign, cb, minutes)
    report: dict = {"split": a.split, "post_hoc": True, "adr": "ADR-031", "config": cb,
                    "fit_rows": model.n_train_rows, "slices": evaluate_split(cfg, data, a.split, model, known)}
    for sl, systems in report["slices"].items():
        for k in SYSTEMS:
            print(f"[{sl}] {k}: {json.dumps(systems[k]['detection'])}", flush=True)
    if a.q_sweep:
        report["q_sweep"] = {}
        for q in a.q_sweep:
            m = CheapModel.fit(benign, {**cb, "quantile": {"q": q}}, minutes)
            res = evaluate_split(cfg, data, a.split, m, known, systems=("b2",))
            report["q_sweep"][str(q)] = {sl: r["b2"]["detection"] for sl, r in res.items()}
            print(f"q={q}: " + json.dumps({sl: (d["tp"], d["fp"], d["fn"]) for sl, d in report["q_sweep"][str(q)].items()}))
    report["seconds"] = round(time.time() - t0, 1)
    dest = Path(a.out or f"results/{a.split}_cheap.json")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {dest}")


if __name__ == "__main__":
    main()

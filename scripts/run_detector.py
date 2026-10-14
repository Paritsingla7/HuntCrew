"""Run the agent detector on a pre-registered split slice and print graded results.

    python scripts/run_detector.py dev ftp_patator --windows 0 4 8
    python scripts/run_detector.py dev ftp_patator            # whole slice (resumes from .cache/runs)
    python scripts/run_detector.py test ssh_patator           # only at evaluation time (ADR-019)
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from huntcrew import llm as llmmod  # noqa: E402
from huntcrew.attack_kb import AttackKB, load_chunks  # noqa: E402
from huntcrew.config import load_config  # noqa: E402
from huntcrew.data_cic import load_cic  # noqa: E402
from huntcrew.detector import merge_into_incidents, run_detector  # noqa: E402
from huntcrew.evaluate import attack_truth, score_findings  # noqa: E402
from huntcrew.profile import BaselineProfile  # noqa: E402
from huntcrew.replay import Replay  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["dev", "test"])
    ap.add_argument("name")
    ap.add_argument("--windows", type=int, nargs="*")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--model")
    ap.add_argument("--tag", default="agent")
    a = ap.parse_args()

    cfg = load_config()
    llmmod.load_dotenv()
    mw = llmmod.install(cfg["llm"]["min_interval_s"], cfg["llm"]["tokens_per_minute"],
                        cfg["llm"]["max_retries"], cfg["llm"]["cache_dir"])
    llm = llmmod.make_llm(cfg, a.model)

    sl_cfg = next(s for s in cfg["splits"][a.split] if s["name"] == a.name)
    data = load_cic(cfg["data"]["cic_parquet"])
    base = cfg["splits"]["baseline_benign"]
    profile = BaselineProfile(data.select(pd.Timestamp(base["start"]), pd.Timestamp(base["end"])).flows,
                              cfg["replay"]["window_minutes"])
    kb = AttackKB(load_chunks(cfg["data"]["attack_stix"]), cfg["rag"]["embedding_model"], cfg["rag"]["persist_dir"])
    sl = data.select(pd.Timestamp(sl_cfg["start"]), pd.Timestamp(sl_cfg["end"]))

    out = Path(".cache/runs") / f"{a.tag}_{a.split}_{a.name}.jsonl"
    results = run_detector(sl.flows, sl_cfg["start"], sl_cfg["end"], cfg, kb, profile, llm, out, mw,
                           only_windows=a.windows, limit=a.limit)

    rp = Replay(sl.flows, sl_cfg["start"], sl_cfg["end"], cfg["replay"]["window_minutes"], cfg["replay"]["history_windows"])
    windows = rp.windows()
    truth = attack_truth(sl.flows, sl.labels, windows, cfg["labels"]["to_technique"], cfg["grading"]["min_attack_flows"])
    covered = {r.window.index for r in results}
    truth = truth[truth["window_index"].isin(covered)]
    findings = [f for r in results for f in r.findings]
    summary = {
        "windows_run": len(results),
        "parse_errors": sum(r.parse_error for r in results),
        "rejected_findings": sum(len(r.rejected) for r in results),
        "dropped_hints": sum(r.dropped_hints for r in results),
        "incidents": len(merge_into_incidents(findings, cfg["replay"]["window_minutes"])),
        "score": {k: v for k, v in score_findings(findings, truth, windows).items() if k != "per_technique"},
        "llm": mw.stats.snapshot(),
    }
    print(json.dumps(summary, indent=2))
    for r in results:
        for f in r.findings:
            print(f"  w{r.window.index} {f.entity} conf={f.confidence} hints={[h.id for h in f.technique_hints]} | {f.behaviour[:90]}")
        for x in r.rejected:
            print(f"  w{r.window.index} REJECTED {x['entity']}: {x['reasons']}")


if __name__ == "__main__":
    main()

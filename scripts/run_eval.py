"""One-command evaluation of B0 / B1 / agent-led / hybrid on a pre-registered split.

    python scripts/run_eval.py dev --systems b0 b1 agent hybrid
    python scripts/run_eval.py test --systems b0 b1 hybrid          # only at evaluation time (ADR-019)

Everything is graded by code against dataset labels. LLM responses are cached, so re-runs are cheap.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from huntcrew import llm as llmmod  # noqa: E402
from huntcrew.attack_kb import AttackKB, load_chunks  # noqa: E402
from huntcrew.baselines import b0_findings, b1_window, known_destinations  # noqa: E402
from huntcrew.config import load_config  # noqa: E402
from huntcrew.crew import DownstreamCrew  # noqa: E402
from huntcrew.data_cic import load_cic  # noqa: E402
from huntcrew.detector import merge_into_incidents, run_detector  # noqa: E402
from huntcrew.digest import build_digest  # noqa: E402
from huntcrew.evaluate import attack_truth, grade_outcomes, score_findings  # noqa: E402
from huntcrew.pipeline import process_incident  # noqa: E402
from huntcrew.profile import BaselineProfile  # noqa: E402
from huntcrew.replay import Replay  # noqa: E402
from huntcrew.response import Policy, SimulatedEnvironment, auto_deny  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["dev", "test"])
    ap.add_argument("--systems", nargs="+", default=["b0", "b1", "hybrid"],
                    choices=["b0", "b1", "agent", "hybrid"])
    ap.add_argument("--names", nargs="*", help="slice names (default: all in the split)")
    ap.add_argument("--max-windows", type=int, help="debug: only the first N windows of each slice")
    ap.add_argument("--no-downstream", action="store_true", help="skip assess/plan/execute/report")
    ap.add_argument("--model")
    ap.add_argument("--out", default=None)
    a = ap.parse_args()

    cfg = load_config()
    llmmod.load_dotenv()
    mw = llmmod.install(cfg["llm"]["min_interval_s"], cfg["llm"]["tokens_per_minute"],
                        cfg["llm"]["max_retries"], cfg["llm"]["cache_dir"])
    llm = llmmod.make_llm(cfg, a.model)
    minutes = cfg["replay"]["window_minutes"]

    data = load_cic(cfg["data"]["cic_parquet"])
    base = cfg["splits"]["baseline_benign"]
    base_flows = data.select(pd.Timestamp(base["start"]), pd.Timestamp(base["end"])).flows
    profile, known = BaselineProfile(base_flows, minutes), known_destinations(base_flows)
    kb = AttackKB(load_chunks(cfg["data"]["attack_stix"]), cfg["rag"]["embedding_model"], cfg["rag"]["persist_dir"])
    policy = Policy.from_file(cfg["data"]["policy"])
    crew = DownstreamCrew(kb, policy, llm)
    kb_ids = set(kb.chunks)

    report: dict = {"split": a.split, "model": a.model or cfg["llm"]["model"], "slices": {}}
    for s in cfg["splits"][a.split]:
        if a.names and s["name"] not in a.names:
            continue
        sl = data.select(pd.Timestamp(s["start"]), pd.Timestamp(s["end"]))
        rp = Replay(sl.flows, s["start"], s["end"], minutes, cfg["replay"]["history_windows"])
        windows = rp.windows()[: a.max_windows] if a.max_windows else rp.windows()
        truth = attack_truth(sl.flows, sl.labels, windows, cfg["labels"]["to_technique"],
                             cfg["grading"]["min_attack_flows"])
        only = [w.index for w in windows]
        out: dict = {"windows": len(windows)}

        for system in a.systems:
            t0, before = time.time(), mw.stats.snapshot()
            if system == "b0":
                findings = [f for w, v in rp if w.index in only
                            for f in b0_findings(v.current(), w, cfg["baseline_rules"], known)]
            elif system == "b1":
                findings = []
                for w, v in rp:
                    if w.index not in only:
                        continue
                    dg = build_digest(v.current(), w, cfg["digest"]["max_private"], cfg["digest"]["public_top_k"])
                    if dg.total_flows:
                        findings += b1_window(llm, dg.to_text(), w, minutes)
            else:
                path = Path(".cache/runs") / f"{'agent' if system == 'agent' else 'hybrid'}_{a.split}_{s['name']}.jsonl"
                res = run_detector(sl.flows, s["start"], s["end"], cfg, kb, profile, llm, path, mw,
                                   only_windows=only, candidates_from="screen" if system == "agent" else "rules",
                                   known_dsts=known)
                findings = [f for r in res for f in r.findings]
            entry = {"detection": {k: v for k, v in score_findings(findings, truth, windows).items()
                                   if k != "per_technique"}}
            incidents = merge_into_incidents(findings, minutes)
            entry["incidents"] = len(incidents)
            if system in {"agent", "hybrid"} and not a.no_downstream:
                env = SimulatedEnvironment()
                outcomes = [process_incident(i, crew, policy, env, auto_deny, write_report=True) for i in incidents]
                entry["response"] = grade_outcomes(outcomes, truth, windows, kb_ids)
                entry["environment"] = {k: len(v) for k, v in env.snapshot().items()}
            entry["llm"] = mw.stats.delta(before)
            entry["seconds"] = round(time.time() - t0, 1)
            out[system] = entry
            print(f"[{s['name']}] {system}: {json.dumps(entry['detection'])}", flush=True)
        report["slices"][s["name"]] = out

    dest = Path(a.out or f"results/{a.split}_{int(time.time())}.json")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"wrote {dest}")


if __name__ == "__main__":
    main()

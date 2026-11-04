"""Technique naming on the attack-linked incidents of one system: strict technique match and tactic match.

    python scripts/grade_naming.py test --system hybrid                 # cached LLM answers cost nothing
    python scripts/grade_naming.py test --system hybrid --model mistral/mistral-small-latest --tag small

Only the Threat-Intel step runs (no strategist, no report). Findings come from .cache/runs/<system>_<split>_<slice>.jsonl.
Strict = a parent-level match with the dataset label's technique (unchanged metric). Tactic = any assessed technique
shares an ATT&CK tactic with it, computed from the official data (post-hoc, secondary; ADR-034).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from huntcrew import llm as llmmod  # noqa: E402
from huntcrew.attack_kb import AttackKB, load_chunks  # noqa: E402
from huntcrew.config import load_config  # noqa: E402
from huntcrew.crew import DownstreamCrew, incident_profile  # noqa: E402
from huntcrew.data_cic import load_cic  # noqa: E402
from huntcrew.detector import merge_into_incidents  # noqa: E402
from huntcrew.evaluate import attack_truth, grade_outcomes  # noqa: E402
from huntcrew.replay import Replay  # noqa: E402
from huntcrew.response import Policy  # noqa: E402
from huntcrew.schema import ActionLog, Finding, ResponsePlan  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("split", choices=["dev", "test", "fresh"])
    ap.add_argument("--system", default="hybrid", choices=["agent", "hybrid", "union"])
    ap.add_argument("--model")
    ap.add_argument("--run-tag", default="", help="read the run files of a tagged run (see run_eval --run-tag)")
    ap.add_argument("--tag", default=None, help="suffix for the output file (default: the model-agnostic name)")
    a = ap.parse_args()

    cfg = load_config()
    llmmod.load_dotenv()
    interval, tpm = llmmod.throttle_for(cfg, a.model)
    mw = llmmod.install(interval, tpm, cfg["llm"]["max_retries"], cfg["llm"]["cache_dir"])
    llm = llmmod.make_llm(cfg, a.model)
    data = load_cic(cfg["data"]["cic_parquet"])
    kb = AttackKB(load_chunks(cfg["data"]["attack_stix"]), cfg["rag"]["embedding_model"], cfg["rag"]["persist_dir"])
    crew = DownstreamCrew(kb, Policy.from_file(cfg["data"]["policy"]), llm)
    tactics = {c.id: c.tactics for c in kb.chunks.values()}
    minutes = cfg["replay"]["window_minutes"]

    outcomes, rows = [], []
    for s in cfg["splits"][a.split]:
        run = Path(".cache/runs") / f"{a.system}{'-' + a.run_tag if a.run_tag else ''}_{a.split}_{s['name']}.jsonl"
        if not run.is_file():
            print(f"skip {s['name']}: no run file {run}")
            continue
        sl = data.select(pd.Timestamp(s["start"]), pd.Timestamp(s["end"]))
        windows = Replay(sl.flows, s["start"], s["end"], minutes, cfg["replay"]["history_windows"]).windows()
        truth = attack_truth(sl.flows, sl.labels, windows, cfg["labels"]["to_technique"], cfg["grading"]["min_attack_flows"])
        findings = [Finding(**f) for line in run.read_text().splitlines() if line.strip() for f in json.loads(line)["findings"]]
        starts = {pd.Timestamp(w.start): w.index for w in windows}
        truth_by_key = {(int(r.window_index), str(r.entity)): str(r.technique) for r in truth.itertuples()}
        for inc in merge_into_incidents(findings, minutes):
            want = {truth_by_key[k] for f in inc.findings if (k := (starts[pd.Timestamp(f.window_start)], f.entity)) in truth_by_key}
            if not want:
                continue                                   # only attack-linked incidents are graded for naming
            assessment, _ = crew.assess(inc, incident_profile(sl.flows, inc))
            outcomes.append((truth, windows, SimpleNamespace(
                incident=inc, assessment=assessment, plan=ResponsePlan(incident_id=inc.id),
                guard=SimpleNamespace(dropped_actions=[]), log=ActionLog(incident_id=inc.id))))
            rows.append({"slice": s["name"], "entity": inc.entity, "truth": sorted(want),
                         "assessed": [(t.id, t.confidence) for t in assessment.techniques]})

    # grade_outcomes takes one truth table; grade per slice and sum, so every incident is judged against its own slice
    per_slice: dict = {}
    for (truth, windows, o), row in zip(outcomes, rows, strict=True):
        g = grade_outcomes([o], truth, windows, set(kb.chunks), tactics)
        row["strict_ok"], row["tactic_ok"] = g["technique_accuracy_incident"] == 1.0, g["tactic_correct"] == 1
        per_slice.setdefault(row["slice"], []).append(row)
    n = len(rows)
    summary = {"system": a.system, "model": a.model or cfg["llm"]["model"], "attack_linked_incidents": n,
               "strict_correct": sum(r["strict_ok"] for r in rows), "tactic_correct": sum(r["tactic_ok"] for r in rows),
               "strict_accuracy": round(sum(r["strict_ok"] for r in rows) / n, 3) if n else 0.0,
               "tactic_accuracy": round(sum(r["tactic_ok"] for r in rows) / n, 3) if n else 0.0,
               "by_slice": {k: {"n": len(v), "strict": sum(r["strict_ok"] for r in v), "tactic": sum(r["tactic_ok"] for r in v)}
                            for k, v in per_slice.items()},
               "incidents": rows, "llm": mw.stats.snapshot()}
    tag = f"_{a.tag}" if a.tag else ""
    dest = Path(f"results/naming_{a.system}_{a.split}{tag}.json")
    dest.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    for r in rows:
        print(f"{r['slice']:12s} {r['entity']:15s} truth={r['truth']} assessed={[t for t, _ in r['assessed']]} "
              f"strict={'Y' if r['strict_ok'] else '-'} tactic={'Y' if r['tactic_ok'] else '-'}")
    print(f"strict {summary['strict_correct']}/{n}  tactic {summary['tactic_correct']}/{n}  -> {dest}")


if __name__ == "__main__":
    main()

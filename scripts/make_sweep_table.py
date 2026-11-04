"""Assemble the model-size sweep (ADR-038) into one table, with the frozen 14b run for comparison.

    python scripts/make_sweep_table.py   # reads results/test_sweep_<tag>.json (+ optional naming_*.json); writes results/sweep.md
"""
from __future__ import annotations

import json
from pathlib import Path

R = Path("results")
MODELS = [("ministral-3b", "3b"), ("ministral-8b", "8b"), ("open-mistral-nemo", "nemo")]


def pooled(slices: dict, system: str = "hybrid") -> dict:
    tp = sum(s[system]["detection"]["tp"] for s in slices.values())
    fp = sum(s[system]["detection"]["fp"] for s in slices.values())
    fn = sum(s[system]["detection"]["fn"] for s in slices.values())
    p, r = (tp / (tp + fp) if tp + fp else 0.0), (tp / (tp + fn) if tp + fn else 0.0)
    resp = [s[system]["response"] for s in slices.values() if "response" in s[system]]
    linked = sum(x["attack_linked_incidents"] for x in resp)
    correct = sum(round(x["technique_accuracy_incident"] * x["attack_linked_incidents"]) for x in resp)
    llm = [s[system]["llm"] for s in slices.values()]
    return {"tp": tp, "fp": fp, "fn": fn, "precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0,
            "incidents": sum(x["incidents"] for x in resp), "linked": linked, "strict": correct,
            "grounding": min((x["grounding_rate"] for x in resp), default=None),
            "policy": min((x["policy_pass_rate"] for x in resp), default=None),
            "calls": sum(x["calls"] for x in llm), "tokens": sum(x["prompt_tokens"] + x["completion_tokens"] for x in llm),
            "minutes": sum(s[system]["seconds"] for s in slices.values()) / 60}


def tactic(tag: str | None) -> str:
    f = R / (f"naming_hybrid_test_{tag}.json" if tag else "naming_hybrid_test.json")
    if not f.is_file():
        return "n/a"
    d = json.loads(f.read_text())
    return f"{d['tactic_correct']}/{d['attack_linked_incidents']}"


def _fmt(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.2f}"


def row(name: str, m: dict, tac: str) -> str:
    return (f"| {name} | {m['recall']:.2f} | {m['precision']:.2f} | {m['f1']:.2f} | {m['fp']} | {m['strict']}/{m['linked']} | {tac} | "
            f"{_fmt(m['grounding'])} | {_fmt(m['policy'])} | {m['calls']:.0f} | {m['tokens'] / 1000:.0f}k | {m['minutes']:.0f} |")


def main() -> None:
    final = json.loads((R / "final.json").read_text())
    rows = ["| Model (hybrid, test slices) | Recall | Precision | F1 | FP | Technique (strict) | Technique (tactic) | Grounding | Policy | LLM calls | Tokens | Minutes |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, tag in MODELS:
        f = R / f"test_sweep_{tag}.json"
        if f.is_file():
            rows.append(row(name, pooled(json.loads(f.read_text())["slices"]), tactic(tag)))
    rows.append(row("ministral-14b (frozen run)", pooled(final["slices"]), tactic(None)))
    out = "\n".join(rows) + "\n"
    (R / "sweep.md").write_text(out, encoding="utf-8")
    print(out)


if __name__ == "__main__":
    main()

"""Assemble results/final.json and results/summary.md from the raw evaluation outputs (reproducible)."""
from __future__ import annotations

import json
from pathlib import Path

R = Path("results")
FROZEN = "19b8682"
SYSTEMS = ["b0", "b1", "agent", "hybrid"]
LABEL = {"b0": "B0 rules", "b1": "B1 single prompt", "agent": "Agent-led", "hybrid": "Hybrid (rules + agent)"}


def merge(*files: str) -> dict:
    out: dict = {}
    for f in files:
        d = json.loads((R / f).read_text())
        out.setdefault("model", d["model"])
        for sl, systems in d["slices"].items():
            out.setdefault(sl, {"windows": systems["windows"]}).update({k: v for k, v in systems.items() if k != "windows"})
    return out


def micro(slices: dict, system: str) -> dict:
    tp = sum(s[system]["detection"]["tp"] for s in slices.values())
    fp = sum(s[system]["detection"]["fp"] for s in slices.values())
    fn = sum(s[system]["detection"]["fn"] for s in slices.values())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3), "recall": round(r, 3),
            "f1": round(2 * p * r / (p + r), 3) if p + r else 0.0}


test = merge("test_hybrid.json", "test_baselines_and_agent.json")
dev = merge("dev_hybrid_v2.json", "dev_baselines_and_agent.json")
model = test.pop("model")
dev.pop("model", None)
summary = {s: micro(test, s) for s in SYSTEMS}

resp = [test[sl]["hybrid"]["response"] for sl in test]
linked = sum(r["attack_linked_incidents"] for r in resp)
correct = sum(round(r["technique_accuracy_incident"] * r["attack_linked_incidents"]) for r in resp)
inc = sum(r["incidents"] for r in resp)
hybrid_response = {
    "incidents": inc, "attack_linked_incidents": linked, "technique_correct": correct,
    "technique_accuracy_incident": round(correct / linked, 3) if linked else 0.0,
    "grounding_rate": 1.0 if all(r["grounding_rate"] == 1.0 for r in resp) else None,
    "policy_pass_rate": min(r["policy_pass_rate"] for r in resp),
}

final = {"split": "test", "model": model, "frozen_commit": FROZEN, "slices": test, "micro_average": summary,
         "hybrid_response": hybrid_response, "dev": dev}
(R / "final.json").write_text(json.dumps(final, indent=2), encoding="utf-8")

lines = ["| Slice | System | Recall | Precision | F1 | FP | Window recall |", "|---|---|---|---|---|---|---|"]
for sl, systems in test.items():
    for s in SYSTEMS:
        d = systems[s]["detection"]
        lines.append(f"| {sl} | {LABEL[s]} | {d['recall']:.2f} | {d['precision']:.2f} | {d['f1']:.2f} | {d['fp']} | {d['window_recall']:.2f} |")
for s in SYSTEMS:
    m = summary[s]
    lines.append(f"| **all test slices** | {LABEL[s]} | {m['recall']:.2f} | {m['precision']:.2f} | {m['f1']:.2f} | {m['fp']} | |")
(R / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
print(json.dumps(hybrid_response, indent=1))

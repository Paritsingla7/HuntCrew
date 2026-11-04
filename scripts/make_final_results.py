"""Assemble results/final.json and results/summary.md from the raw evaluation outputs (reproducible)."""
from __future__ import annotations

import json
from pathlib import Path

R = Path("results")
FROZEN = "19b8682"
SYSTEMS = ["b0", "b1", "agent", "hybrid"]
LABEL = {"b0": "B0 rules", "b1": "B1 single prompt", "agent": "Agent-led", "hybrid": "Hybrid (rules + agent)"}
# Post-hoc, no-LLM comparison baselines (ADR-031). Kept in their own block; the frozen results above are unchanged.
POST_HOC = ["b2", "b3", "b4"]
POST_LABEL = {"b2": "b2 quantile outlier rule", "b3": "b3 IsolationForest",
              "b4": "b4 B0 rules AND b2 (no-LLM triage filter)"}


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
cheap_test, cheap_dev = R / "test_cheap.json", R / "dev_cheap.json"
if cheap_test.is_file():
    ct = json.loads(cheap_test.read_text())
    final["post_hoc_cheap_baselines"] = {
        "adr": "ADR-031", "note": "post-hoc, no LLM; parameters fixed before the run (config.yaml: cheap_baselines)",
        "config": ct["config"], "micro_average": {k: micro(ct["slices"], k) for k in POST_HOC},
        "slices": ct["slices"],
        **({"dev": json.loads(cheap_dev.read_text())} if cheap_dev.is_file() else {}),
    }
(R / "final.json").write_text(json.dumps(final, indent=2), encoding="utf-8")

lines = ["| Slice | System | Recall | Precision | F1 | FP | Window recall |", "|---|---|---|---|---|---|---|"]
for sl, systems in test.items():
    for s in SYSTEMS:
        d = systems[s]["detection"]
        lines.append(f"| {sl} | {LABEL[s]} | {d['recall']:.2f} | {d['precision']:.2f} | {d['f1']:.2f} | {d['fp']} | {d['window_recall']:.2f} |")
for s in SYSTEMS:
    m = summary[s]
    lines.append(f"| **all test slices** | {LABEL[s]} | {m['recall']:.2f} | {m['precision']:.2f} | {m['f1']:.2f} | {m['fp']} | |")
if cheap_test.is_file():
    lines += ["", "Post-hoc, no-LLM comparison baselines (ADR-031; same test slices, parameters fixed beforehand):", "",
              "| Slice | System | Recall | Precision | F1 | FP | Window recall |", "|---|---|---|---|---|---|---|"]
    for sl, systems in ct["slices"].items():
        for k in POST_HOC:
            d = systems[k]["detection"]
            lines.append(f"| {sl} | {POST_LABEL[k]} | {d['recall']:.2f} | {d['precision']:.2f} | {d['f1']:.2f} | {d['fp']} | {d['window_recall']:.2f} |")
    for k in POST_HOC:
        m = final["post_hoc_cheap_baselines"]["micro_average"][k]
        lines.append(f"| **all test slices** | {POST_LABEL[k]} | {m['recall']:.2f} | {m['precision']:.2f} | {m['f1']:.2f} | {m['fp']} | |")
(R / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
print(json.dumps(hybrid_response, indent=1))

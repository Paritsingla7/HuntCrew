"""Confidence intervals for the detection scores and paired differences between systems (ADR-033).

    python scripts/bootstrap_ci.py test        # reads results/predictions_test.json, writes results/bootstrap_ci_test.json

Resamples replay windows (within each slice), the same windows for every system. No LLM, no data download.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from huntcrew.config import load_config  # noqa: E402
from huntcrew.stats import bootstrap, interval, paired_difference, pooled, window_counts  # noqa: E402

LABEL = {"b0": "B0 rules", "b2": "b2 quantile rule", "b3": "b3 IsolationForest", "b4": "b4 rules AND b2",
         "agent": "Agent-led", "hybrid": "Hybrid", "union": "Union (rules + screening)"}


def main() -> None:
    split = sys.argv[1] if len(sys.argv) > 1 else "test"
    bc = load_config()["bootstrap"]
    pred = json.loads(Path(f"results/predictions_{split}.json").read_text())
    systems = [s for s in LABEL if all(s in sl["systems"] for sl in pred["slices"].values())]
    counts = {s: {name: window_counts({tuple(k) for k in sl["systems"][s]}, {tuple(k) for k in sl["truth"]}, sl["windows"])
                  for name, sl in pred["slices"].items()} for s in systems}
    draws = bootstrap(counts, bc["n"], bc["seed"])

    rows = {}
    for s in systems:
        p, r, f = pooled(counts[s])
        rows[s] = {"precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3),
                   "f1_ci": [round(x, 3) for x in interval(draws[s][:, 2], bc["level"])],
                   "recall_ci": [round(x, 3) for x in interval(draws[s][:, 1], bc["level"])],
                   "precision_ci": [round(x, 3) for x in interval(draws[s][:, 0], bc["level"])]}
    diffs = {}
    for a, b in bc["comparisons"]:
        if a in draws and b in draws:
            diffs[f"{a} - {b}"] = paired_difference(draws[a], draws[b])
    report = {"split": split, "post_hoc": True, "adr": "ADR-033", "n": bc["n"], "seed": bc["seed"], "level": bc["level"],
              "unit": "replay window, resampled within each slice, same windows for every system",
              "systems": rows, "f1_differences": diffs}
    Path(f"results/bootstrap_ci_{split}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"| System | Precision | Recall | F1 | F1 {int(bc['level'] * 100)}% interval |\n|---|---|---|---|---|")
    for s, r in rows.items():
        print(f"| {LABEL[s]} | {r['precision']:.2f} | {r['recall']:.2f} | {r['f1']:.2f} | {r['f1_ci'][0]:.2f} to {r['f1_ci'][1]:.2f} |")
    print("\n| Difference in F1 | Mean | Interval | Share of resamples > 0 |\n|---|---|---|---|")
    for k, d in diffs.items():
        print(f"| {k} | {d['mean']:+.3f} | {d['lo']:+.3f} to {d['hi']:+.3f} | {d['share_positive']:.2f} |")


if __name__ == "__main__":
    main()

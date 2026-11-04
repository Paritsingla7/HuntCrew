"""Save per-window predictions of every available system, so intervals can be recomputed without the LLM caches.

    python scripts/export_predictions.py test        # -> results/predictions_test.json

Cheap and rule systems (b0, b2, b3, b4) are recomputed here; LLM systems (agent, hybrid, union) are read from
the resumable run files in .cache/runs (git-ignored) when they exist. Only (window, source) keys are stored.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from huntcrew.baselines import b0_findings, known_destinations  # noqa: E402
from huntcrew.cheap_baselines import CheapModel, flagged_sources  # noqa: E402
from huntcrew.config import load_config  # noqa: E402
from huntcrew.data_cic import load_cic  # noqa: E402
from huntcrew.evaluate import attack_truth  # noqa: E402
from huntcrew.replay import Replay  # noqa: E402

LLM_SYSTEMS = ("agent", "hybrid", "union")


def llm_keys(split: str, slice_name: str, system: str, n_windows: int) -> list[list] | None:
    path = Path(".cache/runs") / f"{system}_{split}_{slice_name}.jsonl"
    if not path.is_file():
        return None
    rows = {d["index"]: d for d in map(json.loads, filter(str.strip, path.read_text().splitlines()))}
    if set(rows) != set(range(n_windows)):
        print(f"  skip {system}/{slice_name}: run file covers {len(rows)} of {n_windows} windows")
        return None
    return sorted([i, f["entity"]] for i, d in rows.items() for f in d["findings"])


def main() -> None:
    split = sys.argv[1] if len(sys.argv) > 1 else "test"
    cfg = load_config()
    minutes = cfg["replay"]["window_minutes"]
    data = load_cic(cfg["data"]["cic_parquet"])
    b = cfg["splits"]["baseline_benign"]
    benign = data.select(pd.Timestamp(b["start"]), pd.Timestamp(b["end"])).flows
    known, model = known_destinations(benign), CheapModel.fit(benign, cfg["cheap_baselines"], minutes)

    out: dict = {"split": split, "slices": {}}
    for s in cfg["splits"][split]:
        sl = data.select(pd.Timestamp(s["start"]), pd.Timestamp(s["end"]))
        rp = Replay(sl.flows, s["start"], s["end"], minutes, cfg["replay"]["history_windows"])
        windows = rp.windows()
        truth = attack_truth(sl.flows, sl.labels, windows, cfg["labels"]["to_technique"], cfg["grading"]["min_attack_flows"])
        systems: dict[str, list] = {k: [] for k in ("b0", "b2", "b3", "b4")}
        for w, v in rp:
            cur = v.current()
            rule_ents = {f.entity for f in b0_findings(cur, w, cfg["baseline_rules"], known)}
            f2, f3 = set(flagged_sources(model, "b2", cur)), set(flagged_sources(model, "b3", cur))
            for name, ents in (("b0", rule_ents), ("b2", f2), ("b3", f3), ("b4", rule_ents & f2)):
                systems[name] += [[w.index, e] for e in sorted(ents)]
        for name in LLM_SYSTEMS:
            keys = llm_keys(split, s["name"], name, len(windows))
            if keys is not None:
                systems[name] = keys
        out["slices"][s["name"]] = {
            "windows": len(windows),
            "truth": sorted([int(r.window_index), str(r.entity)] for r in truth.itertuples()),  # type: ignore[arg-type]
            "systems": systems}
        print(f"{s['name']}: {len(windows)} windows, systems {sorted(systems)}")
    dest = Path(f"results/predictions_{split}.json")
    dest.write_text(json.dumps(out, separators=(",", ":")), encoding="utf-8")
    print(f"wrote {dest} ({dest.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main()

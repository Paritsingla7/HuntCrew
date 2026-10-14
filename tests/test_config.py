from pathlib import Path

import pandas as pd

from huntcrew.config import load_config

ROOT = Path(__file__).resolve().parents[1]


def test_config_has_required_sections():
    cfg = load_config(ROOT / "config.yaml")
    for key in ("llm", "rag", "data", "replay", "labels", "splits", "baseline_rules", "decision_gate"):
        assert key in cfg


def test_splits_do_not_overlap_and_are_ordered():
    cfg = load_config(ROOT / "config.yaml")
    spans = [(s["name"], pd.Timestamp(s["start"]), pd.Timestamp(s["end"]))
             for group in ("dev", "test") for s in cfg["splits"][group]]
    for name, a, b in spans:
        assert a < b, name
    spans.sort(key=lambda x: x[1])
    for (n1, _, e1), (n2, s2, _) in zip(spans, spans[1:], strict=False):
        assert e1 <= s2, f"{n1} overlaps {n2}"


def test_every_scoped_attack_label_has_a_technique_mapping():
    cfg = load_config(ROOT / "config.yaml")
    attacks = set(cfg["labels"]["in_scope"]) - {"BENIGN"}
    assert attacks == set(cfg["labels"]["to_technique"])


def test_policy_actions_have_valid_risk_levels():
    import json
    pol = json.load(open(ROOT / "data" / "policy" / "policy.json"))
    assert {v["risk"] for v in pol["action_catalog"].values()} <= {"low", "medium", "high"}
    assert pol["protected_assets"]

"""Grading by plain code against the dataset's own labels. Nothing here calls an LLM.

Granularity is (window, entity): a source in a window is attack-positive when it has at least
`min_attack_flows` attack-labelled flows in that window (labels are not entity-clean, see
docs/data-provenance.md). Technique matching is parent-level (T1110 accepts T1110.001).
"""
from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from typing import cast

import pandas as pd

from .replay import Window
from .schema import Finding


def attack_truth(flows: pd.DataFrame, labels: pd.Series, windows: list[Window],
                 label_to_technique: dict[str, str], min_attack_flows: int) -> pd.DataFrame:
    """Rows: window_index, entity, label, technique, n_attack_flows. Attack labels only."""
    if not windows:
        return pd.DataFrame(columns=["window_index", "entity", "label", "technique", "n_attack_flows"])
    start, step = windows[0].start, windows[0].end - windows[0].start
    lab = labels.astype(str).reset_index(drop=True)
    f = flows.reset_index(drop=True)
    mask = lab.isin(label_to_technique)
    df = pd.DataFrame({"entity": f.loc[mask, "src_ip"].values, "label": lab[mask].values,
                       "idx": ((f.loc[mask, "ts"] - start) // step).astype(int).values})
    df = df[(df.idx >= 0) & (df.idx < len(windows))]
    g = df.groupby(["idx", "entity", "label"]).size().rename("n_attack_flows").reset_index()
    g = g[g.n_attack_flows >= min_attack_flows].rename(columns={"idx": "window_index"})
    g["technique"] = g["label"].map(label_to_technique)
    return g.reset_index(drop=True)


def parent(technique_id: str) -> str:
    return technique_id.split(".")[0]


def score_findings(findings: Iterable[Finding], truth: pd.DataFrame, windows: list[Window]) -> dict:
    """(window, entity)-level detection scores and parent-level technique accuracy on true positives."""
    starts = {pd.Timestamp(w.start): w.index for w in windows}
    pred: dict[tuple[int, str], list[str]] = defaultdict(list)
    for f in findings:
        ws = pd.Timestamp(f.window_start)
        if not f.suspicious or ws not in starts:
            continue
        pred[(starts[ws], f.entity)].extend(h.id for h in f.technique_hints)

    truth_tech: dict[tuple[int, str], set[str]] = defaultdict(set)
    for r in truth.itertuples(index=False):
        truth_tech[(int(cast(int, r.window_index)), str(r.entity))].add(str(r.technique))

    keys_t, keys_p = set(truth_tech), set(pred)
    tp, fp, fn = keys_t & keys_p, keys_p - keys_t, keys_t - keys_p
    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 0.0
    recall = len(tp) / len(keys_t) if keys_t else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    tech_ok = sum(1 for k in tp if {parent(h) for h in pred[k]} & truth_tech[k])
    attack_windows = {k[0] for k in keys_t}
    hit_windows = {k[0] for k in tp}
    per_tech: dict[str, dict[str, int]] = defaultdict(lambda: {"truth": 0, "tp": 0})
    for k, techs in truth_tech.items():
        for t in techs:
            per_tech[t]["truth"] += 1
            per_tech[t]["tp"] += int(k in tp)
    return {
        "truth_positives": len(keys_t), "predicted_positives": len(keys_p),
        "tp": len(tp), "fp": len(fp), "fn": len(fn),
        "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
        "window_recall": round(len(hit_windows) / len(attack_windows), 3) if attack_windows else 0.0,
        "technique_accuracy_on_tp": round(tech_ok / len(tp), 3) if tp else 0.0,
        "per_technique": dict(per_tech),
    }


def grade_outcomes(outcomes: list, truth: pd.DataFrame, windows: list[Window], kb_ids: set[str]) -> dict:
    """Incident-level grading of the full pipeline (technique naming, grounding, response quality).

    An incident is *attack-linked* when at least one of its (window, entity) findings is attack-positive.
    Technique accuracy is measured on attack-linked incidents only, at parent level.
    """
    starts = {pd.Timestamp(w.start): w.index for w in windows}
    truth_tech: dict[tuple[int, str], set[str]] = defaultdict(set)
    for r in truth.itertuples(index=False):
        truth_tech[(int(cast(int, r.window_index)), str(r.entity))].add(str(r.technique))

    linked = correct = 0
    cited = grounded = 0
    actions = executed_or_denied = with_mitigation = 0
    for o in outcomes:
        keys = {(starts.get(pd.Timestamp(f.window_start), -1), f.entity) for f in o.incident.findings}
        want: set[str] = set()
        for k in keys:
            want |= truth_tech.get(k, set())
        if want:
            linked += 1
            got = {parent(t.id) for t in o.assessment.techniques}
            correct += int(bool(got & want))
        n_ok, n_drop = len(o.assessment.techniques), len(o.assessment.dropped_ids)
        cited += n_ok + n_drop
        grounded += sum(1 for t in o.assessment.techniques if t.id in kb_ids)
        for r in o.log.records:
            actions += 1
            executed_or_denied += int(r.status != "rejected")
            with_mitigation += int(r.action.mitigation_id is not None)
        actions += len(o.guard.dropped_actions)               # unknown action types never reach the executor
    return {
        "incidents": len(outcomes), "attack_linked_incidents": linked,
        "incident_precision": round(linked / len(outcomes), 3) if outcomes else 0.0,
        "technique_accuracy_incident": round(correct / linked, 3) if linked else 0.0,
        "grounding_rate": round(grounded / cited, 3) if cited else 1.0,
        "policy_pass_rate": round(executed_or_denied / actions, 3) if actions else 1.0,
        "mitigation_grounded_share": round(with_mitigation / actions, 3) if actions else 0.0,
        "proposed_actions": actions,
    }

"""B0: a classic rules engine with a fixed rule -> technique map (what a basic SIEM does).

These thresholds are hand-made on purpose (see docs/03-architecture.md, "What is still hand-made").
The agent detector does not use them; B0 exists to be beaten, or to show the agent cannot beat it.
"""
from __future__ import annotations

import pandas as pd

from .digest import is_private
from .replay import Window
from .schema import Finding, TechniqueHint

RULE_TO_TECHNIQUE = {"password_guessing": "T1110", "port_scan": "T1046", "beaconing": "T1071"}


def _finding(window: Window, entity: str, rule: str, behaviour: str, evidence: dict[str, float]) -> Finding:
    return Finding(window_start=window.start, window_end=window.end, entity=entity, behaviour=behaviour,
                   evidence=evidence, confidence=1.0, suspicious=True,
                   technique_hints=[TechniqueHint(id=RULE_TO_TECHNIQUE[rule], citation=f"b0-rule:{rule}")])


def known_destinations(baseline_flows: pd.DataFrame) -> set[str]:
    """External destinations seen in benign baseline traffic (used by the rarity condition)."""
    d = baseline_flows["dst_ip"].drop_duplicates()
    return {str(i) for i in d if not is_private(str(i))}


def b0_findings(current: pd.DataFrame, window: Window, rules: dict,
                known_dsts: set[str] | None = None) -> list[Finding]:
    if current.empty:
        return []
    out: list[Finding] = []

    pg = rules["password_guessing"]
    svc = current[current["dst_port"].isin(pg["ports"])]
    for (src, port), n in svc.groupby(["src_ip", "dst_port"]).size().items():
        if n >= pg["min_flows"]:
            out.append(_finding(window, str(src), "password_guessing",
                                f"{n} flows to port {port}", {"flows": float(n), "dst_port": float(port)}))

    ps = rules["port_scan"]
    # distinct ports on ONE destination host; a server replying to many clients is not scanning
    pair = current.groupby(["src_ip", "dst_ip"])["dst_port"].nunique()
    for (src, dst), n in pair[pair >= ps["min_distinct_ports"]].items():
        out.append(_finding(window, str(src), "port_scan",
                            f"{n} distinct destination ports on {dst}",
                            {"distinct_ports": float(n)}))

    bc = rules["beaconing"]
    ext = current[~current["dst_ip"].map(is_private)]
    if bc.get("require_rare_destination") and known_dsts is not None:
        ext = ext[~ext["dst_ip"].isin(known_dsts)]      # only destinations never seen in normal traffic
    if not ext.empty:
        minute = ext["ts"].dt.floor("min")
        trip = ext.assign(_m=minute).groupby(["src_ip", "dst_ip", "dst_port", "_m"]).size()
        for (src, dst, port), counts in trip.groupby(level=[0, 1, 2]):
            if len(counts) >= bc["min_active_minutes"] and counts.sum() >= bc["min_flows"]:
                mean = counts.mean()
                cv = counts.std(ddof=0) / mean if mean else 0.0
                if cv <= bc["max_cv"]:
                    out.append(_finding(window, str(src), "beaconing",
                                        f"regular flows to {dst}:{port}",
                                        {"flows": float(counts.sum()), "cv": float(round(cv, 3)),
                                         "dst_port": float(port)}))
    return out

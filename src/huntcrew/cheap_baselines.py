"""Post-hoc, no-LLM comparison baselines (ADR-031).

They answer one question the frozen evaluation could not: does the LLM earn its place?

  b2  per-feature outlier rule: flag a source if any feature is above the q-quantile seen in benign traffic;
  b3  IsolationForest fitted on benign (window, source) rows, flagged above a benign score quantile;
  b4  B0 rule findings kept only when b2 also flags the source (a non-LLM triage filter for the hybrid).

Everything is fitted on the benign Monday only, uses the current window alone (no look-ahead), never sees a
label, and takes its settings from `config.yaml` (`cheap_baselines`). New detectors register by name in
`DETECTORS`, so adding one needs no change to the callers.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import numpy as np
import pandas as pd

from .replay import Window
from .schema import Finding

ALL_FEATURES = ("flows", "dst_ips", "dst_ports", "fwd_bytes", "syn", "rst", "max_ports_per_dst", "top_port_share")


def source_features(flows: pd.DataFrame, window_minutes: int) -> pd.DataFrame:
    """Raw per-(window bucket, source) statistics, plain arithmetic. Index: (bucket, src_ip)."""
    if flows.empty:
        return pd.DataFrame(columns=list(ALL_FEATURES),
                            index=pd.MultiIndex.from_arrays([[], []], names=["_b", "src_ip"]))
    df = flows.assign(_b=flows["ts"].dt.floor(f"{window_minutes}min"))
    g = df.groupby(["_b", "src_ip"])
    out = pd.DataFrame({
        "flows": g.size(),
        "dst_ips": g["dst_ip"].nunique(),
        "dst_ports": g["dst_port"].nunique(),
        "fwd_bytes": g["fwd_bytes"].sum(),
        "syn": g["syn_count"].sum(),
        "rst": g["rst_count"].sum(),
    })
    per_dst = df.groupby(["_b", "src_ip", "dst_ip"])["dst_port"].nunique().groupby(level=[0, 1]).max()
    top_port = df.groupby(["_b", "src_ip", "dst_port"]).size().groupby(level=[0, 1]).max()
    out["max_ports_per_dst"] = per_dst.reindex(out.index)
    out["top_port_share"] = top_port.reindex(out.index) / out["flows"]
    return out[list(ALL_FEATURES)].astype(float)


def feature_matrix(raw: pd.DataFrame, features: list[str]) -> pd.DataFrame:
    """Model input: the chosen features on a log scale (counts span orders of magnitude)."""
    return raw[features].apply(np.log1p)


@dataclass
class CheapModel:
    """Everything fitted from benign traffic. Build with `CheapModel.fit`."""

    cfg: dict[str, Any]
    window_minutes: int
    features: list[str]
    thresholds: pd.Series
    iso: Any = None
    iso_cut: float = float("inf")
    n_train_rows: int = 0
    extras: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def fit(cls, benign_flows: pd.DataFrame, cfg: dict[str, Any], window_minutes: int) -> CheapModel:
        feats = [f for f in cfg.get("features", list(ALL_FEATURES))]
        unknown = set(feats) - set(ALL_FEATURES)
        if unknown:
            raise ValueError(f"unknown cheap-baseline features: {sorted(unknown)}")
        raw = source_features(benign_flows, window_minutes)
        if raw.empty:
            raise ValueError("cannot fit cheap baselines on empty benign traffic")
        m = feature_matrix(raw, feats)
        model = cls(cfg=cfg, window_minutes=window_minutes, features=feats,
                    thresholds=m.quantile(cfg["quantile"]["q"]), n_train_rows=len(m))
        iso_cfg = cfg.get("isolation_forest")
        if iso_cfg:
            from sklearn.ensemble import IsolationForest

            model.iso = IsolationForest(n_estimators=iso_cfg["n_estimators"],
                                        random_state=iso_cfg["random_state"]).fit(m)
            model.iso_cut = float(np.quantile(-model.iso.score_samples(m), iso_cfg["flag_quantile"]))
        return model

    def matrix(self, raw: pd.DataFrame) -> pd.DataFrame:
        return feature_matrix(raw, self.features)


Detector = Callable[[CheapModel, pd.DataFrame], pd.Series]
DETECTORS: dict[str, Detector] = {}


def detector(name: str) -> Callable[[Detector], Detector]:
    def deco(fn: Detector) -> Detector:
        DETECTORS[name] = fn
        return fn
    return deco


@detector("b2")
def quantile_flags(model: CheapModel, raw: pd.DataFrame) -> pd.Series:
    return (model.matrix(raw) > model.thresholds).any(axis=1)


@detector("b3")
def isolation_flags(model: CheapModel, raw: pd.DataFrame) -> pd.Series:
    if model.iso is None:
        raise ValueError("isolation_forest is not configured")
    return pd.Series(-model.iso.score_samples(model.matrix(raw)) > model.iso_cut, index=raw.index)


def flagged_sources(model: CheapModel, name: str, current: pd.DataFrame) -> dict[str, str]:
    """Sources the named detector flags in ONE window of flows, with a short plain reason."""
    if name not in DETECTORS:
        raise KeyError(f"unknown cheap detector '{name}'; known: {sorted(DETECTORS)}")
    raw = source_features(current, model.window_minutes)
    if raw.empty:
        return {}
    raw = raw.droplevel(0)
    flags = DETECTORS[name](model, raw) & (raw["flows"] >= model.cfg["min_flows"])
    out: dict[str, str] = {}
    for ip in raw.index[flags.to_numpy()]:
        if name == "b3":
            out[str(ip)] = "isolation-forest outlier vs benign"
        else:
            above = (model.matrix(raw.loc[[ip]]).iloc[0] > model.thresholds)
            out[str(ip)] = "above benign quantile: " + ", ".join(above.index[above.to_numpy()])
    return out


def cheap_findings(model: CheapModel, name: str, current: pd.DataFrame, window: Window) -> list[Finding]:
    """Findings for one window. No technique hints: these baselines detect, they do not name."""
    flows = current.groupby("src_ip").size() if not current.empty else pd.Series(dtype=int)
    return [Finding(window_start=window.start, window_end=window.end, entity=ip, behaviour=why,
                    evidence={"flows": float(flows.get(ip, 0))}, confidence=1.0, suspicious=True)
            for ip, why in flagged_sources(model, name, current).items()]


def filter_findings(findings: list[Finding], flagged: set[str]) -> list[Finding]:
    """b4: keep the rule findings whose source the anomaly detector also flags."""
    return [f for f in findings if f.entity in flagged]

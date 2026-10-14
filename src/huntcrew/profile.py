"""Baseline profile of normal traffic (from the benign-only Monday), used as context for the detector.

This is a lookup table of what is usual per source, not a verdict: the detector decides what to do with it.
"""
from __future__ import annotations

import pandas as pd


class BaselineProfile:
    def __init__(self, flows: pd.DataFrame, window_minutes: int = 5):
        bucket = flows["ts"].dt.floor(f"{window_minutes}min")
        per = (flows.assign(_w=bucket).groupby(["src_ip", "_w"])
               .agg(flows=("dst_ip", "size"), ports=("dst_port", "nunique")))
        g = per.groupby(level=0)
        self.n_windows = int(bucket.nunique())
        self._active = g.size().to_dict()
        self._med = g["flows"].median().to_dict()
        self._p95 = g["flows"].quantile(0.95).to_dict()
        self._max = g["flows"].max().to_dict()
        self._ports_med = g["ports"].median().to_dict()
        self._ports_p95 = g["ports"].quantile(0.95).to_dict()
        self._dsts = set(flows["dst_ip"].astype(str).unique())

    def lookup(self, ip: str) -> dict:
        if ip not in self._active:
            return {"seen_in_baseline": False}
        return {
            "seen_in_baseline": True,
            "active_windows": f"{int(self._active[ip])}/{self.n_windows}",
            "flows_per_window_median": float(self._med[ip]),
            "flows_per_window_p95": float(self._p95[ip]),
            "flows_per_window_max": int(self._max[ip]),
            "dst_ports_per_window_median": float(self._ports_med[ip]),
            "dst_ports_per_window_p95": float(self._ports_p95[ip]),
        }

    def destination_known(self, ip: str) -> bool:
        return ip in self._dsts

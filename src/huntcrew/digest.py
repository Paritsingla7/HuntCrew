"""Window digest: per-source statistics computed with arithmetic only.

Deliberately contains no thresholds and no verdicts, so the decision of what is suspicious stays
with the detector agent.

A window can hold hundreds of sources (in CIC-IDS2017 ~13 internal hosts and ~500 public addresses with
1-3 flows each), so the listing is structured, not truncated by one ranking:
  * every private (in-network) source is listed;
  * public sources are listed if they lead in ANY of several neutral views (flows, destinations,
    ports, outbound bytes, most regular timing), so a quiet source is not hidden by volume alone;
  * everything else is summarised with explicit counts, never silently dropped.
The agent's tools can query any source individually, so the digest is a starting point.
"""
from __future__ import annotations

import ipaddress
from functools import cache

import numpy as np
import pandas as pd

from .replay import Window
from .schema import EntityStats, WindowDigest

_RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


@cache
def is_private(ip: str) -> bool:
    """RFC 1918 address (an in-network host). Deliberately narrower than ipaddress.is_private,
    which also covers loopback, link-local and documentation ranges."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _RFC1918)


def _ip_key(ip: str) -> tuple[int, int]:
    try:
        a = ipaddress.ip_address(ip)
        return (a.version, int(a))
    except ValueError:
        return (0, 0)


def build_digest(flows: pd.DataFrame, window: Window, max_private: int = 40,
                 public_top_k: int = 6) -> WindowDigest:
    if flows.empty:
        return WindowDigest(window_start=window.start, window_end=window.end, total_flows=0,
                            sources=0, entities=[])

    df = flows
    minute = df["ts"].dt.floor("min")
    g = df.groupby("src_ip", sort=False)
    base = pd.DataFrame({
        "flows": g.size(),
        "dst_ips": g["dst_ip"].nunique(),
        "dst_ports": g["dst_port"].nunique(),
        "mean_duration_ms": g["duration_us"].mean() / 1000.0,
        "fwd_bytes": g["fwd_bytes"].sum(),
        "bwd_bytes": g["bwd_bytes"].sum(),
        "syn": g["syn_count"].sum(),
        "rst": g["rst_count"].sum(),
    })

    ext = df.loc[~df["dst_ip"].map(is_private), ["src_ip", "dst_ip"]]
    base["ext_dst_ips"] = ext.groupby("src_ip")["dst_ip"].nunique().reindex(base.index).fillna(0).astype(int)

    per_min = df.assign(_m=minute).groupby(["src_ip", "_m"]).size()
    pm = per_min.groupby(level=0)
    base["active_minutes"] = pm.size()
    base["per_minute_mean"] = pm.mean()
    std = pm.std(ddof=0)
    base["per_minute_cv"] = (std / base["per_minute_mean"]).where(base["active_minutes"] >= 2, 0.0).fillna(0.0)

    ports = df.groupby(["src_ip", "dst_port"]).size().rename("n").reset_index()
    ports = ports.sort_values(["src_ip", "n", "dst_port"], ascending=[True, False, True])
    port_max = ports.groupby("src_ip")["n"].max()
    dst_max = df.groupby(["src_ip", "dst_ip"]).size().groupby(level=0).max()
    base["top_port_share"] = (port_max / base["flows"]).reindex(base.index).fillna(0.0)
    base["top_dst_share"] = (dst_max / base["flows"]).reindex(base.index).fillna(0.0)
    top: dict[str, list[tuple[int, int]]] = {}
    for src, port, n in ports.groupby("src_ip").head(3).itertuples(index=False):
        top.setdefault(str(src), []).append((int(port), int(n)))

    base = base.sort_values("flows", ascending=False, kind="stable")
    private = base[[is_private(str(i)) for i in base.index]]
    public = base.drop(index=private.index)
    chosen = list(private.head(max_private).index)
    views = [public.nlargest(public_top_k, col, keep="first").index
             for col in ("flows", "dst_ports", "dst_ips", "fwd_bytes")]
    regular = public[public["active_minutes"] >= 3].nsmallest(public_top_k, "per_minute_cv", keep="first").index
    for idx in (*views, regular):
        chosen.extend(i for i in idx if i not in chosen)
    # neutral order (numeric by address), not by volume, so row position carries no signal
    shown = base.loc[sorted(chosen, key=lambda i: _ip_key(str(i)))]
    rest = base.drop(index=shown.index)
    peers: dict[str, float] = {}
    if len(private):
        peers = {"flows": float(private["flows"].median()), "dst_ips": float(private["dst_ips"].median()),
                 "dst_ports": float(private["dst_ports"].median()),
                 "per_min_cv": float(np.round(private["per_minute_cv"].median(), 2))}
    entities = [
        EntityStats(
            entity=str(ip), is_private=is_private(str(ip)), flows=int(r.flows), dst_ips=int(r.dst_ips),
            dst_ports=int(r.dst_ports), top_ports=top.get(str(ip), []), ext_dst_ips=int(r.ext_dst_ips),
            mean_duration_ms=float(np.round(r.mean_duration_ms, 3)), fwd_bytes=int(r.fwd_bytes),
            bwd_bytes=int(r.bwd_bytes), syn=int(r.syn), rst=int(r.rst), active_minutes=int(r.active_minutes),
            per_minute_mean=float(np.round(r.per_minute_mean, 3)), per_minute_cv=float(np.round(r.per_minute_cv, 3)),
            top_port_share=float(np.round(r.top_port_share, 3)), top_dst_share=float(np.round(r.top_dst_share, 3)),
        )
        for ip, r in shown.iterrows()
    ]
    return WindowDigest(window_start=window.start, window_end=window.end, total_flows=int(len(df)),
                        sources=int(len(base)), entities=entities, omitted=int(len(rest)),
                        omitted_flows=int(rest["flows"].sum()) if len(rest) else 0,
                        omitted_max_flows=int(rest["flows"].max()) if len(rest) else 0,
                        omitted_max_dst_ports=int(rest["dst_ports"].max()) if len(rest) else 0,
                        peers=peers)


def entity_stats(flows: pd.DataFrame, ip: str, window: Window) -> EntityStats | None:
    """Statistics for one source in `flows` (same arithmetic as the digest), or None if it is absent."""
    sub = flows[flows["src_ip"] == ip]
    if sub.empty:
        return None
    return build_digest(sub, window, max_private=1, public_top_k=1).entities[0]

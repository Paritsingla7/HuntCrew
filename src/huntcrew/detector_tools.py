"""Read-only tools the detector agent may call. All data flows through the replay `FlowView`, so a tool
can look back a bounded number of windows and never forward, and nothing here can see a label."""
from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pandas as pd

from .attack_kb import AttackKB
from .digest import build_digest, entity_stats, is_private
from .profile import BaselineProfile
from .replay import FlowView, Window
from .schema import WindowDigest

RANK_KEYS = {"flows", "dst_ports", "dst_ips", "fwd_bytes", "regularity"}


@dataclass
class DetectorContext:
    window: Window
    view: FlowView
    digest: WindowDigest
    kb: AttackKB
    profile: BaselineProfile
    trace_start: int = 0             # index into kb.trace where this window's searches begin

    def retrieved_ids(self) -> set[str]:
        return {i for t in self.kb.trace[self.trace_start:] for i in t["ids"]}


def list_sources(ctx: DetectorContext, by: str = "flows", n: int = 8) -> str:
    """Rank ALL sources in the current window by one neutral metric (not limited to the digest)."""
    if by not in RANK_KEYS:
        return f"unknown ranking '{by}'; choose one of {sorted(RANK_KEYS)}"
    n = max(1, min(int(n), 15))
    cur = ctx.view.current()
    if cur.empty:
        return "no flows in this window"
    g = cur.groupby("src_ip")
    s: pd.Series
    if by == "flows":
        s = g.size()
    elif by == "dst_ports":
        s = g["dst_port"].nunique()
    elif by == "dst_ips":
        s = g["dst_ip"].nunique()
    elif by == "fwd_bytes":
        s = g["fwd_bytes"].sum()
    else:   # regularity: lowest coefficient of variation of flows per minute among sources active >= 3 minutes
        pm = cur.assign(_m=cur["ts"].dt.floor("min")).groupby(["src_ip", "_m"]).size().groupby(level=0)
        cv = (pm.std(ddof=0) / pm.mean()).where(pm.size() >= 3).dropna()
        s = cv.sort_values().head(n)
        return "\n".join(f"{ip} per_min_cv={v:.2f}" for ip, v in s.items()) or "no source active >= 3 minutes"
    top = s.sort_values(ascending=False, kind="stable").head(n)
    sizes = g.size().to_dict()
    return "\n".join(f"{ip} {by}={int(v)} flows={int(sizes[ip])}" for ip, v in top.items())


def source_profile(ctx: DetectorContext, ip: str) -> str:
    """Detail for one source: this window, recent history, top destinations, and its normal baseline."""
    cur = ctx.view.current()
    st = entity_stats(cur, ip, ctx.window)
    if st is None:
        return f"{ip}: no flows as a source in this window"
    out = [f"{ip} private={int(st.is_private)} flows={st.flows} dst_ips={st.dst_ips} dst_ports={st.dst_ports} "
           f"top_ports={','.join(f'{p}:{n}' for p, n in st.top_ports)} ext_dst={st.ext_dst_ips} "
           f"fwd_B={st.fwd_bytes} bwd_B={st.bwd_bytes} syn={st.syn} rst={st.rst} "
           f"act_min={st.active_minutes} per_min={st.per_minute_mean} per_min_cv={st.per_minute_cv}"]
    hist = ctx.view.history()
    h = hist[hist["src_ip"] == ip]
    if not h.empty:
        step_s = (ctx.window.end - ctx.window.start).total_seconds()
        secs = (ctx.window.start - h["ts"]).dt.total_seconds()
        ago = ((secs - 1e-9) // step_s + 1).astype(int).value_counts().sort_index()
        out.append("history flows by windows-ago: " + ", ".join(f"{int(k)}:{int(v)}" for k, v in ago.head(6).items()))
    else:
        out.append("history: no flows from this source in the look-back")
    dest = (cur[cur["src_ip"] == ip].groupby(["dst_ip", "dst_port"]).size().reset_index(name="n")
            .sort_values("n", ascending=False, kind="stable").head(4))
    parts = []
    for r in dest.itertuples(index=False):
        d = str(r.dst_ip)
        tag = "" if is_private(d) else (" (known)" if ctx.profile.destination_known(d) else " (never seen in baseline)")
        parts.append(f"{d}:{int(cast(int, r.dst_port))} x{int(cast(int, r.n))}{tag}")
    out.append("top destinations: " + "; ".join(parts))
    out.append("baseline: " + ", ".join(f"{k}={v}" for k, v in ctx.profile.lookup(ip).items()))
    return "\n".join(out)


def search_attack_kb(ctx: DetectorContext, query: str) -> str:
    """Search the official MITRE ATT&CK knowledge base by meaning. Returns IDs you may cite."""
    hits = ctx.kb.search(query, k=4)
    return "\n".join(f"{h.id} {h.name} [{', '.join(h.tactics)}] score={h.score:.2f}: {h.snippet[:170]}" for h in hits)


def window_digest_text(flows: pd.DataFrame, window: Window, max_private: int = 40, public_top_k: int = 6) -> str:
    return build_digest(flows, window, max_private, public_top_k).to_text()

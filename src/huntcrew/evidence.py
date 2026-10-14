"""Evidence check: code verifies what the detector claims, before anything downstream trusts it.

A finding survives only if its entity exists in the window and none of its quoted numbers contradicts
the real statistics. Technique hints must be real ATT&CK IDs that were actually retrieved in this window.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .detector_tools import DetectorContext
from .digest import entity_stats
from .schema import Finding, TechniqueHint

CHECKABLE = ("flows", "dst_ips", "dst_ports", "ext_dst_ips", "fwd_bytes", "bwd_bytes", "syn", "rst",
             "active_minutes", "per_minute_mean", "per_minute_cv", "mean_duration_ms")


@dataclass
class Verdict:
    ok: bool
    reasons: list[str] = field(default_factory=list)
    verified: int = 0
    unverifiable: int = 0
    dropped_hints: list[str] = field(default_factory=list)
    finding: Finding | None = None


def _close(claimed: float, actual: float) -> bool:
    return abs(claimed - actual) <= max(0.05, 0.05 * abs(actual))


def verify_finding(draft: dict, ctx: DetectorContext, known_ids: set[str]) -> Verdict:
    entity = str(draft.get("entity", "")).strip()
    st = entity_stats(ctx.view.current(), entity, ctx.window) if entity else None
    if st is None:
        return Verdict(False, [f"entity {entity or '<empty>'} has no flows in this window"])

    v = Verdict(True)
    actual = st.model_dump()
    clean_ev: dict[str, float] = {}
    for k, raw in (draft.get("evidence") or {}).items():
        try:
            claimed = float(raw)
        except (TypeError, ValueError):
            v.unverifiable += 1
            continue
        if k not in CHECKABLE:
            v.unverifiable += 1
            continue
        if _close(claimed, float(actual[k])):
            v.verified += 1
            clean_ev[k] = claimed
        else:
            v.ok = False
            v.reasons.append(f"{k}: claimed {claimed:g}, actual {float(actual[k]):g}")
    if v.ok and v.verified == 0:
        v.ok = False
        v.reasons.append("no verifiable evidence quoted")

    retrieved = ctx.retrieved_ids()
    hints: list[TechniqueHint] = []
    for h in draft.get("technique_hints") or []:
        tid = str((h or {}).get("id", "")).strip()
        if tid in known_ids and tid in retrieved:
            hints.append(TechniqueHint(id=tid, citation=str((h or {}).get("citation", tid))))
        elif tid:
            v.dropped_hints.append(tid)

    if v.ok:
        try:
            conf = max(0.0, min(1.0, float(draft.get("confidence", 0.5))))
        except (TypeError, ValueError):
            conf = 0.5
        v.finding = Finding(window_start=ctx.window.start, window_end=ctx.window.end, entity=entity,
                            behaviour=str(draft.get("behaviour", ""))[:300], evidence=clean_ev,
                            technique_hints=hints, confidence=conf, suspicious=True)
    return v

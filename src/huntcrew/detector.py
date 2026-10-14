"""Detector agent: decides what is suspicious in one replay window.

The agent (CrewAI + Mistral) sees a statistics-only digest, can query flows and search ATT&CK, and
answers with JSON findings. Code then verifies every finding (evidence.py); only verified findings leave
this module. Nothing here uses detection rules or labels.
"""
from __future__ import annotations

import json
import os
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

import pandas as pd  # noqa: E402

from .attack_kb import AttackKB  # noqa: E402
from .detector_tools import DetectorContext, list_sources, search_attack_kb, source_profile  # noqa: E402
from .evidence import verify_finding  # noqa: E402
from .llm import Middleware  # noqa: E402
from .profile import BaselineProfile  # noqa: E402
from .replay import Replay, Window  # noqa: E402
from .schema import Finding, Incident  # noqa: E402

TASK_TEMPLATE = """You are reviewing ONE {minutes}-minute window of network flow statistics ({label}).
Decide which source addresses behave like an attack or a compromised host.

Method:
1. Compare every listed source with its peers (see the PEERS line) and with what is typical for it.
   Sources are listed in address order, not by importance. Most sources are ordinary clients and servers.
2. For each source whose pattern is clearly unlike its peers, call source_profile and compare it with its
   normal baseline and recent history. Volume alone is NOT suspicious, and a destination never seen in
   the baseline is common for ordinary browsing and name lookups, so it is not suspicious by itself.
3. Describe what the source is doing in plain terms (how many destinations, how many ports, how regular,
   how much data), then call search_attack_kb with that description. Flag the source only if a retrieved
   ATT&CK technique genuinely matches the behaviour.
4. Only quote numbers that appear in the digest or in tool outputs. Only cite technique IDs returned by
   search_attack_kb. At most 5 findings, shortest evidence that proves the point. If nothing stands out,
   return {{"findings": []}}.

Allowed evidence metric names: flows, dst_ips, dst_ports, ext_dst_ips, fwd_bytes, bwd_bytes, syn, rst,
active_minutes, per_minute_mean, per_minute_cv, mean_duration_ms.

Final answer must be ONLY this JSON (no prose):
{{"findings": [{{"entity": "<source ip>", "behaviour": "<=25 words", "evidence": {{"flows": 0}},
"technique_hints": [{{"id": "T0000", "citation": "T0000"}}], "confidence": 0.0}}]}}

DIGEST
{digest}
"""


@dataclass
class WindowResult:
    window: Window
    findings: list[Finding] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    dropped_hints: int = 0
    parse_error: bool = False
    raw: str = ""
    usage: dict[str, float] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        return {"index": self.window.index, "start": str(self.window.start), "end": str(self.window.end),
                "findings": [f.model_dump(mode="json") for f in self.findings], "rejected": self.rejected,
                "dropped_hints": self.dropped_hints, "parse_error": self.parse_error,
                "raw": self.raw[:2000], "usage": self.usage}


def parse_findings_json(text: str) -> list[dict] | None:
    """Extract the findings list from model output. None means unparseable."""
    if not text:
        return None
    i, j = text.find("{"), text.rfind("}")
    if i < 0 or j <= i:
        return None
    try:
        data = json.loads(text[i:j + 1])
    except json.JSONDecodeError:
        return None
    items = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None
    return [x for x in items if isinstance(x, dict)]


def build_tools(ctx: DetectorContext) -> list[Any]:
    from crewai.tools import tool

    @tool("list_sources")
    def list_sources_tool(by: str = "flows", n: int = 8) -> str:
        """Rank ALL sources in the current window by one metric: flows, dst_ports, dst_ips, fwd_bytes or
        regularity (lowest per-minute variation). Use it to look beyond the digest."""
        return list_sources(ctx, by, n)

    @tool("source_profile")
    def source_profile_tool(ip: str) -> str:
        """Detail for one source address: this window, recent history, top destinations (flagging
        never-seen ones) and its normal baseline."""
        return source_profile(ctx, ip)

    @tool("search_attack_kb")
    def search_attack_kb_tool(query: str) -> str:
        """Search the MITRE ATT&CK knowledge base by meaning, e.g. 'many failed logins to one service'.
        Returns technique IDs you may cite."""
        return search_attack_kb(ctx, query)

    return [list_sources_tool, source_profile_tool, search_attack_kb_tool]


def _run_agent(llm: Any, tools: list[Any], prompt: str, max_iter: int) -> str:
    from crewai import Agent, Crew, Process, Task

    agent = Agent(
        role="Network threat detector",
        goal="Find sources whose behaviour in this window indicates an attack, and avoid false alarms.",
        backstory="A careful SOC analyst who verifies suspicions against baselines and ATT&CK before flagging.",
        tools=tools, llm=llm, max_iter=max_iter, allow_delegation=False, verbose=False,
    )
    task = Task(description=prompt, expected_output="Only the JSON object described in the task.", agent=agent)
    crew = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False)
    out = crew.kickoff()
    return str(getattr(out, "raw", out))


def detect_window(ctx: DetectorContext, llm: Any, known_ids: set[str], minutes: int, max_iter: int = 5,
                  mw: Middleware | None = None) -> WindowResult:
    before = mw.stats.snapshot() if mw else {}
    ctx.trace_start = len(ctx.kb.trace)
    res = WindowResult(window=ctx.window)
    if ctx.digest.total_flows == 0:
        return res
    prompt = TASK_TEMPLATE.format(minutes=minutes, label=ctx.window.label(), digest=ctx.digest.to_text())
    raw = _run_agent(llm, build_tools(ctx), prompt, max_iter)
    res.raw = raw
    items = parse_findings_json(raw)
    if items is None:
        res.parse_error = True
    else:
        for draft in items[:5]:
            v = verify_finding(draft, ctx, known_ids)
            res.dropped_hints += len(v.dropped_hints)
            if v.ok and v.finding is not None:
                res.findings.append(v.finding)
            else:
                res.rejected.append({"entity": str(draft.get("entity", "")), "reasons": v.reasons})
    if mw:
        res.usage = mw.stats.delta(before)
    return res


def run_detector(flows: pd.DataFrame, start: str, end: str, cfg: dict, kb: AttackKB, profile: BaselineProfile,
                 llm: Any, out_path: str | Path, mw: Middleware | None = None,
                 only_windows: Iterable[int] | None = None, limit: int | None = None) -> list[WindowResult]:
    """Replay [start, end) window by window. Results are appended to `out_path` (jsonl) so a run resumes."""
    from .digest import build_digest

    rp = Replay(flows, start, end, cfg["replay"]["window_minutes"], cfg["replay"]["history_windows"])
    known = set(kb.chunks)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    done: dict[int, dict] = {}
    if out.is_file():
        for line in out.read_text(encoding="utf-8").splitlines():
            if line.strip():
                d = json.loads(line)
                done[d["index"]] = d
    wanted = set(only_windows) if only_windows is not None else None
    results: list[WindowResult] = []
    processed = 0
    for w, view in rp:
        if wanted is not None and w.index not in wanted:
            continue
        if w.index in done:
            d = done[w.index]
            results.append(WindowResult(window=w, findings=[Finding(**f) for f in d["findings"]],
                                        rejected=d["rejected"], dropped_hints=d["dropped_hints"],
                                        parse_error=d["parse_error"], raw=d.get("raw", ""), usage=d["usage"]))
            continue
        if limit is not None and processed >= limit:
            break
        dg = build_digest(view.current(), w, cfg["digest"]["max_private"], cfg["digest"]["public_top_k"])
        ctx = DetectorContext(window=w, view=view, digest=dg, kb=kb, profile=profile)
        r = detect_window(ctx, llm, known, cfg["replay"]["window_minutes"], mw=mw)
        with out.open("a", encoding="utf-8") as f:
            f.write(json.dumps(r.to_json()) + "\n")
        results.append(r)
        processed += 1
    return results


def merge_into_incidents(findings: Iterable[Finding], window_minutes: int, max_gap_windows: int = 1) -> list[Incident]:
    """Bookkeeping, not detection: join consecutive findings on the same entity into one incident."""
    gap = timedelta(minutes=window_minutes * (max_gap_windows + 1))
    by_entity: dict[str, list[Finding]] = {}
    for f in sorted(findings, key=lambda x: (x.entity, x.window_start)):
        by_entity.setdefault(f.entity, []).append(f)
    out: list[Incident] = []
    for ent, fs in by_entity.items():
        cur: list[Finding] = []
        for f in fs:
            if cur and f.window_start - cur[-1].window_start > gap:
                out.append(_incident(ent, cur, len(out)))
                cur = []
            cur.append(f)
        if cur:
            out.append(_incident(ent, cur, len(out)))
    return sorted(out, key=lambda i: i.start)


def _incident(entity: str, fs: list[Finding], n: int) -> Incident:
    return Incident(id=f"INC-{n + 1:03d}", entity=entity, start=fs[0].window_start, end=fs[-1].window_end,
                    findings=fs)

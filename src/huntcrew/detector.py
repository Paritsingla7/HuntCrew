"""Detector agent: decides what is suspicious in one replay window.

The agent (CrewAI + Mistral) sees a statistics-only digest, can query flows and search ATT&CK, and
answers with JSON findings. Code then verifies every finding (evidence.py); only verified findings leave
this module. Nothing here uses detection rules or labels.
"""
from __future__ import annotations

import json
import os
import re
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
from .digest import entity_stats  # noqa: E402
from .evidence import verify_finding  # noqa: E402
from .llm import Middleware  # noqa: E402
from .profile import BaselineProfile  # noqa: E402
from .replay import Replay, Window  # noqa: E402
from .schema import Finding, Incident  # noqa: E402
from .syncutil import run_blocking  # noqa: E402

SCREEN_TEMPLATE = """You are screening network sources seen in ONE {minutes}-minute window ({label}).
{peers}
For EACH source below decide whether it is doing something its peers are not doing.
Look at: how many destinations and ports it uses, how concentrated its traffic is on one port or one
destination (top_port_share, top_dst_share), how regular its timing is (per_min_cv), and how much data
moves. Ordinary clients and servers are the majority; mark a source unusual only if its pattern differs
clearly from its peers. Volume alone is not enough. Mark at most 3 sources in this list as unusual:
the ones that deviate most from their peers.

Return ONLY this JSON, one entry per source, same order:
{{"sources": [{{"entity": "<ip>", "unusual": false, "why": "<=15 words"}}]}}

SOURCES
{rows}
"""

VERIFY_TEMPLATE = """These sources were flagged as unusual in ONE {minutes}-minute window ({label}).
Decide which of them really behave like an attack or a compromised host.

{peers}
CANDIDATES
{rows}

Method:
1. For each candidate call source_profile and compare it with its baseline and recent history.
2. Describe what it is doing in plain terms, then call search_attack_kb with that description. Confirm a
   candidate only if a retrieved ATT&CK technique genuinely matches the behaviour. Volume alone is not
   an attack, and a destination never seen in the baseline is common for ordinary browsing.
3. Only quote numbers that appear in the rows above or in tool outputs. Only cite technique IDs returned
   by search_attack_kb.
4. You MUST give a verdict for EVERY candidate listed, including the ones you reject.

Allowed evidence metric names: flows, dst_ips, dst_ports, ext_dst_ips, fwd_bytes, bwd_bytes, syn, rst,
active_minutes, per_minute_mean, per_minute_cv, mean_duration_ms, top_port_share, top_dst_share.

Final answer must be ONLY this JSON (no prose), one entry per candidate:
{{"verdicts": [{{"entity": "<source ip>", "attack": true, "behaviour": "<=25 words",
"evidence": {{"flows": 0}}, "technique_hints": [{{"id": "T0000", "citation": "T0000"}}],
"confidence": 0.0}}]}}
Keep it short: at most 4 evidence metrics per candidate. For a rejected candidate use "attack": false,
a behaviour note of at most 8 words, and "evidence": {{}}.
"""

MAX_CANDIDATES = 8
SCREEN_CHUNK = 12


@dataclass
class WindowResult:
    window: Window
    findings: list[Finding] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    dropped_hints: int = 0
    parse_error: bool = False
    raw: str = ""
    usage: dict[str, float] = field(default_factory=dict)
    screened_unusual: list[str] = field(default_factory=list)
    candidates_truncated: int = 0
    verdicts_missing: int = 0

    def to_json(self) -> dict[str, Any]:
        return {"index": self.window.index, "start": str(self.window.start), "end": str(self.window.end),
                "findings": [f.model_dump(mode="json") for f in self.findings], "rejected": self.rejected,
                "dropped_hints": self.dropped_hints, "parse_error": self.parse_error,
                "raw": self.raw[:2000], "usage": self.usage,
                "screened_unusual": self.screened_unusual, "candidates_truncated": self.candidates_truncated,
                "verdicts_missing": self.verdicts_missing}


def _salvage_objects(text: str) -> list[dict]:
    """Recover complete JSON objects from a truncated answer by balanced-brace scanning (string-aware)."""
    out: list[dict] = []
    start = max(text.find('"verdicts"'), text.find('"findings"'))
    if start < 0:
        return out
    k = text.find("[", start)
    if k < 0:
        return out
    depth, in_str, esc, obj_start = 0, False, False, -1
    for pos in range(k + 1, len(text)):
        ch = text[pos]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                obj_start = pos
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and obj_start >= 0:
                try:
                    obj = json.loads(text[obj_start:pos + 1])
                    if isinstance(obj, dict):
                        out.append(obj)
                except json.JSONDecodeError:
                    pass
                obj_start = -1
            elif depth < 0:
                break
    return out


def parse_findings_json(text: str) -> list[dict] | None:
    """Extract confirmed findings from model output. None means unparseable (nothing salvageable)."""
    if not text:
        return None
    i, j = text.find("{"), text.rfind("}")
    data: Any = None
    if i >= 0 and j > i:
        try:
            data = json.loads(text[i:j + 1])
        except json.JSONDecodeError:
            data = None
    if data is None:                                   # truncated or malformed: keep complete objects
        items = _salvage_objects(text)
        if not items:
            return None
        return [x for x in items if x.get("attack") is True or ("verdicts" not in text and "entity" in x)]
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("verdicts"), list):
        return [x for x in data["verdicts"] if isinstance(x, dict) and x.get("attack") is True]
    legacy = data.get("findings")
    if not isinstance(legacy, list):
        return None
    return [x for x in legacy if isinstance(x, dict)]


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
    out = run_blocking(crew.kickoff)
    return str(getattr(out, "raw", out))


def parse_screen_json(text: str, allowed: set[str]) -> dict[str, str] | None:
    """Return {entity: why} for sources marked unusual; None if unparseable. Unknown entities are ignored."""
    if not text:
        return None
    i, k = text.find("{"), text.rfind("}")
    if i < 0 or k <= i:
        return None
    try:
        data = json.loads(text[i:k + 1])
    except json.JSONDecodeError:
        return None
    items = data.get("sources") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None
    out: dict[str, str] = {}
    for x in items:
        if isinstance(x, dict) and x.get("unusual") is True and str(x.get("entity")) in allowed:
            out[str(x["entity"])] = str(x.get("why", ""))[:120]
    return out


def screen_sources(ctx: DetectorContext, llm: Any, minutes: int) -> tuple[dict[str, str], bool]:
    """Stage 1: the model judges EVERY listed source against its peers (forced coverage, small chunks)."""
    ents = ctx.digest.entities
    peers = ("PEERS(in-network median) " + " ".join(f"{k}={v:g}" for k, v in ctx.digest.peers.items())
             if ctx.digest.peers else "")
    flagged: dict[str, str] = {}
    failed = False
    for i in range(0, len(ents), SCREEN_CHUNK):
        part = ents[i:i + SCREEN_CHUNK]
        prompt = SCREEN_TEMPLATE.format(minutes=minutes, label=ctx.window.label(), peers=peers,
                                        rows="\n".join(e.row() for e in part))
        text = str(llm.call([{"role": "system", "content": "You are a careful network security analyst."},
                             {"role": "user", "content": prompt}]))
        got = parse_screen_json(text, {e.entity for e in part})
        if got is None:
            failed = True
        else:
            flagged.update(got)
    return flagged, failed


def rule_candidates(ctx: DetectorContext, rules: dict, known_dsts: set[str] | None) -> dict[str, str]:
    """Hybrid mode: the B0 rules propose candidate sources; the agent verifies them (ADR-019 fallback)."""
    from .baselines import b0_findings

    out: dict[str, str] = {}
    for f in b0_findings(ctx.view.current(), ctx.window, rules, known_dsts):
        out.setdefault(f.entity, f"rule fired: {f.behaviour}")
    return out


def detect_window(ctx: DetectorContext, llm: Any, known_ids: set[str], minutes: int, max_iter: int = 6,
                  mw: Middleware | None = None, candidates_from: str = "screen",
                  rules: dict | None = None, known_dsts: set[str] | None = None) -> WindowResult:
    before = mw.stats.snapshot() if mw else {}
    ctx.trace_start = len(ctx.kb.trace)
    res = WindowResult(window=ctx.window)
    if ctx.digest.total_flows == 0:
        return res

    if candidates_from == "rules":
        flagged, failed = rule_candidates(ctx, rules or {}, known_dsts), False
    else:
        flagged, failed = screen_sources(ctx, llm, minutes)
    res.screened_unusual = sorted(flagged)
    res.parse_error = failed
    if flagged:
        cand = sorted(flagged)[:MAX_CANDIDATES]
        res.candidates_truncated = len(flagged) - len(cand)
        by_ent = {e.entity: e for e in ctx.digest.entities}
        for c in cand:
            if c not in by_ent:                      # a rule fired on a source the digest did not list
                st = entity_stats(ctx.view.current(), c, ctx.window)
                if st is not None:
                    by_ent[c] = st
        peers = ("PEERS(in-network median) " + " ".join(f"{k}={v:g}" for k, v in ctx.digest.peers.items())
                 if ctx.digest.peers else "")
        rows = "\n".join(f"{by_ent[c].row()}  | screening note: {flagged[c]}" for c in cand if c in by_ent)
        prompt = VERIFY_TEMPLATE.format(minutes=minutes, label=ctx.window.label(), peers=peers, rows=rows)
        raw = _run_agent(llm, build_tools(ctx), prompt, max_iter)
        res.raw = raw
        res.verdicts_missing = max(0, len(cand) - len(re.findall(r'"entity"', raw)))
        items = parse_findings_json(raw)
        if items is None:
            res.parse_error = True
        else:
            for draft in items[:MAX_CANDIDATES]:
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
                 only_windows: Iterable[int] | None = None, limit: int | None = None,
                 candidates_from: str = "screen", known_dsts: set[str] | None = None) -> list[WindowResult]:
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
                                        parse_error=d["parse_error"], raw=d.get("raw", ""), usage=d["usage"],
                                        screened_unusual=d.get("screened_unusual", []),
                                        candidates_truncated=d.get("candidates_truncated", 0),
                                        verdicts_missing=d.get("verdicts_missing", 0)))
            continue
        if limit is not None and processed >= limit:
            break
        dg = build_digest(view.current(), w, cfg["digest"]["max_private"], cfg["digest"]["public_top_k"])
        ctx = DetectorContext(window=w, view=view, digest=dg, kb=kb, profile=profile)
        r = detect_window(ctx, llm, known, cfg["replay"]["window_minutes"], mw=mw,
                          candidates_from=candidates_from, rules=cfg.get("baseline_rules"), known_dsts=known_dsts)
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

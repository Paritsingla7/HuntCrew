"""Downstream agents: Threat-Intel, Strategist, Reporter. Code guardrails check every output.

Guardrails (plain code, ADR-007):
  * a technique must exist in ATT&CK AND have been retrieved in this incident's searches;
  * an action must be in the catalog; its mitigation must be an official mitigation of an assessed technique;
  * anything that fails is dropped and counted, so hallucination rates are measurable.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("OTEL_SDK_DISABLED", "true")

from .attack_kb import AttackKB  # noqa: E402
from .response import Policy  # noqa: E402
from .schema import Incident, ProposedAction, ResponsePlan, TechniqueAssessment, ThreatAssessment  # noqa: E402

SEVERITIES = {"low", "medium", "high", "critical"}


def extract_json(text: str) -> dict | None:
    i, j = text.find("{"), text.rfind("}")
    if i < 0 or j <= i:
        return None
    try:
        data = json.loads(text[i:j + 1])
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def incident_brief(inc: Incident) -> str:
    lines = [f"Incident {inc.id}: source {inc.entity}, {inc.start:%Y-%m-%d %H:%M} to {inc.end:%H:%M}, "
             f"{len(inc.findings)} window(s) flagged."]
    for f in inc.findings[:6]:
        ev = ", ".join(f"{k}={v:g}" for k, v in f.evidence.items())
        lines.append(f"- {f.window_start:%H:%M}: {f.behaviour} [{ev}]")
    return "\n".join(lines)


def incident_profile(flows: Any, inc: Incident) -> str:
    """Neutral aggregate facts for an incident, computed by code from the flows the incident spans.

    No labels, no verdicts: just the quantities an analyst would read to tell different behaviours apart.
    """
    cur = flows[(flows["ts"] >= inc.start) & (flows["ts"] < inc.end) & (flows["src_ip"] == inc.entity)]
    n = len(cur)
    if n == 0:
        return "no flows"
    minutes = max(1.0, (inc.end - inc.start).total_seconds() / 60.0)
    unanswered = float((cur["bwd_pkts"] == 0).mean())
    ports = cur["dst_port"].value_counts()
    top = ", ".join(f"{int(p)}:{c / n:.0%}" for p, c in ports.head(3).items())
    return (f"Aggregate facts for {inc.entity} over the incident: flows={n}, flows_per_minute={n / minutes:.1f}, "
            f"distinct_dst_ips={cur['dst_ip'].nunique()}, distinct_dst_ports={cur['dst_port'].nunique()}, "
            f"top_dst_ports(share)={top}, unanswered_flow_share={unanswered:.2f} (flows with no backward packets), "
            f"mean_fwd_packets_per_flow={cur['fwd_pkts'].mean():.1f}, mean_bwd_packets_per_flow={cur['bwd_pkts'].mean():.1f}, "
            f"mean_fwd_bytes_per_flow={cur['fwd_bytes'].mean():.0f}, mean_bwd_bytes_per_flow={cur['bwd_bytes'].mean():.0f}, "
            f"mean_flow_duration_ms={cur['duration_us'].mean() / 1000:.1f}")


# --- guardrails -------------------------------------------------------------------------------
def guard_assessment(draft: dict, incident_id: str, kb_ids: set[str], retrieved: set[str]) -> ThreatAssessment:
    techs: list[TechniqueAssessment] = []
    dropped: list[str] = []
    for t in draft.get("techniques") or []:
        tid = str((t or {}).get("id", "")).strip()
        if not tid:
            continue
        if tid in kb_ids and tid in retrieved:
            try:
                conf = max(0.0, min(1.0, float(t.get("confidence", 0.5))))
            except (TypeError, ValueError):
                conf = 0.5
            techs.append(TechniqueAssessment(id=tid, confidence=conf, citation=str(t.get("citation", tid))))
        else:
            dropped.append(tid)
    return ThreatAssessment(incident_id=incident_id, techniques=techs,
                            rationale=str(draft.get("rationale", ""))[:600], dropped_ids=dropped)


@dataclass
class PlanGuard:
    plan: ResponsePlan
    dropped_actions: list[str] = field(default_factory=list)       # unknown action types
    ungrounded_mitigations: int = 0                                # mitigation id not official for the technique


def guard_plan(draft: dict, incident_id: str, assessment: ThreatAssessment, kb: AttackKB,
               policy: Policy) -> PlanGuard:
    official: set[str] = set()
    for t in assessment.techniques:
        official |= {m.id for m in kb.mitigations_for(t.id)}
    actions: list[ProposedAction] = []
    dropped: list[str] = []
    ungrounded = 0
    for a in draft.get("actions") or []:
        typ = str((a or {}).get("type", "")).strip()
        if typ not in policy.catalog:
            dropped.append(typ or "<empty>")
            continue
        mit = a.get("mitigation_id")
        mit = str(mit).strip() if mit else None
        if mit and mit not in official:
            ungrounded += 1
            mit = None
        actions.append(ProposedAction(type=typ, target=str(a.get("target", "")).strip(),
                                      justification=str(a.get("justification", ""))[:200], mitigation_id=mit))
    sev = str(draft.get("severity", "medium")).lower()
    try:
        risk = max(0, min(100, int(draft.get("risk_score", 50))))
    except (TypeError, ValueError):
        risk = 50
    plan = ResponsePlan(incident_id=incident_id, severity=sev if sev in SEVERITIES else "medium",
                        risk_score=risk, rationale=str(draft.get("rationale", ""))[:400], actions=actions)
    return PlanGuard(plan, dropped, ungrounded)


# --- agents -----------------------------------------------------------------------------------
INTEL_PROMPT = """Identify which MITRE ATT&CK technique(s) this incident corresponds to.

{brief}
{profile}

Steps:
1. Read the aggregate facts: are flows answered or unanswered, how large is each flow, how concentrated is
   the traffic on one port or destination, how regular is it, how many destinations or ports are touched.
2. Form at least THREE competing hypotheses that span different ATT&CK tactics (for example access or
   credential-related, discovery, command and control, exfiltration, impact). Call search_attack_kb once
   per hypothesis with a plain description of what the facts would look like under it.
3. Compare each hypothesis with the facts and choose the best-matching technique ID(s). Prefer the most
   specific sub-technique only if the evidence supports it; otherwise use the parent technique. At most 2.
Only cite IDs returned by search_attack_kb.

Answer with ONLY this JSON:
{{"techniques": [{{"id": "T0000", "confidence": 0.0, "citation": "<technique name>"}}],
"rationale": "<=40 words tying evidence to the technique"}}
"""

STRATEGY_PROMPT = """Plan the response to this incident.

{brief}
Assessed techniques: {techniques}

Allowed action types (type: risk): {catalog}
Official ATT&CK mitigations you may cite (id: name): {mitigations}

Rules: at most 4 actions; choose only action types listed above; use "mitigation_id" only from the
official list and only when the action implements it (otherwise null); the target of block_ip/rate_limit_ip/
isolate_host must be an IP address that appears in the brief. Never target these protected addresses: {protected}.

Answer with ONLY this JSON:
{{"severity": "low|medium|high|critical", "risk_score": 0, "rationale": "<=40 words",
"actions": [{{"type": "block_ip", "target": "<ip>", "justification": "<=20 words", "mitigation_id": null}}]}}
"""

REPORT_PROMPT = """Write a concise incident report in Markdown for a security manager.

{brief}
Assessed techniques: {techniques}
Severity: {severity} (risk score {risk})
Response log: {log}

Sections: Summary, Evidence, ATT&CK mapping, Actions taken (executed / awaiting approval / denied /
rejected), Recommendations. Do not invent facts beyond what is given.
"""


def _run(llm: Any, role: str, goal: str, backstory: str, tools: list[Any], prompt: str, max_iter: int = 5) -> str:
    from crewai import Agent, Crew, Process, Task

    agent = Agent(role=role, goal=goal, backstory=backstory, tools=tools, llm=llm, max_iter=max_iter,
                  allow_delegation=False, verbose=False)
    task = Task(description=prompt, expected_output="Exactly the format requested.", agent=agent)
    out = Crew(agents=[agent], tasks=[task], process=Process.sequential, verbose=False).kickoff()
    return str(getattr(out, "raw", out))


class DownstreamCrew:
    def __init__(self, kb: AttackKB, policy: Policy, llm: Any):
        self.kb, self.policy, self.llm = kb, policy, llm
        self.kb_ids = set(kb.chunks)

    def _search_tool(self) -> Any:
        from crewai.tools import tool

        kb = self.kb

        @tool("search_attack_kb")
        def search_attack_kb_tool(query: str) -> str:
            """Search the MITRE ATT&CK knowledge base by meaning. Returns technique IDs you may cite."""
            hits = kb.search(query, k=5)
            return "\n".join(f"{h.id} {h.name} [{', '.join(h.tactics)}] score={h.score:.2f}: {h.snippet[:160]}"
                             for h in hits)

        return search_attack_kb_tool

    def assess(self, inc: Incident, profile: str = "") -> tuple[ThreatAssessment, str]:
        start = len(self.kb.trace)
        raw = _run(self.llm, "Threat intelligence analyst",
                   "Map the incident to the correct MITRE ATT&CK technique using retrieved evidence.",
                   "Knows ATT&CK well and never cites an ID without retrieving it.",
                   [self._search_tool()], INTEL_PROMPT.format(brief=incident_brief(inc), profile=profile))
        retrieved = {i for t in self.kb.trace[start:] for i in t["ids"]}
        draft = extract_json(raw) or {}
        return guard_assessment(draft, inc.id, self.kb_ids, retrieved), raw

    def plan(self, inc: Incident, assessment: ThreatAssessment, profile: str = "") -> tuple[PlanGuard, str]:
        mits: dict[str, str] = {}
        for t in assessment.techniques:
            for m in self.kb.mitigations_for(t.id):
                mits[m.id] = m.name
        prompt = STRATEGY_PROMPT.format(
            brief=incident_brief(inc) + ("\n" + profile if profile else ""),
            techniques=", ".join(f"{t.id}" for t in assessment.techniques) or "none identified",
            catalog="; ".join(f"{k}: {v['risk']}" for k, v in self.policy.catalog.items()),
            mitigations="; ".join(f"{k}: {v}" for k, v in mits.items()) or "none available",
            protected=", ".join(sorted(self.policy.protected)) or "none")
        raw = _run(self.llm, "Incident response strategist",
                   "Propose a safe, policy-compliant response grounded in official ATT&CK mitigations.",
                   "Prefers containment that is proportionate, never touches protected assets.", [], prompt)
        return guard_plan(extract_json(raw) or {}, inc.id, assessment, self.kb, self.policy), raw

    def report(self, inc: Incident, assessment: ThreatAssessment, plan: ResponsePlan, log_text: str) -> str:
        return _run(self.llm, "Incident report writer", "Write a clear, factual incident report.",
                    "Writes for busy managers; states only what the data supports.", [],
                    REPORT_PROMPT.format(brief=incident_brief(inc),
                                         techniques=", ".join(t.id for t in assessment.techniques) or "none",
                                         severity=plan.severity, risk=plan.risk_score, log=log_text))

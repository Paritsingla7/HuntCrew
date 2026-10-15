"""End-to-end orchestration for incidents: assess -> plan -> execute -> report."""
from __future__ import annotations

from dataclasses import dataclass, field

from .crew import DownstreamCrew, PlanGuard
from .response import Approver, Policy, SimulatedEnvironment, auto_deny, execute_plan
from .schema import ActionLog, Incident, ResponsePlan, ThreatAssessment


@dataclass
class IncidentOutcome:
    incident: Incident
    assessment: ThreatAssessment
    plan: ResponsePlan
    guard: PlanGuard
    log: ActionLog
    report: str = ""
    raw: dict[str, str] = field(default_factory=dict)


def log_summary(log: ActionLog) -> str:
    if not log.records:
        return "no actions proposed"
    return "; ".join(f"{r.action.type} {r.action.target} -> {r.status}"
                     + (f" ({r.reason})" if r.status in {"rejected", "denied"} else "") for r in log.records)


def process_incident(inc: Incident, crew: DownstreamCrew, policy: Policy, env: SimulatedEnvironment,
                     approver: Approver = auto_deny, write_report: bool = True,
                     profile: str = "") -> IncidentOutcome:
    assessment, raw_a = crew.assess(inc, profile)
    guard, raw_p = crew.plan(inc, assessment, profile)
    log = execute_plan(guard.plan, policy, env, approver)
    report = crew.report(inc, assessment, guard.plan, log_summary(log)) if write_report else ""
    return IncidentOutcome(inc, assessment, guard.plan, guard, log, report, {"assess": raw_a, "plan": raw_p})

"""Shared data contracts for the agent side of the system. Bulk flow data stays in DataFrames
(see data_cic.py); these models carry what agents and graders exchange."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class TechniqueHint(BaseModel):
    id: str                         # ATT&CK ID, e.g. T1110
    citation: str = ""              # KB chunk the model claims to rely on


class Finding(BaseModel):
    """One detector-agent verdict about one entity in one window. Never contains a label."""

    window_start: datetime
    window_end: datetime
    entity: str                     # usually a source IP
    behaviour: str                  # plain-language description
    evidence: dict[str, float] = Field(default_factory=dict)   # metric name -> quoted value (verified by code)
    technique_hints: list[TechniqueHint] = Field(default_factory=list)
    confidence: float = 0.0
    suspicious: bool = True


class Incident(BaseModel):
    id: str
    entity: str
    start: datetime
    end: datetime
    findings: list[Finding]


class GroundTruthSpan(BaseModel):
    """Derived from the dataset labels by the grader only. Agents never see this."""

    label: str
    technique_id: str | None     # via config labels.to_technique
    entity_src: str
    start: datetime
    end: datetime
    flows: int


class EntityStats(BaseModel):
    """Plain statistics for one source address in one window. No judgement, no thresholds."""

    entity: str
    is_private: bool
    flows: int
    dst_ips: int
    dst_ports: int
    top_ports: list[tuple[int, int]]       # (port, flows), at most 3
    ext_dst_ips: int                       # distinct non-private destinations
    mean_duration_ms: float
    fwd_bytes: int
    bwd_bytes: int
    syn: int
    rst: int
    active_minutes: int
    per_minute_mean: float
    per_minute_cv: float                   # 0 = perfectly regular; undefined (0.0) with <2 active minutes
    top_port_share: float = 0.0            # share of this source's flows that hit its most common port
    top_dst_share: float = 0.0             # share of this source's flows that hit its most common destination

    def row(self) -> str:
        ports = ",".join(f"{p}:{n}" for p, n in self.top_ports)
        return (f"src={self.entity} priv={int(self.is_private)} flows={self.flows} dst_ips={self.dst_ips} "
                f"dst_ports={self.dst_ports} top_ports={ports} top_port_share={self.top_port_share:.2f} "
                f"top_dst_share={self.top_dst_share:.2f} ext_dst={self.ext_dst_ips} "
                f"dur_ms={self.mean_duration_ms:.1f} fwd_B={self.fwd_bytes} bwd_B={self.bwd_bytes} "
                f"syn={self.syn} rst={self.rst} act_min={self.active_minutes} "
                f"per_min={self.per_minute_mean:.1f} per_min_cv={self.per_minute_cv:.2f}")


class WindowDigest(BaseModel):
    window_start: datetime
    window_end: datetime
    total_flows: int
    sources: int
    entities: list[EntityStats]
    omitted: int = 0                       # sources not listed individually
    omitted_flows: int = 0
    omitted_max_flows: int = 0
    omitted_max_dst_ports: int = 0
    peers: dict[str, float] = {}           # medians over in-network sources: what 'typical' looks like

    def to_text(self) -> str:
        head = (f"WINDOW {self.window_start:%Y-%m-%d %H:%M}-{self.window_end:%H:%M} "
                f"flows={self.total_flows} sources={self.sources}")
        rows = [e.row() for e in self.entities]
        peers = ""
        if self.peers:
            peers = "PEERS(in-network median) " + " ".join(f"{k}={v:g}" for k, v in self.peers.items())
        tail = (f"UNLISTED sources={self.omitted} flows={self.omitted_flows} "
                f"max_flows_per_source={self.omitted_max_flows} max_dst_ports_per_source={self.omitted_max_dst_ports}")
        return "\n".join(x for x in [head, peers, *rows, tail] if x)


class ProposedAction(BaseModel):
    type: str                               # must be in the action catalog
    target: str                             # ip, domain, host or free text depending on type
    justification: str = ""
    mitigation_id: str | None = None     # official ATT&CK mitigation this action implements


class ResponsePlan(BaseModel):
    incident_id: str
    severity: str = "medium"                # low | medium | high | critical
    risk_score: int = 50                    # 0-100
    rationale: str = ""
    actions: list[ProposedAction] = Field(default_factory=list)


class ActionRecord(BaseModel):
    action: ProposedAction
    status: str                             # executed | denied | rejected
    reason: str = ""
    risk: str = ""


class ActionLog(BaseModel):
    incident_id: str
    records: list[ActionRecord] = Field(default_factory=list)

    def by_status(self, status: str) -> list[ActionRecord]:
        return [r for r in self.records if r.status == status]


class TechniqueAssessment(BaseModel):
    id: str
    confidence: float = 0.5
    citation: str = ""


class ThreatAssessment(BaseModel):
    incident_id: str
    techniques: list[TechniqueAssessment] = Field(default_factory=list)
    rationale: str = ""
    dropped_ids: list[str] = Field(default_factory=list)      # cited but not real / not retrieved

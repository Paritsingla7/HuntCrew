"""Shared data contracts for the agent side of the system. Bulk flow data stays in DataFrames
(see data_cic.py); these models carry what agents and graders exchange."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

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
    technique_id: Optional[str]     # via config labels.to_technique
    entity_src: str
    start: datetime
    end: datetime
    flows: int

from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pandas as pd

from huntcrew import crew as crewmod
from huntcrew.crew import DownstreamCrew
from huntcrew.evaluate import grade_outcomes
from huntcrew.pipeline import process_incident
from huntcrew.replay import Window
from huntcrew.response import Policy, SimulatedEnvironment, auto_approve
from huntcrew.schema import Finding, Incident

POLICY = Path(__file__).resolve().parents[1] / "data" / "policy" / "policy.json"
T0 = datetime(2017, 7, 4, 14, 0)


class FakeKB:
    def __init__(self):
        self.trace = []
        self.chunks = {"T1110": object(), "T1046": object()}

    def search(self, q, k=5, include_subtechniques=True):
        self.trace.append({"query": q, "ids": ["T1110"]})
        return []

    def mitigations_for(self, tid):
        return [SimpleNamespace(id="M1032", name="MFA")] if tid == "T1110" else []


def _incident():
    f = Finding(window_start=T0, window_end=datetime(2017, 7, 4, 14, 5), entity="172.16.0.1", behaviour="x",
                evidence={"flows": 650.0})
    return Incident(id="INC-001", entity="172.16.0.1", start=T0, end=datetime(2017, 7, 4, 14, 5), findings=[f])


def test_full_incident_flow_with_stubbed_llm(monkeypatch):
    answers = [
        '{"techniques": [{"id": "T1110", "confidence": 0.9}, {"id": "T9999"}], "rationale": "r"}',
        '{"severity": "high", "risk_score": 80, "actions": ['
        '{"type": "block_ip", "target": "172.16.0.1", "mitigation_id": "M1032"},'
        '{"type": "isolate_host", "target": "192.168.10.3"}]}',
        "# Incident report\nAll good.",
    ]
    kb, calls = FakeKB(), iter(range(3))

    def fake_run(*a, **k):
        n = next(calls)
        if n == 0:                                   # the intel agent's search_attack_kb call
            kb.trace.append({"query": "q", "ids": ["T1110"]})
        return answers[n]

    monkeypatch.setattr(crewmod, "_run", fake_run)
    policy = Policy.from_file(POLICY)
    crew = DownstreamCrew(kb, policy, llm=None)
    monkeypatch.setattr(crew, "_search_tool", lambda: None)
    env = SimulatedEnvironment()
    out = process_incident(_incident(), crew, policy, env, auto_approve)
    assert [t.id for t in out.assessment.techniques] == ["T1110"] and out.assessment.dropped_ids == ["T9999"]
    statuses = {r.action.type: r.status for r in out.log.records}
    assert statuses == {"block_ip": "executed", "isolate_host": "rejected"}     # protected DNS server refused
    assert env.blocked_ips == {"172.16.0.1"} and not env.isolated_hosts
    assert out.guard.ungrounded_mitigations == 0 and out.report.startswith("# Incident report")


def test_grade_outcomes_counts_accuracy_grounding_and_policy():
    inc = _incident()
    from huntcrew.schema import (
        ActionLog,
        ActionRecord,
        ProposedAction,
        ResponsePlan,
        TechniqueAssessment,
        ThreatAssessment,
    )
    act_ok = ProposedAction(type="block_ip", target="172.16.0.1", mitigation_id="M1032")
    act_bad = ProposedAction(type="isolate_host", target="192.168.10.3")
    out = SimpleNamespace(
        incident=inc,
        assessment=ThreatAssessment(incident_id="INC-001", techniques=[TechniqueAssessment(id="T1110.001")],
                                    dropped_ids=["T9999"]),
        plan=ResponsePlan(incident_id="INC-001"),
        guard=SimpleNamespace(dropped_actions=[]),
        log=ActionLog(incident_id="INC-001", records=[
            ActionRecord(action=act_ok, status="executed"), ActionRecord(action=act_bad, status="rejected")]))
    truth = pd.DataFrame([dict(window_index=0, entity="172.16.0.1", label="FTP-Patator", technique="T1110",
                               n_attack_flows=600)])
    w = [Window(0, pd.Timestamp(T0), pd.Timestamp("2017-07-04 14:05"))]
    g = grade_outcomes([out], truth, w, kb_ids={"T1110", "T1110.001"})
    assert g["technique_accuracy_incident"] == 1.0 and g["incident_precision"] == 1.0
    assert g["grounding_rate"] == 0.5            # T1110.001 exists, T9999 was dropped
    assert g["policy_pass_rate"] == 0.5 and g["mitigation_grounded_share"] == 0.5

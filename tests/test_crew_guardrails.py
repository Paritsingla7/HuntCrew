from types import SimpleNamespace

from huntcrew.crew import extract_json, guard_assessment, guard_plan
from huntcrew.response import Policy
from huntcrew.schema import TechniqueAssessment, ThreatAssessment

CATALOG = {"block_ip": {"risk": "low"}, "isolate_host": {"risk": "high"}, "open_ticket": {"risk": "low"}}


class FakeKB:
    def mitigations_for(self, tid):
        return {"T1110": [SimpleNamespace(id="M1032", name="MFA"), SimpleNamespace(id="M1027", name="Passwords")]}.get(tid, [])


def test_assessment_drops_unknown_and_unretrieved_ids():
    draft = {"techniques": [{"id": "T1110", "confidence": 0.9}, {"id": "T1046"}, {"id": "T9999"}]}
    a = guard_assessment(draft, "INC-1", kb_ids={"T1110", "T1046"}, retrieved={"T1110"})
    assert [t.id for t in a.techniques] == ["T1110"] and set(a.dropped_ids) == {"T1046", "T9999"}


def test_assessment_clamps_confidence_and_tolerates_garbage():
    a = guard_assessment({"techniques": [{"id": "T1110", "confidence": "high"}, None, {"id": ""}]},
                         "I", {"T1110"}, {"T1110"})
    assert a.techniques[0].confidence == 0.5 and len(a.techniques) == 1


def _assessed():
    return ThreatAssessment(incident_id="I", techniques=[TechniqueAssessment(id="T1110")])


def test_plan_guard_filters_actions_and_grounds_mitigations():
    pol = Policy(CATALOG, {"192.168.10.3"})
    draft = {"severity": "HIGH", "risk_score": 140, "actions": [
        {"type": "block_ip", "target": "172.16.0.1", "mitigation_id": "M1032"},
        {"type": "launch_missiles", "target": "x"},
        {"type": "open_ticket", "target": "web", "mitigation_id": "M9999"}]}
    g = guard_plan(draft, "I", _assessed(), FakeKB(), pol)
    assert [a.type for a in g.plan.actions] == ["block_ip", "open_ticket"]
    assert g.plan.actions[0].mitigation_id == "M1032" and g.plan.actions[1].mitigation_id is None
    assert g.dropped_actions == ["launch_missiles"] and g.ungrounded_mitigations == 1
    assert g.plan.severity == "high" and g.plan.risk_score == 100


def test_extract_json_handles_fences_and_prose():
    assert extract_json('Here:\n```json\n{"a": 1}\n```') == {"a": 1}
    assert extract_json("nothing here") is None


def test_incident_profile_reports_neutral_aggregates_only():
    from datetime import datetime

    import pandas as pd

    from huntcrew.crew import incident_profile
    from huntcrew.schema import Incident

    ts = pd.to_datetime(["2017-07-04 09:15", "2017-07-04 09:16", "2017-07-04 09:17", "2017-07-04 09:18"])
    flows = pd.DataFrame({"ts": ts, "src_ip": ["A", "A", "A", "B"], "dst_ip": ["X"] * 4, "dst_port": [21, 21, 80, 21],
                          "fwd_pkts": [3, 3, 1, 9], "bwd_pkts": [2, 0, 0, 9], "fwd_bytes": [60, 60, 40, 9],
                          "bwd_bytes": [90, 0, 0, 9], "duration_us": [1000, 2000, 3000, 4000]})
    inc = Incident(id="I", entity="A", start=datetime(2017, 7, 4, 9, 15), end=datetime(2017, 7, 4, 9, 20), findings=[])
    text = incident_profile(flows, inc)
    assert "flows=3" in text and "unanswered_flow_share=0.67" in text and "top_dst_ports(share)=21:67%" in text
    assert "attack" not in text.lower() and "malicious" not in text.lower()
    assert incident_profile(flows, Incident(id="J", entity="Z", start=inc.start, end=inc.end, findings=[])) == "no flows"


def test_candidates_rank_by_best_score_and_keep_agent_choice_first():
    from huntcrew.crew import DownstreamCrew

    kb = SimpleNamespace(trace=[{"ids": ["A", "B"], "scores": [0.3, 0.6]}, {"ids": ["B", "C"], "scores": [0.5, 0.7]}],
                         chunks={})
    c = DownstreamCrew(kb, Policy({}, set()), llm=None)
    # per-query leaders first (A,B from query 1; B,C from query 2), then agent picks, then the rest by score
    assert c._candidates(0, ["A"], k=3, per_query=1) == ["A", "B", "C"]
    assert c._candidates(1, [], k=5, per_query=2) == ["B", "C"]


def test_extract_list_accepts_wrapped_and_bare_arrays():
    from huntcrew.crew import extract_list

    assert extract_list('{"scores": [{"id": "A", "score": 7}]}', "scores") == [{"id": "A", "score": 7}]
    assert extract_list('```json\n[{"id": "A", "score": 7}, {"id": "B", "score": 2}]\n```', "scores")[1]["id"] == "B"
    assert extract_list("no json", "scores") is None

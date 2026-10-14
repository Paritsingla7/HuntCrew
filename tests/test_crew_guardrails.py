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

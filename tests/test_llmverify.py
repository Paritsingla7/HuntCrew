import pytest

from llmverify import ActionGate, SearchTrace, check_numeric_claims, ground_ids, numbers_close

CHECKABLE = {"flows", "ports"}


def test_numbers_close_uses_the_larger_of_absolute_and_relative_tolerance():
    assert numbers_close(100, 104) and not numbers_close(100, 106)          # 5% of 100 = 5
    assert numbers_close(0.03, 0.0) and not numbers_close(0.2, 0.0)         # absolute floor 0.05 near zero


def test_claims_split_into_verified_contradicted_and_unverifiable():
    c = check_numeric_claims({"flows": 650, "ports": 9, "colour": 3, "x": "n/a"}, {"flows": 652, "ports": 3, "colour": 3}, CHECKABLE)
    assert c.verified == {"flows": 650.0}
    assert c.contradicted == ["ports: claimed 9, actual 3"]
    assert c.unverifiable == 2                       # "colour" is not checkable, "x" is not a number
    assert not c.ok


def test_a_claim_with_nothing_checkable_is_not_ok_even_without_contradictions():
    c = check_numeric_claims({"colour": 3}, {"colour": 3}, CHECKABLE)
    assert not c.contradicted and not c.verified and not c.ok
    assert check_numeric_claims({"flows": 10}, {"flows": 10}, CHECKABLE).ok


def test_claims_tolerate_missing_or_empty_input():
    assert check_numeric_claims(None, {}, CHECKABLE).unverifiable == 0              # type: ignore[arg-type]
    assert check_numeric_claims({"flows": 5}, {}, CHECKABLE).unverifiable == 1      # we cannot compute it


def test_ground_ids_keeps_only_known_and_retrieved_in_order_and_ignores_blanks():
    kept, dropped = ground_ids(["T1", " T2 ", "T3", "", None, "T9", "T1"], known={"T1", "T2", "T3"}, retrieved={"T1", "T2"})
    assert kept == ["T1", "T2", "T1"] and dropped == ["T3", "T9"]


def test_search_trace_reports_only_what_was_retrieved_after_a_mark():
    t = SearchTrace()
    t.record("brute force", ["T1110", "T1078"], [0.9, 0.5])
    start = t.mark()
    t.record("scan", ["T1046"])
    assert t.retrieved_ids() == {"T1110", "T1078", "T1046"} and t.retrieved_ids(start) == {"T1046"}


CATALOG = {"block": {"risk": "low"}, "wipe": {"risk": "high"}, "note": {"risk": "low"}}


def _gate(**kw):
    return ActionGate(CATALOG, protected={"10.0.0.1"}, validators={"block": lambda t: None if t.startswith("10.") else f"bad target {t}"}, **kw)


def test_gate_rejects_unknown_actions_and_bad_targets_before_anything_else():
    g = _gate()
    assert g.check("nuke", "x").status == "rejected" and "unknown action" in g.check("nuke", "x").reason
    d = g.check("block", "evil")
    assert d.status == "rejected" and d.reason == "bad target evil" and d.risk == "low"


def test_gate_protects_targets_and_tiers_by_risk():
    g = _gate()
    assert g.check("block", "10.0.0.1").reason == "10.0.0.1 is a protected asset"
    assert g.check("block", "10.0.0.2").status == "auto"
    assert g.check("wipe", "anything").status == "needs_approval"


def test_gate_protected_actions_can_be_limited_to_some_action_types():
    g = _gate(protected_actions={"block"})
    assert g.check("note", "10.0.0.1").status == "auto"            # the protected list does not apply to this action
    assert g.check("block", "10.0.0.1").status == "rejected"


def test_gate_auto_risks_are_configurable():
    g = ActionGate(CATALOG, auto_risks=("low", "high"))
    assert g.check("wipe", "x").status == "auto"


@pytest.mark.parametrize("action", ["block", "wipe", "note"])
def test_gate_decision_always_carries_the_risk_tier_once_the_action_is_known(action):
    assert _gate().check(action, "10.0.0.2").risk == CATALOG[action]["risk"]

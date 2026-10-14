import pandas as pd

from huntcrew.baselines import b0_findings
from huntcrew.evaluate import attack_truth, parent, score_findings
from huntcrew.replay import Window
from huntcrew.schema import Finding, TechniqueHint

RULES = {"password_guessing": {"min_flows": 5, "ports": [21, 22]},
         "port_scan": {"min_distinct_ports": 6},
         "beaconing": {"min_flows": 6, "min_active_minutes": 3, "max_cv": 0.3}}
W0 = Window(0, pd.Timestamp("2017-07-04 14:00"), pd.Timestamp("2017-07-04 14:05"))
W1 = Window(1, pd.Timestamp("2017-07-04 14:05"), pd.Timestamp("2017-07-04 14:10"))


def _flows(rows):
    return pd.DataFrame([dict(ts=pd.Timestamp(t), src_ip=s, dst_ip=d, dst_port=p) for t, s, d, p in rows])


def test_password_guessing_rule_fires_at_threshold_and_not_below():
    hit = _flows([("2017-07-04 14:01", "172.16.0.1", "192.168.10.50", 22)] * 5)
    miss = _flows([("2017-07-04 14:01", "172.16.0.1", "192.168.10.50", 22)] * 4)
    f = b0_findings(hit, W0, RULES)
    assert len(f) == 1 and f[0].technique_hints[0].id == "T1110" and f[0].entity == "172.16.0.1"
    assert b0_findings(miss, W0, RULES) == []


def test_port_scan_rule_counts_distinct_ports():
    rows = [("2017-07-04 14:01", "172.16.0.1", "192.168.10.50", p) for p in range(100, 106)]
    f = b0_findings(_flows(rows), W0, RULES)
    assert [x.technique_hints[0].id for x in f] == ["T1046"]


def test_beaconing_needs_external_dst_and_regularity():
    regular = [(f"2017-07-04 14:0{m}", "192.168.10.15", "205.174.165.73", 8080) for m in range(5) for _ in range(2)]
    to_internal = [(t, s, "192.168.10.3", p) for t, s, _, p in regular]
    bursty = [("2017-07-04 14:00", "192.168.10.15", "205.174.165.73", 8080)] * 8 + \
             [("2017-07-04 14:01", "192.168.10.15", "205.174.165.73", 8080),
              ("2017-07-04 14:02", "192.168.10.15", "205.174.165.73", 8080),
              ("2017-07-04 14:03", "192.168.10.15", "205.174.165.73", 8080)]
    assert [x.technique_hints[0].id for x in b0_findings(_flows(regular), W0, RULES)] == ["T1071"]
    assert b0_findings(_flows(to_internal), W0, RULES) == []
    assert b0_findings(_flows(bursty), W0, RULES) == []


def test_truth_requires_min_attack_flows_per_window_entity():
    flows = _flows([("2017-07-04 14:01", "172.16.0.1", "x", 22)] * 5 + [("2017-07-04 14:06", "172.16.0.1", "x", 22)] * 2
                   + [("2017-07-04 14:02", "192.168.10.9", "y", 80)] * 9)
    labels = pd.Series(["SSH-Patator"] * 5 + ["SSH-Patator"] * 2 + ["BENIGN"] * 9)
    t = attack_truth(flows, labels, [W0, W1], {"SSH-Patator": "T1110"}, min_attack_flows=5)
    assert t[["window_index", "entity", "technique"]].values.tolist() == [[0, "172.16.0.1", "T1110"]]


def _finding(w, ent, tech):
    return Finding(window_start=w.start, window_end=w.end, entity=ent, behaviour="x",
                   technique_hints=[TechniqueHint(id=tech)] if tech else [])


def test_scoring_tp_fp_fn_and_parent_level_technique_match():
    import pandas as pd
    truth = pd.DataFrame([dict(window_index=0, entity="A", label="SSH-Patator", technique="T1110", n_attack_flows=9),
                          dict(window_index=1, entity="A", label="SSH-Patator", technique="T1110", n_attack_flows=9)])
    findings = [_finding(W0, "A", "T1110.001"),      # TP, sub-technique of truth parent -> correct
                _finding(W0, "B", "T1046")]          # FP; (1, A) is FN
    s = score_findings(findings, truth, [W0, W1])
    assert (s["tp"], s["fp"], s["fn"]) == (1, 1, 1)
    assert s["precision"] == 0.5 and s["recall"] == 0.5
    assert s["technique_accuracy_on_tp"] == 1.0 and s["window_recall"] == 0.5
    assert parent("T1110.001") == "T1110"


def test_wrong_technique_is_counted_wrong_even_when_detected():
    truth = pd.DataFrame([dict(window_index=0, entity="A", label="Bot", technique="T1071", n_attack_flows=9)])
    s = score_findings([_finding(W0, "A", "T1021")], truth, [W0])
    assert s["tp"] == 1 and s["technique_accuracy_on_tp"] == 0.0


def test_non_suspicious_findings_are_ignored():
    f = _finding(W0, "A", "T1110")
    f.suspicious = False
    truth = pd.DataFrame([dict(window_index=0, entity="A", label="x", technique="T1110", n_attack_flows=9)])
    s = score_findings([f], truth, [W0])
    assert s["tp"] == 0 and s["fn"] == 1

import json
from pathlib import Path

from huntcrew.response import Policy, SimulatedEnvironment, auto_approve, auto_deny, execute_plan
from huntcrew.schema import ProposedAction, ResponsePlan

POLICY = Path(__file__).resolve().parents[1] / "data" / "policy" / "policy.json"


def _policy():
    return Policy.from_file(POLICY)


def _plan(*actions):
    return ResponsePlan(incident_id="INC-1", actions=[ProposedAction(type=t, target=x, justification="j")
                                                       for t, x in actions])


def test_low_risk_runs_automatically_and_changes_environment():
    env = SimulatedEnvironment()
    log = execute_plan(_plan(("block_ip", "172.16.0.1"), ("open_ticket", "web server")), _policy(), env, auto_deny)
    assert [r.status for r in log.records] == ["executed", "executed"]
    assert env.blocked_ips == {"172.16.0.1"} and len(env.tickets) == 1


def test_medium_and_high_risk_need_approval_and_denial_changes_nothing():
    env = SimulatedEnvironment()
    plan = _plan(("force_password_reset", "alice"), ("isolate_host", "192.168.10.15"))
    log = execute_plan(plan, _policy(), env, auto_deny)
    assert [r.status for r in log.records] == ["denied", "denied"]
    assert not env.password_resets and not env.isolated_hosts


def test_approval_lets_risky_actions_through():
    env = SimulatedEnvironment()
    log = execute_plan(_plan(("isolate_host", "192.168.10.15")), _policy(), env, auto_approve)
    assert log.by_status("executed") and env.isolated_hosts == {"192.168.10.15"}


def test_protected_assets_can_never_be_acted_on_even_with_approval():
    env = SimulatedEnvironment()
    pol = _policy()
    log = execute_plan(_plan(("isolate_host", "192.168.10.3"), ("block_ip", "192.168.10.1")), pol, env, auto_approve)
    assert [r.status for r in log.records] == ["rejected", "rejected"]
    assert "protected" in log.records[0].reason and not env.isolated_hosts and not env.blocked_ips


def test_unknown_actions_and_malformed_targets_are_rejected():
    env = SimulatedEnvironment()
    plan = _plan(("launch_missiles", "x"), ("block_ip", "not-an-ip"), ("block_domain", "evil_domain"))
    log = execute_plan(plan, _policy(), env, auto_approve)
    assert [r.status for r in log.records] == ["rejected"] * 3
    assert env.snapshot()["blocked_ips"] == []


def test_domain_block_accepts_valid_domain():
    env = SimulatedEnvironment()
    log = execute_plan(_plan(("block_domain", "Bad.Example.com")), _policy(), env, auto_deny)
    assert log.by_status("executed") and env.blocked_domains == {"bad.example.com"}


def test_snapshot_is_json_serialisable():
    env = SimulatedEnvironment()
    execute_plan(_plan(("block_ip", "1.2.3.4")), _policy(), env, auto_deny)
    assert json.loads(json.dumps(env.snapshot()))["blocked_ips"] == ["1.2.3.4"]

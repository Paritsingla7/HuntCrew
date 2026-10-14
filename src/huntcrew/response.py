"""Response layer: policy, simulated environment, approval gate and executor. Plain code, no LLM.

Everything a plan proposes is checked here before it touches (the simulated) environment:
  * the action must be in the catalog;
  * targets on the protected-asset list can never be blocked or isolated;
  * `low` risk actions run automatically, `medium`/`high` need an explicit human approval.
"""
from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .schema import ActionLog, ActionRecord, ProposedAction, ResponsePlan

IP_ACTIONS = {"block_ip", "rate_limit_ip", "isolate_host"}
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", re.I)


@dataclass(frozen=True)
class Decision:
    status: str          # auto | needs_approval | rejected
    reason: str
    risk: str = ""


class Policy:
    def __init__(self, catalog: dict[str, dict[str, str]], protected_ips: set[str]):
        self.catalog = catalog
        self.protected = protected_ips

    @classmethod
    def from_file(cls, path: str | Path) -> Policy:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(data["action_catalog"], {a["ip"] for a in data.get("protected_assets", [])})

    def check(self, a: ProposedAction) -> Decision:
        spec = self.catalog.get(a.type)
        if spec is None:
            return Decision("rejected", f"unknown action '{a.type}'")
        risk = spec["risk"]
        if a.type in IP_ACTIONS:
            try:
                ipaddress.ip_address(a.target)
            except ValueError:
                return Decision("rejected", f"target '{a.target}' is not an IP address", risk)
            if a.target in self.protected:
                return Decision("rejected", f"{a.target} is a protected asset", risk)
        if a.type == "block_domain" and not _DOMAIN.match(a.target):
            return Decision("rejected", f"target '{a.target}' is not a domain name", risk)
        if risk == "low":
            return Decision("auto", "low risk", risk)
        return Decision("needs_approval", f"{risk} risk action requires approval", risk)


@dataclass
class SimulatedEnvironment:
    """A pretend firewall/IAM/ticketing system. Nothing here reaches a real network."""

    blocked_ips: set[str] = field(default_factory=set)
    rate_limited: set[str] = field(default_factory=set)
    blocked_domains: set[str] = field(default_factory=set)
    isolated_hosts: set[str] = field(default_factory=set)
    disabled_accounts: set[str] = field(default_factory=set)
    password_resets: set[str] = field(default_factory=set)
    waf_rules: list[str] = field(default_factory=list)
    tickets: list[str] = field(default_factory=list)

    def apply(self, a: ProposedAction) -> None:
        t = a.type
        if t == "block_ip":
            self.blocked_ips.add(a.target)
        elif t == "rate_limit_ip":
            self.rate_limited.add(a.target)
        elif t == "block_domain":
            self.blocked_domains.add(a.target.lower())
        elif t == "isolate_host":
            self.isolated_hosts.add(a.target)
        elif t == "disable_account":
            self.disabled_accounts.add(a.target)
        elif t == "force_password_reset":
            self.password_resets.add(a.target)
        elif t == "enable_waf_rule":
            self.waf_rules.append(a.target)
        elif t == "open_ticket":
            self.tickets.append(f"{a.target}: {a.justification}"[:200])
        else:                                               # policy should have stopped this
            raise ValueError(f"unsupported action {t}")

    def snapshot(self) -> dict[str, Any]:
        return {k: (sorted(v) if isinstance(v, set) else list(v)) for k, v in self.__dict__.items()}


Approver = Callable[[ProposedAction, str], bool]


def auto_deny(action: ProposedAction, reason: str) -> bool:        # safe default for unattended runs
    return False


def auto_approve(action: ProposedAction, reason: str) -> bool:     # for tests and scripted demos only
    return True


def console_approver(action: ProposedAction, reason: str) -> bool:
    """Interactive gate for the notebook: asks the human."""
    print(f"\nAPPROVAL NEEDED: {action.type} -> {action.target}\n  why: {action.justification}\n  {reason}")
    return input("approve? [y/N] ").strip().lower() in {"y", "yes"}


def execute_plan(plan: ResponsePlan, policy: Policy, env: SimulatedEnvironment,
                 approver: Approver = auto_deny) -> ActionLog:
    log = ActionLog(incident_id=plan.incident_id)
    for a in plan.actions:
        d = policy.check(a)
        if d.status == "rejected":
            log.records.append(ActionRecord(action=a, status="rejected", reason=d.reason, risk=d.risk))
        elif d.status == "auto" or approver(a, d.reason):
            env.apply(a)
            log.records.append(ActionRecord(action=a, status="executed", reason=d.reason, risk=d.risk))
        else:
            log.records.append(ActionRecord(action=a, status="denied", reason="approval denied", risk=d.risk))
    return log

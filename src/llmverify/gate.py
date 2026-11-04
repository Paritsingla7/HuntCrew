"""A policy gate for actions an LLM proposes: catalog, target validation, protected targets, risk tiers."""
from __future__ import annotations

from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Decision:
    status: str          # "auto" | "needs_approval" | "rejected"
    reason: str
    risk: str = ""


Validator = Callable[[str], str | None]       # returns an error message, or None if the target is fine


class ActionGate:
    """Decide what may happen to a proposed (action type, target).

    catalog: action type -> {"risk": "low" | ...}; only listed types are allowed.
    protected: targets that must never be acted on; applied to `protected_actions` (default: every action).
    validators: per action type, a function that returns an error message for a malformed target.
    Risk "low" runs automatically; every other tier needs a human decision.
    """

    def __init__(self, catalog: Mapping[str, Mapping[str, str]], protected: Collection[str] = (),
                 validators: Mapping[str, Validator] | None = None, protected_actions: Collection[str] | None = None,
                 auto_risks: Collection[str] = ("low",)):
        self.catalog = catalog
        self.protected = set(protected)
        self.validators = dict(validators or {})
        self.protected_actions = set(protected_actions) if protected_actions is not None else None
        self.auto_risks = set(auto_risks)

    def check(self, action_type: str, target: str) -> Decision:
        spec = self.catalog.get(action_type)
        if spec is None:
            return Decision("rejected", f"unknown action '{action_type}'")
        risk = spec["risk"]
        validator = self.validators.get(action_type)
        if validator is not None:
            error = validator(target)
            if error:
                return Decision("rejected", error, risk)
        if (self.protected_actions is None or action_type in self.protected_actions) and target in self.protected:
            return Decision("rejected", f"{target} is a protected asset", risk)
        if risk in self.auto_risks:
            return Decision("auto", f"{risk} risk", risk)
        return Decision("needs_approval", f"{risk} risk action requires approval", risk)

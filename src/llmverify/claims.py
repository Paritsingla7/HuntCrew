"""Check numbers an LLM quoted against numbers your own code computed."""
from __future__ import annotations

from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from typing import Any


def numbers_close(claimed: float, actual: float, rel: float = 0.05, abs_: float = 0.05) -> bool:
    """True if `claimed` is within max(abs_, rel * |actual|) of `actual`."""
    return abs(claimed - actual) <= max(abs_, rel * abs(actual))


@dataclass
class ClaimCheck:
    verified: dict[str, float] = field(default_factory=dict)       # metric -> the value the model quoted (it checked out)
    contradicted: list[str] = field(default_factory=list)          # one readable line per wrong number
    unverifiable: int = 0                                          # not a number, or a metric we cannot compute

    @property
    def ok(self) -> bool:
        """No contradiction AND at least one number was actually checked (a claim with nothing checkable proves nothing)."""
        return not self.contradicted and bool(self.verified)


def check_numeric_claims(claims: Mapping[str, Any], facts: Mapping[str, float], checkable: Collection[str],
                         rel: float = 0.05, abs_: float = 0.05) -> ClaimCheck:
    """Compare quoted metrics with computed ones.

    claims: what the model said, e.g. {"flows": 650, "dst_ports": "3"}; facts: what code computed;
    checkable: metric names that may be checked. Anything else counts as unverifiable and never as verified.
    """
    out = ClaimCheck()
    for name, raw in (claims or {}).items():
        try:
            claimed = float(raw)
        except (TypeError, ValueError):
            out.unverifiable += 1
            continue
        if name not in checkable or name not in facts:
            out.unverifiable += 1
            continue
        actual = float(facts[name])
        if numbers_close(claimed, actual, rel, abs_):
            out.verified[name] = claimed
        else:
            out.contradicted.append(f"{name}: claimed {claimed:g}, actual {actual:g}")
    return out

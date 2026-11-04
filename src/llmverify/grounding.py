"""Keep only identifiers a model cited that really exist AND that it really retrieved."""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field


def ground_ids(cited: Iterable[object], known: set[str], retrieved: set[str]) -> tuple[list[str], list[str]]:
    """Split cited IDs into (kept, dropped). An ID is kept only if it is in `known` and in `retrieved`.

    Blank or non-string-able entries are ignored (not counted as dropped); order is preserved.
    """
    kept: list[str] = []
    dropped: list[str] = []
    for c in cited:
        tid = str(c).strip() if c is not None else ""
        if not tid:
            continue
        (kept if tid in known and tid in retrieved else dropped).append(tid)
    return kept, dropped


@dataclass
class SearchTrace:
    """Record of every retrieval call, so 'was this ID really retrieved?' has a factual answer."""

    entries: list[dict] = field(default_factory=list)

    def record(self, query: str, ids: list[str], scores: list[float] | None = None) -> None:
        self.entries.append({"query": query, "ids": list(ids), "scores": list(scores or [])})

    def retrieved_ids(self, start: int = 0) -> set[str]:
        return {i for e in self.entries[start:] for i in e["ids"]}

    def mark(self) -> int:
        """Position to pass as `start` later, to look only at searches made after this point."""
        return len(self.entries)

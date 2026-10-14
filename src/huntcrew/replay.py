"""Replay simulator: reveals traffic one time window at a time.

Everything an agent tool may read goes through `FlowView`, which is bound to a single window. It can
look back a bounded number of windows and can never look forward. It also holds no label column, so
there is nothing to leak.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

import pandas as pd


class FutureAccessError(RuntimeError):
    """A tool tried to read traffic after the end of the current window."""


class HistoryLimitError(RuntimeError):
    """A tool tried to look back further than the configured history."""


@dataclass(frozen=True)
class Window:
    index: int
    start: pd.Timestamp
    end: pd.Timestamp

    def label(self) -> str:
        return f"{self.start:%Y-%m-%d %H:%M}-{self.end:%H:%M}"


class FlowView:
    """Read-only view of flows up to the end of `window`. No labels, no future."""

    def __init__(self, flows: pd.DataFrame, window: Window, step: pd.Timedelta, history_windows: int):
        self._flows = flows
        self.window = window
        self._step = step
        self._history = history_windows

    @property
    def earliest(self) -> pd.Timestamp:
        return self.window.start - self._history * self._step

    def _between(self, start: pd.Timestamp, end: pd.Timestamp) -> pd.DataFrame:
        ts = self._flows["ts"]
        lo = ts.searchsorted(start, side="left")
        hi = ts.searchsorted(end, side="left")
        return self._flows.iloc[lo:hi]

    def current(self) -> pd.DataFrame:
        return self._between(self.window.start, self.window.end)

    def history(self) -> pd.DataFrame:
        """Flows from the allowed look-back up to (not including) the current window."""
        return self._between(self.earliest, self.window.start)

    def between(self, start: pd.Timestamp, end: pd.Timestamp) -> pd.DataFrame:
        start, end = pd.Timestamp(start), pd.Timestamp(end)
        if end > self.window.end:
            raise FutureAccessError(f"requested up to {end}, but replay clock is at {self.window.end}")
        if start < self.earliest:
            raise HistoryLimitError(f"requested from {start}, earliest allowed is {self.earliest}")
        return self._between(start, end)


class Replay:
    def __init__(self, flows: pd.DataFrame, start: str | pd.Timestamp, end: str | pd.Timestamp,
                 window_minutes: int = 5, history_windows: int = 12):
        leaked = [c for c in flows.columns if "label" in c.lower()]
        if leaked:
            raise ValueError(f"flows must not carry label columns: {leaked}")
        if not flows["ts"].is_monotonic_increasing:
            raise ValueError("flows must be sorted by ts")
        self._flows = flows
        self.start, self.end = pd.Timestamp(start), pd.Timestamp(end)
        self.step = pd.Timedelta(minutes=window_minutes)
        self.history_windows = history_windows

    def windows(self) -> list[Window]:
        out, t, i = [], self.start, 0
        while t < self.end:
            out.append(Window(i, t, min(t + self.step, self.end)))
            t += self.step
            i += 1
        return out

    def view(self, window: Window) -> FlowView:
        return FlowView(self._flows, window, self.step, self.history_windows)

    def __iter__(self) -> Iterator[tuple[Window, FlowView]]:
        for w in self.windows():
            yield w, self.view(w)

"""Streaming windows: the same no-peeking guarantee as `Replay`, for flows that arrive in batches.

`WindowStream` consumes an iterator of flow batches (each sorted by time, and the batches in time order, as a
log tail or a collector would deliver them) and yields `(Window, FlowView)` for each window once it is CLOSED,
that is once a flow at or after the window's end has been seen (or the stream ends). The view is the same
`FlowView` the batch replay uses, over a bounded buffer, so tools and detectors cannot tell the difference:
they can look back `history_windows` windows and never forward, and no label column is accepted.

Late flows (older than a window that was already emitted) cannot be analysed any more. By default they raise;
with `late="drop"` they are discarded and counted in `late_dropped`.
"""
from __future__ import annotations

from collections.abc import Iterable, Iterator

import pandas as pd

from .replay import FlowView, Window


class LateFlowError(ValueError):
    """A flow arrived for a window that was already emitted."""


class WindowStream:
    def __init__(self, batches: Iterable[pd.DataFrame], window_minutes: int = 5, history_windows: int = 12,
                 start: str | pd.Timestamp | None = None, late: str = "raise"):
        if late not in {"raise", "drop"}:
            raise ValueError("late must be 'raise' or 'drop'")
        self._batches = batches
        self.step = pd.Timedelta(minutes=window_minutes)
        self.history_windows = history_windows
        self.start = pd.Timestamp(start) if start is not None else None
        self.late = late
        self.late_dropped = 0

    def __iter__(self) -> Iterator[tuple[Window, FlowView]]:
        buf: pd.DataFrame | None = None
        start = self.start
        next_idx = 0
        newest: pd.Timestamp | None = None

        def emit(idx: int) -> tuple[Window, FlowView]:
            nonlocal buf
            assert start is not None and buf is not None
            w = Window(idx, start + idx * self.step, start + (idx + 1) * self.step)
            keep_from = w.start - self.history_windows * self.step
            buf = buf[buf["ts"] >= keep_from].reset_index(drop=True)
            return w, FlowView(buf, w, self.step, self.history_windows)

        for batch in self._batches:
            leaked = [c for c in batch.columns if "label" in c.lower()]
            if leaked:
                raise ValueError(f"flows must not carry label columns: {leaked}")
            if batch.empty:
                continue
            if start is None:
                start = batch["ts"].min().floor(f"{int(self.step.total_seconds() // 60)}min")
            closed_until = start + next_idx * self.step
            late_mask = batch["ts"] < closed_until
            if late_mask.any():
                if self.late == "raise":
                    raise LateFlowError(f"{int(late_mask.sum())} flow(s) older than {closed_until}, already analysed")
                self.late_dropped += int(late_mask.sum())
                batch = batch[~late_mask]
                if batch.empty:
                    continue
            buf = batch if buf is None else pd.concat([buf, batch], ignore_index=True)
            buf = buf.sort_values("ts", kind="stable").reset_index(drop=True)
            newest = buf["ts"].iloc[-1]
            while start + (next_idx + 1) * self.step <= newest:        # a later flow exists, so this window is closed
                yield emit(next_idx)
                next_idx += 1

        if start is not None and newest is not None:                  # stream ended: flush through the last flow
            while start + next_idx * self.step <= newest:
                yield emit(next_idx)
                next_idx += 1

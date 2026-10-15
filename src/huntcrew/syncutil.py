"""Run blocking agent code safely from notebooks.

Jupyter/Colab already run an asyncio event loop in the main thread, and CrewAI refuses synchronous
`kickoff()` inside a running loop. In that case we execute the call in a short-lived worker thread,
which has no running loop.
"""
from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import TypeVar

T = TypeVar("T")


def run_blocking(fn: Callable[[], T]) -> T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return fn()                                   # plain script: no loop, call directly
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(fn).result()

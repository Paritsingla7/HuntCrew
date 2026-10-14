"""LLM plumbing: .env loading, a throttle + response cache around `litellm.completion`, usage stats.

CrewAI routes non-native providers (Mistral) through `litellm.completion`, so wrapping that one function
gives us, without touching CrewAI internals:
  * a request-rate throttle and a tokens-per-minute budget (the free tier is ~20k tokens/min on Small);
  * an on-disk response cache keyed by the full request (re-runs and the demo cost nothing);
  * retries with exponential backoff on rate limits and transient errors;
  * usage counters for the cost metrics.
Caching is at the completion level, so tools still execute on cached runs and retrieval traces stay real.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_RETRY_STATUS = {408, 409, 429, 500, 502, 503, 504}


def load_dotenv(path: str | Path = ".env") -> bool:
    """Minimal .env reader (KEY=VALUE). Never overrides variables already set. Returns True if file found."""
    p = Path(path)
    if not p.is_file():
        return False
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    return True


@dataclass
class LLMStats:
    calls: int = 0                 # requests that reached the provider
    cache_hits: int = 0
    retries: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    waited_s: float = 0.0
    log: list[dict] = field(default_factory=list)

    def snapshot(self) -> dict[str, float]:
        return {"calls": self.calls, "cache_hits": self.cache_hits, "retries": self.retries,
                "prompt_tokens": self.prompt_tokens, "completion_tokens": self.completion_tokens,
                "waited_s": round(self.waited_s, 1)}

    def delta(self, before: dict[str, float]) -> dict[str, float]:
        now = self.snapshot()
        return {k: round(now[k] - before.get(k, 0), 1) for k in now}


def _estimate_tokens(kwargs: dict[str, Any]) -> int:
    text = json.dumps(kwargs.get("messages", []), default=str) + json.dumps(kwargs.get("tools", []), default=str)
    return int(len(text) / 3.2) + int(kwargs.get("max_tokens") or 500)


def _cache_key(kwargs: dict[str, Any]) -> str:
    keep = {k: kwargs.get(k) for k in ("model", "messages", "temperature", "tools", "tool_choice",
                                       "stop", "max_tokens", "response_format", "top_p", "seed")}
    return hashlib.sha256(json.dumps(keep, sort_keys=True, default=str).encode()).hexdigest()


class Middleware:
    def __init__(self, min_interval_s: float = 1.2, tokens_per_minute: int = 16000, max_retries: int = 5,
                 cache_dir: str | Path | None = None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.monotonic):
        self.min_interval_s = min_interval_s
        self.tpm = tokens_per_minute
        self.max_retries = max_retries
        self.cache_dir = Path(cache_dir) if cache_dir else None
        self.stats = LLMStats()
        self._sleep, self._clock = sleep, clock
        self._lock = threading.Lock()
        self._last = -1e9
        self._window: deque[tuple[float, int]] = deque()     # (time, tokens) in the last 60 s

    # --- throttle -----------------------------------------------------------------------------
    def _wait_for_capacity(self, need: int) -> None:
        while True:
            with self._lock:
                now = self._clock()
                while self._window and now - self._window[0][0] >= 60:
                    self._window.popleft()
                used = sum(t for _, t in self._window)
                gap = self.min_interval_s - (now - self._last)
                if gap <= 0 and (used + need <= self.tpm or not self._window):
                    self._last = now
                    self._window.append((now, need))
                    return
                if gap > 0:
                    delay = gap
                else:
                    delay = max(60 - (now - self._window[0][0]), 0.5)
            self.stats.waited_s += delay
            self._sleep(delay)

    def _record_actual(self, estimated: int, actual: int) -> None:
        with self._lock:
            for i in range(len(self._window) - 1, -1, -1):
                t, n = self._window[i]
                if n == estimated:
                    self._window[i] = (t, actual)
                    break

    # --- cache ----------------------------------------------------------------------------------
    def _cache_path(self, key: str) -> Path | None:
        return self.cache_dir / key[:2] / f"{key}.json" if self.cache_dir else None

    def _cache_get(self, key: str) -> dict | None:
        p = self._cache_path(key)
        if p and p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return None
        return None

    def _cache_put(self, key: str, payload: dict) -> None:
        p = self._cache_path(key)
        if p:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload), encoding="utf-8")
            tmp.replace(p)

    # --- wrapper --------------------------------------------------------------------------------
    def wrap(self, completion: Callable[..., Any], make_response: Callable[[dict], Any]) -> Callable[..., Any]:
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            if args or kwargs.get("stream"):
                return completion(*args, **kwargs)           # streaming/positional: pass through untouched
            key = _cache_key(kwargs)
            hit = self._cache_get(key)
            if hit is not None:
                self.stats.cache_hits += 1
                return make_response(hit)
            need = _estimate_tokens(kwargs)
            for attempt in range(self.max_retries + 1):
                self._wait_for_capacity(need)
                try:
                    resp = completion(**kwargs)
                    break
                except Exception as e:                       # noqa: BLE001 - classified below
                    status = getattr(e, "status_code", None)
                    transient = status in _RETRY_STATUS or type(e).__name__ in {
                        "RateLimitError", "Timeout", "APIConnectionError", "ServiceUnavailableError",
                        "InternalServerError"}
                    if not transient or attempt == self.max_retries:
                        raise
                    self.stats.retries += 1
                    backoff = min(2 ** (attempt + 1), 60)
                    self.stats.waited_s += backoff
                    self._sleep(backoff)
            usage = getattr(resp, "usage", None)
            pt = int(getattr(usage, "prompt_tokens", 0) or 0)
            ct = int(getattr(usage, "completion_tokens", 0) or 0)
            self.stats.calls += 1
            self.stats.prompt_tokens += pt
            self.stats.completion_tokens += ct
            if pt + ct:
                self._record_actual(need, pt + ct)
            payload = resp.model_dump() if hasattr(resp, "model_dump") else resp
            self._cache_put(key, payload)
            return resp
        return wrapped


_installed: Middleware | None = None


def install(min_interval_s: float = 1.2, tokens_per_minute: int = 16000, max_retries: int = 5,
            cache_dir: str | Path | None = ".cache/llm") -> Middleware:
    """Patch `litellm.completion` once per process. Returns the active middleware (for stats)."""
    global _installed
    if _installed is not None:
        return _installed
    import litellm

    mw = Middleware(min_interval_s, tokens_per_minute, max_retries, cache_dir)
    litellm.completion = mw.wrap(litellm.completion, lambda d: litellm.ModelResponse(**d))  
    _installed = mw
    return mw


def make_llm(cfg: dict, model: str | None = None):
    """CrewAI LLM for the configured model. Call `install()` first so the middleware is in place."""
    from crewai import LLM

    load_dotenv()
    c = cfg["llm"]
    return LLM(model=model or c["model"], temperature=c.get("temperature", 0.0),
               max_tokens=c.get("max_tokens", 700), max_retries=0)

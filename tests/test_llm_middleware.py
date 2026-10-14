from types import SimpleNamespace

import pytest

from huntcrew.llm import Middleware, load_dotenv


class FakeClock:
    def __init__(self):
        self.t = 1000.0
        self.slept: list[float] = []

    def now(self):
        return self.t

    def sleep(self, s):
        self.slept.append(s)
        self.t += s


def _resp(text="ok", pt=100, ct=20):
    d = {"text": text, "usage": {"prompt_tokens": pt, "completion_tokens": ct}}
    return SimpleNamespace(usage=SimpleNamespace(prompt_tokens=pt, completion_tokens=ct),
                           model_dump=lambda: d, _d=d)


def _mw(clock, **kw):
    return Middleware(sleep=clock.sleep, clock=clock.now, **kw)


def _make_response(d):
    return SimpleNamespace(usage=SimpleNamespace(**d["usage"]), model_dump=lambda: d, cached=True)


def test_cache_hit_skips_provider_and_counts(tmp_path):
    clock, calls = FakeClock(), []
    mw = _mw(clock, cache_dir=tmp_path, min_interval_s=0)
    fn = mw.wrap(lambda **kw: calls.append(kw) or _resp("A"), _make_response)
    kw = {"model": "m", "messages": [{"role": "user", "content": "hi"}], "temperature": 0}
    first = fn(**kw)
    second = fn(**kw)
    assert len(calls) == 1 and mw.stats.calls == 1 and mw.stats.cache_hits == 1
    assert getattr(second, "cached", False) and second.model_dump()["text"] == "A"
    assert first.model_dump()["text"] == "A"


def test_different_requests_are_not_confused(tmp_path):
    clock = FakeClock()
    mw = _mw(clock, cache_dir=tmp_path, min_interval_s=0)
    fn = mw.wrap(lambda **kw: _resp(kw["messages"][0]["content"]), _make_response)
    a = fn(model="m", messages=[{"role": "user", "content": "A"}])
    b = fn(model="m", messages=[{"role": "user", "content": "B"}])
    assert a.model_dump()["text"] == "A" and b.model_dump()["text"] == "B" and mw.stats.calls == 2


def test_min_interval_is_enforced():
    clock = FakeClock()
    mw = _mw(clock, min_interval_s=1.2, tokens_per_minute=10**9)
    fn = mw.wrap(lambda **kw: _resp(), _make_response)
    for i in range(3):
        fn(model="m", messages=[{"role": "user", "content": str(i)}])
    assert clock.t - 1000.0 >= 2.4 - 1e-9


def test_token_budget_delays_calls():
    clock = FakeClock()
    mw = _mw(clock, min_interval_s=0, tokens_per_minute=1000)
    fn = mw.wrap(lambda **kw: _resp(pt=450, ct=50), _make_response)      # actual 500 tokens per call
    big = "x" * 300
    for i in range(3):
        fn(model="m", messages=[{"role": "user", "content": big + str(i)}], max_tokens=50)
    assert clock.t - 1000.0 >= 55, "third call must wait for the 60 s window to free budget"


def test_retries_on_transient_error_then_succeeds():
    clock = FakeClock()
    mw = _mw(clock, min_interval_s=0, max_retries=3)
    state = {"n": 0}

    class RateLimitError(Exception):
        status_code = 429

    def flaky(**kw):
        state["n"] += 1
        if state["n"] < 3:
            raise RateLimitError("slow down")
        return _resp()

    fn = mw.wrap(flaky, _make_response)
    fn(model="m", messages=[{"role": "user", "content": "x"}])
    assert state["n"] == 3 and mw.stats.retries == 2 and clock.slept[-1] >= 4


def test_non_transient_error_is_raised_immediately():
    clock = FakeClock()
    mw = _mw(clock, min_interval_s=0, max_retries=3)

    class BadRequest(Exception):
        status_code = 400

    def bad(**kw):
        raise BadRequest("no")

    fn = mw.wrap(bad, _make_response)
    with pytest.raises(BadRequest):
        fn(model="m", messages=[])
    assert mw.stats.retries == 0


def test_streaming_passes_through_untouched():
    clock = FakeClock()
    mw = _mw(clock)
    fn = mw.wrap(lambda **kw: "stream-object", _make_response)
    assert fn(model="m", stream=True) == "stream-object" and mw.stats.calls == 0


def test_load_dotenv_does_not_override_existing(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text('# c\nHC_TEST_A="from_file"\nHC_TEST_B=2\n')
    monkeypatch.setenv("HC_TEST_A", "already")
    monkeypatch.delenv("HC_TEST_B", raising=False)
    assert load_dotenv(f) is True
    import os
    assert os.environ["HC_TEST_A"] == "already" and os.environ["HC_TEST_B"] == "2"
    monkeypatch.delenv("HC_TEST_B", raising=False)
    assert load_dotenv(tmp_path / "missing") is False


def test_unsupported_caching_hints_are_stripped_before_the_provider(tmp_path):
    clock, seen = FakeClock(), []
    mw = _mw(clock, cache_dir=tmp_path, min_interval_s=0)
    fn = mw.wrap(lambda **kw: seen.append(kw) or _resp(), _make_response)
    fn(model="m", messages=[{"role": "system", "content": "s", "cache_breakpoint": True},
                            {"role": "user", "content": [{"type": "text", "text": "t", "cache_control": {}}]}])
    sent = seen[0]["messages"]
    assert "cache_breakpoint" not in sent[0]
    assert sent[1]["content"][0] == {"type": "text", "text": "t"}

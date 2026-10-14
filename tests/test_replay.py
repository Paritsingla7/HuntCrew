import pandas as pd
import pytest

from huntcrew.replay import FutureAccessError, HistoryLimitError, Replay


def _flows():
    ts = pd.to_datetime(["2017-07-04 09:00", "2017-07-04 09:02", "2017-07-04 09:07",
                         "2017-07-04 09:12", "2017-07-04 09:14"])
    return pd.DataFrame({"ts": ts, "src_ip": ["a", "b", "a", "c", "a"]})


def test_windows_cover_range_without_gaps():
    r = Replay(_flows(), "2017-07-04 09:00", "2017-07-04 09:15", window_minutes=5)
    ws = r.windows()
    assert [w.start.strftime("%H:%M") for w in ws] == ["09:00", "09:05", "09:10"]
    assert ws[-1].end == pd.Timestamp("2017-07-04 09:15")


def test_current_returns_only_window_flows():
    r = Replay(_flows(), "2017-07-04 09:00", "2017-07-04 09:15", window_minutes=5)
    sizes = [len(view.current()) for _, view in r]
    assert sizes == [2, 1, 2]


def test_future_read_is_refused():
    r = Replay(_flows(), "2017-07-04 09:00", "2017-07-04 09:15", window_minutes=5)
    w, view = next(iter(r))
    with pytest.raises(FutureAccessError):
        view.between(w.start, w.end + pd.Timedelta(minutes=1))


def test_history_is_bounded():
    r = Replay(_flows(), "2017-07-04 09:00", "2017-07-04 09:15", window_minutes=5, history_windows=1)
    w = r.windows()[2]                      # 09:10-09:15, may look back to 09:05
    view = r.view(w)
    assert len(view.history()) == 1         # only the 09:07 flow
    with pytest.raises(HistoryLimitError):
        view.between(pd.Timestamp("2017-07-04 09:00"), w.end)


def test_label_columns_are_rejected():
    df = _flows().assign(attack_label="BENIGN")
    with pytest.raises(ValueError, match="label"):
        Replay(df, "2017-07-04 09:00", "2017-07-04 09:15")


def test_unsorted_flows_are_rejected():
    df = _flows().iloc[::-1].reset_index(drop=True)
    with pytest.raises(ValueError, match="sorted"):
        Replay(df, "2017-07-04 09:00", "2017-07-04 09:15")

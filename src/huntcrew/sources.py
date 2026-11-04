"""Flow sources: turn real network logs into the canonical flow table the pipeline reads.

The canonical table has one row per flow with the columns in `REQUIRED` (plus `src_port` and `protocol` when the
log has them), sorted by `ts`, and NO label column (the replay refuses label columns). Adapters:

  * `cic`          - the CIC-IDS2017 parquet used for the evaluation (labels are dropped here, see data_cic.py);
  * `zeek_conn`    - Zeek `conn.log`, tab-separated (`#fields` header) or JSON lines;
  * `suricata_eve` - Suricata `eve.json` lines with `event_type == "flow"`.

New formats register with `@source("name")`; callers use `load_flows(kind, path)`, so nothing else changes.

Mapping caveats (flows carry no payload, and the logs count things differently from CIC's flow exporter):
  * Zeek `history` records SYN/RST once per direction change, so `syn_count` / `rst_count` are lower bounds, not
    packet counts; Suricata flow events only say whether a SYN/RST was seen (0 or 1).
  * Timestamps are the flow START in UTC, converted to naive timestamps in `tz_offset_hours` (default 0).
    CIC-IDS2017 uses local capture time, so thresholds learned on one are not directly comparable to the other.
"""
from __future__ import annotations

import json
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pandas as pd

REQUIRED = ("ts", "src_ip", "dst_ip", "dst_port", "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes",
            "syn_count", "rst_count")
OPTIONAL = ("src_port", "protocol")
_INT_COLS = ("dst_port", "duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "syn_count", "rst_count")

Loader = Callable[..., pd.DataFrame]
SOURCES: dict[str, Loader] = {}


def source(name: str) -> Callable[[Loader], Loader]:
    def deco(fn: Loader) -> Loader:
        SOURCES[name] = fn
        return fn
    return deco


def load_flows(kind: str, path: str | Path, **options: Any) -> pd.DataFrame:
    if kind not in SOURCES:
        raise KeyError(f"unknown flow source '{kind}'; known: {sorted(SOURCES)}")
    return validate_flows(SOURCES[kind](path, **options))


def validate_flows(df: pd.DataFrame) -> pd.DataFrame:
    """Check the canonical contract and return the table sorted by time."""
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f"flow table is missing columns: {missing}")
    leaked = [c for c in df.columns if "label" in c.lower()]
    if leaked:
        raise ValueError(f"flow table must not carry label columns: {leaked}")
    return df.sort_values("ts", kind="stable").reset_index(drop=True)


def _num(series: pd.Series, default: float = 0.0) -> pd.Series:
    """Zeek writes unset values as '-' and Suricata may omit them: treat both as `default`."""
    return pd.to_numeric(series, errors="coerce").fillna(default)


def _canonical(df: pd.DataFrame) -> pd.DataFrame:
    for c in _INT_COLS:
        df[c] = df[c].round().astype("int64")
    cols = [*REQUIRED, *[c for c in OPTIONAL if c in df.columns]]
    return df[cols]


# --- CIC-IDS2017 -----------------------------------------------------------------------------
@source("cic")
def cic(path: str | Path, **_: Any) -> pd.DataFrame:
    from .data_cic import load_cic

    return load_cic(path).flows


# --- Zeek conn.log ---------------------------------------------------------------------------
def _zeek_rows(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if lines and lines[0].lstrip().startswith("{"):                       # JSON-lines log
        return [json.loads(ln) for ln in lines if ln.lstrip().startswith("{")]
    fields: list[str] = []
    rows = []
    for ln in lines:
        if ln.startswith("#fields"):
            fields = ln.split("\t")[1:]
        elif ln.startswith("#"):
            continue
        else:
            rows.append(dict(zip(fields, ln.split("\t"), strict=False)))
    if not fields:
        raise ValueError(f"{path}: no '#fields' header and not JSON lines: not a Zeek log?")
    return rows


@source("zeek_conn")
def zeek_conn(path: str | Path, tz_offset_hours: float = 0.0, **_: Any) -> pd.DataFrame:
    raw = pd.DataFrame(_zeek_rows(Path(path)))
    if raw.empty:
        return _canonical(pd.DataFrame({c: pd.Series(dtype="int64") for c in REQUIRED}).assign(
            ts=pd.Series(dtype="datetime64[ns]"), src_ip=pd.Series(dtype="object"), dst_ip=pd.Series(dtype="object")))
    hist = raw["history"].fillna("").replace("-", "") if "history" in raw else pd.Series("", index=raw.index)
    df = pd.DataFrame({
        "ts": pd.to_datetime(_num(raw["ts"]), unit="s") + pd.Timedelta(hours=tz_offset_hours),
        "src_ip": raw["id.orig_h"], "src_port": _num(raw["id.orig_p"]).astype("int64"),
        "dst_ip": raw["id.resp_h"], "dst_port": _num(raw["id.resp_p"]),
        "protocol": raw["proto"] if "proto" in raw else "",
        "duration_us": _num(raw["duration"] if "duration" in raw else pd.Series(0, index=raw.index)) * 1e6,
        "fwd_pkts": _num(raw["orig_pkts"]) if "orig_pkts" in raw else 0,
        "bwd_pkts": _num(raw["resp_pkts"]) if "resp_pkts" in raw else 0,
        "fwd_bytes": _num(raw["orig_bytes"]) if "orig_bytes" in raw else 0,
        "bwd_bytes": _num(raw["resp_bytes"]) if "resp_bytes" in raw else 0,
        "syn_count": hist.str.count("[Ss]"), "rst_count": hist.str.count("[Rr]"),
    })
    return _canonical(df)


# --- Suricata eve.json -----------------------------------------------------------------------
def _eve_flows(lines: Iterable[str]) -> list[dict[str, Any]]:
    out = []
    for ln in lines:
        ln = ln.strip()
        if not ln.startswith("{"):
            continue
        ev = json.loads(ln)
        if ev.get("event_type") == "flow":
            out.append(ev)
    return out


@source("suricata_eve")
def suricata_eve(path: str | Path, tz_offset_hours: float = 0.0, **_: Any) -> pd.DataFrame:
    events = _eve_flows(Path(path).read_text(encoding="utf-8").splitlines())
    rows = []
    for ev in events:
        fl, tcp = ev.get("flow", {}), ev.get("tcp", {})
        start = pd.Timestamp(fl.get("start") or ev["timestamp"])
        start = start.tz_convert("UTC").tz_localize(None) if start.tzinfo is not None else start
        age = float(fl.get("age", 0) or 0)
        rows.append({
            "ts": start + pd.Timedelta(hours=tz_offset_hours),
            "src_ip": ev["src_ip"], "src_port": ev.get("src_port", 0) or 0,
            "dst_ip": ev["dest_ip"], "dst_port": ev.get("dest_port", 0) or 0, "protocol": ev.get("proto", ""),
            "duration_us": age * 1e6,
            "fwd_pkts": fl.get("pkts_toserver", 0), "bwd_pkts": fl.get("pkts_toclient", 0),
            "fwd_bytes": fl.get("bytes_toserver", 0), "bwd_bytes": fl.get("bytes_toclient", 0),
            "syn_count": int(bool(tcp.get("syn"))), "rst_count": int(bool(tcp.get("rst"))),
        })
    if not rows:
        return _canonical(pd.DataFrame({c: pd.Series(dtype="int64") for c in REQUIRED}).assign(
            ts=pd.Series(dtype="datetime64[ns]"), src_ip=pd.Series(dtype="object"), dst_ip=pd.Series(dtype="object")))
    return _canonical(pd.DataFrame(rows))

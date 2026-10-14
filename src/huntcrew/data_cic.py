"""CIC-IDS2017 loader.

Two things matter here:
  1. Timestamps in this dataset are messy (see `parse_timestamps`).
  2. The answer key (attack label) is returned as a SEPARATE object from the flows, so the
     detector side of the system never has a label column to peek at.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

# parquet column -> canonical name. Only what the digest / tools need.
COLUMN_MAP = {
    "flow_id": "flow_id",
    "source_ip": "src_ip",
    "source_port": "src_port",
    "destination_ip": "dst_ip",
    "destination_port": "dst_port",
    "protocol": "protocol",
    "Timestamp": "ts_raw",
    "Flow Duration": "duration_us",
    "Total Fwd Packets": "fwd_pkts",
    "Total Backward Packets": "bwd_pkts",
    "Total Length of Fwd Packets": "fwd_bytes",
    "Total Length of Bwd Packets": "bwd_bytes",
    "Flow IAT Mean": "iat_mean_us",
    "Flow IAT Std": "iat_std_us",
    "SYN Flag Count": "syn_count",
    "RST Flag Count": "rst_count",
    "ACK Flag Count": "ack_count",
    "Init_Win_bytes_forward": "init_win_fwd",
}
LABEL_COLUMN = "attack_label"

# The capture ran roughly 09:00-17:00. Timestamps use a 12-hour clock with no AM/PM marker,
# so hours 1..7 are the afternoon (13..19). This is documented in docs/data-provenance.md.
_PM_BELOW_HOUR = 8


def parse_timestamps(raw: pd.Series) -> pd.Series:
    """Parse CIC-IDS2017 timestamps.

    Formats are mixed ('03/07/2017 08:55:58' on Monday, '5/7/2017 10:58' on later days), are
    day-first, and use a 12-hour clock without AM/PM. Returns naive local capture time.
    """
    ts = pd.to_datetime(raw, dayfirst=True, format="mixed", errors="raise")
    pm = ts.dt.hour < _PM_BELOW_HOUR
    return ts.where(~pm, ts + pd.Timedelta(hours=12))


@dataclass(frozen=True)
class CicData:
    flows: pd.DataFrame          # canonical columns + `ts`; NO label column; sorted by ts; RangeIndex
    labels: pd.Series            # same index as `flows`; dataset authors' attack_label

    def __len__(self) -> int:
        return len(self.flows)

    def select(self, start: pd.Timestamp, end: pd.Timestamp) -> CicData:
        """Time slice [start, end). Index is reset so downstream code can't rely on global row ids."""
        m = (self.flows["ts"] >= start) & (self.flows["ts"] < end)
        flows = self.flows.loc[m].reset_index(drop=True)
        labels = self.labels.loc[m].reset_index(drop=True)
        return CicData(flows, labels)

    def keep_labels(self, labels: Iterable[str]) -> CicData:
        m = self.labels.isin(set(labels))
        return CicData(self.flows.loc[m].reset_index(drop=True), self.labels.loc[m].reset_index(drop=True))


def load_cic(path: str | Path, columns: dict[str, str] | None = None) -> CicData:
    cmap = columns or COLUMN_MAP
    df = pd.read_parquet(path, columns=[*cmap.keys(), LABEL_COLUMN])
    df = df.rename(columns=cmap)
    df["ts"] = parse_timestamps(df["ts_raw"])
    df = df.drop(columns=["ts_raw"]).sort_values("ts", kind="stable").reset_index(drop=True)
    labels = df[LABEL_COLUMN].astype("category")
    flows = df.drop(columns=[LABEL_COLUMN])
    return CicData(flows=flows, labels=labels)

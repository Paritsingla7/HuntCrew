"""Config loader. Lookup order: explicit path -> $HUNTCREW_CONFIG -> ./config.yaml -> repo root."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

_REPO_ROOT = Path(__file__).resolve().parents[2]


def find_config(path: str | None = None) -> Path:
    candidates = [path, os.environ.get("HUNTCREW_CONFIG"), "config.yaml", _REPO_ROOT / "config.yaml"]
    for c in candidates:
        if c and Path(c).is_file():
            return Path(c)
    raise FileNotFoundError("config.yaml not found (set HUNTCREW_CONFIG or run from the project root)")


def load_config(path: str | None = None) -> dict[str, Any]:
    with open(find_config(path), encoding="utf-8") as f:
        return yaml.safe_load(f)

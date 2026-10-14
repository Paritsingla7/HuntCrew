"""Download the external datasets into data/external/<name>/ (one new directory per source).

Data is never committed to git; this script + the SHA256 files are the reproducible record.
Standard library only, so it can run unmodified on Colab.

    python -I scripts/fetch_data.py            # fetch everything missing
    python -I scripts/fetch_data.py cic-ids2017
"""
from __future__ import annotations

import hashlib
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "data" / "external"

SOURCES = {
    "cic-ids2017": {
        "url": "https://huggingface.co/datasets/rdpahalavan/CIC-IDS2017/resolve/main/Network-Flows/CICIDS_Flow.parquet",
        "filename": "CICIDS_Flow.parquet",
        "expected_bytes": 369_814_810,      # as reported by the server on 2026-10-15
        "note": "CIC-IDS2017 flows via HF mirror rdpahalavan/CIC-IDS2017 (apache-2.0 per metadata). "
                "Cite: Sharafaldin, Habibi Lashkari, Ghorbani, ICISSP 2018.",
    },
    "attack-stix": {
        "url": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
        "filename": "enterprise-attack.json",
        "expected_bytes": None,             # unversioned file moves with each ATT&CK release
        "note": "MITRE ATT&CK Enterprise STIX 2.1 (latest release). Subject to ATT&CK Terms of Use.",
    },
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def fetch(name: str) -> Path:
    src = SOURCES[name]
    out_dir = DEST / name
    target = out_dir / src["filename"]
    if target.exists():
        print(f"[{name}] already present: {target} ({target.stat().st_size:,} bytes)")
        return target
    out_dir.mkdir(parents=True, exist_ok=True)
    part = target.with_suffix(target.suffix + ".part")
    print(f"[{name}] downloading {src['url']}")
    req = urllib.request.Request(src["url"], headers={"User-Agent": "huntcrew-fetch/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp, open(part, "wb") as f:
        while True:
            chunk = resp.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)
    size = part.stat().st_size
    exp = src["expected_bytes"]
    if exp is not None and size != exp:
        part.unlink()
        raise RuntimeError(f"[{name}] size {size:,} != expected {exp:,}; download discarded")
    part.rename(target)
    digest = sha256(target)
    (out_dir / "SHA256SUM").write_text(f"{digest}  {src['filename']}\n{src['note']}\n", encoding="utf-8")
    print(f"[{name}] ok  {size:,} bytes  sha256={digest}")
    return target


if __name__ == "__main__":
    wanted = sys.argv[1:] or list(SOURCES)
    for n in wanted:
        fetch(n)

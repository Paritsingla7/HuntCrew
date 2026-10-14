# Data provenance

Everything the system consumes from outside the repository, how it was obtained, and what was
checked. Data is **not** committed; `scripts/fetch_data.py` reproduces it and records checksums.

## 1. Network traffic — CIC-IDS2017 (labelled flows)

| | |
|---|---|
| Origin | Canadian Institute for Cybersecurity, Univ. of New Brunswick (capture 3–7 July 2017) |
| Obtained from | Hugging Face mirror `rdpahalavan/CIC-IDS2017`, file `Network-Flows/CICIDS_Flow.parquet` |
| Size | 369,814,810 bytes |
| SHA-256 | `e64f6adfbcb7f96b018cf36c731be64ef4de3353ccd7340b190590734a0dda35` |
| License | apache-2.0 per mirror metadata. **Cite:** Sharafaldin, Habibi Lashkari, Ghorbani, *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization*, ICISSP 2018. |
| Rows / columns | 2,827,677 flows × 84 columns |

### Verification against the official release
The mirror's per-class counts match the published CIC-IDS2017 counts (e.g. SSH-Patator 5,897; FTP-Patator
7,935; Bot 1,956; PortScan 158,804; total 2,827,677), so the official zip was not needed.

### Quirks the loader handles (`src/huntcrew/data_cic.py`)
1. **Mixed timestamp formats**: Monday `03/07/2017 08:55:58`, later days `5/7/2017 10:58` (no seconds).
2. **Day-first dates** (`03/07/2017` is 3 July).
3. **12-hour clock without AM/PM**: hours 1–7 are the afternoon. After the fix the capture spans
   08:55–17:02, and attack windows match the published schedule (FTP-Patator Tue 09:17–10:30,
   SSH-Patator Tue 14:09–15:11).
4. File order is not time order → sorted by timestamp.

### Properties that shape the evaluation
- **Labels are not entity-clean.** The attacker address `172.16.0.1` also has 3,599 *benign*-labelled
  flows. Ground truth must therefore be per (entity, time-window), never per IP.
- **Attack spans have scattered tails.** E.g. Bot: dense 10:00–11:30 then ~126 flows/30 min until 13:00;
  PortScan: 138,386 flows in 14:30–15:00, a handful of flows earlier. Spans use clusters, not min/max.
- **Monday is benign-only** (529,450 flows): used as the "normal profile" source.
- **Protected assets are derivable**: 192.168.10.3 (663,674 port-53 flows) and 192.168.10.1 (294,066).
- **Flows carry no payload and no login outcome.** SQL injection (21 flows) is not distinguishable from
  other web attacks at flow level and is out of scope.

## 2. Handbook — MITRE ATT&CK Enterprise (STIX 2.1)

| | |
|---|---|
| Origin | `mitre-attack/attack-stix-data`, `enterprise-attack/enterprise-attack.json` (latest release) |
| Release | ATT&CK v20.0 (as of 2026-10-15) |
| Size | 55,271,014 bytes |
| SHA-256 | `81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352` |
| Terms | MITRE ATT&CK Terms of Use |

### Structure found (drives the RAG chunking)
- 227 live techniques + 479 sub-techniques (`attack-pattern`, excluding revoked/deprecated).
- 44 mitigations (`course-of-action`) linked by 1,477 `mitigates` relationships
  (e.g. T1110 → M1018, M1036, M1032, M1027).
- Detection guidance has moved out of `x_mitre_detection`: it lives in `x-mitre-detection-strategy`
  objects linked by 703 `detects` relationships, each referencing `x-mitre-analytic` objects that
  carry behaviour descriptions.

## 3. Not used (decided against)
- CISA KEV: nearly irrelevant to flow-level attacks. Dropped.
- CERT-SG IRM playbooks: license unverified, reportedly deprecated. Dropped; ATT&CK mitigations
  provide machine-readable response guidance instead.

## Reproduce
```bash
python -I scripts/fetch_data.py        # downloads into data/external/<source>/ and writes SHA256SUM
```

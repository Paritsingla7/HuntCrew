# Progress Log

Newest entry on top.

## 2026-10-15 (evening) — P2 Replay, digest, B0 baseline
- Replay clock with bounded history and a no-future guard; refuses flows that carry label columns.
- Digest: statistics only, no thresholds, no verdict words (tested). Real-data check showed ~300–550 sources
  per window, so the listing is structured rather than truncated (ADR-022). ~1.7k tokens per window.
- Fixed a semantic bug found by a test: Python's `is_private` includes documentation ranges; the digest now
  uses explicit RFC 1918 networks.
- B0 rules baseline + code grader at (window, entity) granularity; B0 refined on dev/benign only, then frozen
  (ADR-023). Dev result: recall 0.93, precision 0.27, parent-level technique accuracy 1.0 on true positives.
- Tests: 29 passing. Test slices have not been touched.
- Next: P3 knowledge base (ATT&CK chunks + embeddings + retrieval test set).

## 2026-10-15 — P1 Foundation
- Re-planned around real data: CIC-IDS2017 flows + official MITRE ATT&CK; agent-led detection through a
  replay simulator; grading by code against dataset labels (ADR-015/016/017).
- Fetched and verified both datasets (sizes and SHA-256 in `data-provenance.md`); mirror counts match the
  published CIC-IDS2017 counts.
- Findings that shaped the design: mixed/12-hour timestamps (ADR-020); labels are not entity-clean (the
  attacker IP also has 3,599 benign flows); attack spans have scattered tails; ATT&CK v20 detection guidance
  lives in detection strategies (ADR-021); protected assets derived from DNS traffic.
- Implemented: config loader, schema, CIC loader with labels split from flows, fetch script, policy file.
- Pre-registered dev/test slices and the decision-gate bar in `config.yaml` before any detector existed (ADR-019).
- Tests: 8 passed (timestamp repair, label separation, slice alignment, real-data counts and schedule, config sanity).
- Decided: project name **HuntCrew**; repository `Paritsingla7/HuntCrew`.

## 2026-10-14 — P0 Planning
- Scored all 15 titles; chose title 1 (ADR-001). First design (synthetic logs, handwritten KB) was later
  superseded after review of its circular evaluation.

## Status board

| Phase | State |
|---|---|
| P1 Foundation | ✅ done |
| P2 Replay + digest + B0 | ✅ done |
| P3 Knowledge base | ⬜ |
| P4 Detector agent | ⬜ |
| P5 Downstream crew + response | ⬜ |
| P6 Evaluation | ⬜ |
| P7 Colab | ⬜ |
| P8 Polish | ⬜ |

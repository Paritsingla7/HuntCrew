# Progress Log

Newest entry on top.

## 2026-10-15 (night) — P3 Knowledge base
- `attack_kb.py`: official ATT&CK v20 STIX → 706 chunks (227 techniques + 479 sub-techniques), each joined with
  its official mitigations and detection analytics; local MiniLM embeddings in ChromaDB; every search is
  traced so guardrails can verify a cited ID was really retrieved.
- Retrieval smoke set (20 hand-written queries): hit@1 0.80, hit@3 0.95, hit@5 0.95.
- Tests: 34 passing (first run downloads the embedding model, ~1 min).
- Next: P4 detector agent (needs the provider API key and limits).

## 2026-10-15 (late night) — P4/P5 build-out, gate pending
- LLM middleware: throttle, token budget, completion-level response cache, retries; strips prompt-caching
  hints that the provider rejects (I-010).
- Measured provider quotas through response headers: `mistral-small*`/`medium`/`magistral-small` have a
  quota of 0 on this key; default model is `ministral-14b-latest` (ADR-024, I-011).
- Detector: first single-pass design anchored on busy hosts and never opened the clearest anomaly.
  Redesigned as two stages (ADR-025): forced-coverage screening of every listed source, then tool-based
  verification with an explicit verdict per candidate. Hybrid fallback is a mode of the same detector (ADR-026).
- First full dev run of the agent-led detector: recall 0.36, precision 0.07 (vs B0 0.93 / 0.27). 8 of 21
  windows had parse errors caused by output truncation; fixed (larger budget, shorter format, salvage parser)
  and re-running before the gate is evaluated.
- Built: response layer (policy, simulated environment, approval gate, executor), downstream agents with code
  guardrails, pipeline, incident-level graders, B1 baseline, one-command evaluation runner, notebook builder.
- Tests: 69 passing; ruff and mypy clean.

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
| P3 Knowledge base | ✅ done |
| P4 Detector agent | 🔄 built, gate pending |
| P5 Downstream crew + response | ✅ built (live run pending) |
| P6 Evaluation | ⬜ |
| P7 Colab | ⬜ |
| P8 Polish | ⬜ |

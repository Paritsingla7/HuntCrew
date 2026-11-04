# Progress Log

Newest entry on top.

## 2026-11-04 — Fresh split
- Declared before any run (ADR-037): DoS, web attacks, DDoS and unused Bot/PortScan stretches, 66 windows, 57 positives. Result: nothing
  generalises well; hybrid F1 0.02, the volume rule b2 0.11. Agent-led only partly run (provider outage on the 14b model, I-030; resumable).

## 2026-11-04 — Model-size sweep
- 3b, 8b, nemo vs the frozen 14b (hybrid, test): F1 0.26 / 0.31 / 0.26 / 0.34. Larger Mistral models are unavailable on this key
  (limit 0 or tier), so no stronger-model test was possible. Per-model throttle limits are now config.

## 2026-11-04 — Technique naming
- Tactic-level metric (official ATT&CK data) beside the strict one: strict 1/9, tactic 6/9. Fixed a race that made the judge's
  candidate order, and so the named technique, vary between runs (I-028). No prompt tuning on test incidents.

## 2026-11-04 — Uncertainty: paired window bootstrap
- `stats.py`, `export_predictions.py`, `bootstrap_ci.py`; per-window predictions saved in `results/predictions_test.json` so intervals
  reproduce without the LLM caches; a test ties them to the frozen micro-averages (and the post-hoc ones). Hybrid vs B0 clear;
  hybrid vs the no-LLM filter not.

## 2026-11-04 — Union of candidates (negative result)
- `candidates_from="union"` (rules ∪ screening, rule hits verified first under the cap). Frozen modes verified unchanged by
  re-running the SSH-Patator hybrid from the LLM cache (identical findings, 0 API calls). First direct tests for `detect_window`.
- ADR-032 fixed the criterion first. Test: F1 0.22 vs hybrid 0.34; recall up to 0.44 but 247 false positives. Not met.

## 2026-11-04 — Post-hoc cheap baselines (does the LLM earn its place?)
- Added `cheap_baselines.py` (b2 quantile rule, b3 IsolationForest, b4 rules-AND-b2 filter), config-driven and
  registry-based, no LLM; `scripts/run_cheap.py`; ADR-031 declares it post-hoc with parameters fixed beforehand.
- Findings: agent-led (F1 0.17) does not beat b2 (0.21); the LLM verification keeps more true detections than a
  no-LLM filter (28 vs 19, 7 of the 9 on Bot) at somewhat more false positives (40 vs 19). Frozen results unchanged.
- Tests: 88 passed (10 new). Next in the improvement list: the union-of-candidates experiment (item 2).

## 2026-11-04 — Standalone assignment notebook
- Replaced the 42-cell "whole project" notebook with a short standalone one (22 cells, about 380 lines of code) that shows
  the agentic part and nothing else: data, RAG, rule candidates, four agents, guardrails, approval gate, grading (ADR-030).
  The repository is the full project; the notebook links to it.
- Tested without an API key: stand-in model over the real data and real CrewAI tool calling (78 tests + 1 slow test).
- Mistral key was rejected for a while (I-022); a new key fixed it. The notebook then ran live on Colab: attacker confirmed in 3 of 3 windows,
  1 false alarm, 0 missed; technique named SSH instead of T1110 (I-025). Two Strategist guardrail gaps found and fixed.

## 2026-11-03 — Earlier same-day notebook consolidation; folder renamed
- The Colab side had three files (notebook, a generator script in `notebooks/`, `requirements-colab.txt`) and the
  notebook depended on cloning the repository. It is now **one file**: `notebooks/huntcrew_colab.ipynb` embeds the
  requirements, config, policy, saved results, fetch script and all 19 package modules (ADR-029). The generator
  moved to `scripts/build_notebook.py`; `requirements-colab.txt` was removed.
- Project folder renamed to `HuntCrew` to match the repository; conda environment is `huntcrew`.

## 2026-10-15 (night) — P3 Knowledge base
- `attack_kb.py`: official ATT&CK v20 STIX → 706 chunks (227 techniques + 479 sub-techniques), each joined with
  its official mitigations and detection analytics; local MiniLM embeddings in ChromaDB; every search is
  traced so guardrails can verify a cited ID was really retrieved.
- Retrieval smoke set (20 hand-written queries): hit@1 0.80, hit@3 0.95, hit@5 0.95.
- Tests: 34 passing (first run downloads the embedding model, ~1 min).
- Next: P4 detector agent (needs the provider API key and limits).

## 2026-10-15 (morning) — P7 Colab run verified
- Notebook is generated from the package (`notebooks/build_notebook.py`) and opened from GitHub in Colab.
- Fixed on the way: import path, Colab-friendly requirements, install-and-restart cell, loop-safe crew
  execution, idempotent clone, API-key preflight (I-018, I-019).
- Fresh-runtime run succeeded: detection on real traffic (attacker `172.16.0.1` flagged), assessment
  `T1021.004` + `T1110`, simulated rate limit, incident report, results table.
- Added `docs/06-viva-notes.md` and the Colab badge in the README.

## 2026-10-15 (morning) — P6 evaluation complete
- Dev: B0 recall 0.93 / precision 0.27; agent-led 0.64 / 0.09 (gate missed, ADR-027); hybrid 0.93 / 0.42.
- Test slices run once on the frozen commit `19b8682`. Pooled: B0 R 0.29 / P 0.27 / 76 FP; hybrid R 0.29 /
  P 0.41 / 40 FP; agent-led R 0.36 / P 0.11 / 273 FP; B1 R 0.03 / 401 FP.
- Hybrid pipeline: grounding 1.00, policy pass 1.00, incident-level technique accuracy 1/9.
- Wrote `docs/05-evaluation.md` with limitations stated plainly; assembled `results/final.json`.
- Next: Colab run through Chrome, README results and viva notes.

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
| P4 Detector agent | ✅ done (gate: hybrid) |
| P5 Downstream crew + response | ✅ done |
| P6 Evaluation | ✅ done |
| P7 Colab | ✅ done |
| P8 Polish | ✅ done (v1.0.0, final state) |

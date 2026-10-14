# 04 — Implementation Plan

**Window:** 2026-10-15 → 2026-10-19 (demo in Google Colab due the 19th). Phases are sequential; each
ends with an exit check, a `PROGRESS.md` entry and a small series of commits.

## Phases

| Phase | Day | Deliverable | Exit check |
|---|---|---|---|
| P1 Foundation | Oct 15 | repo, env, data fetch, loader, schema, config, policy, docs | tests green; data verified against published counts |
| P2 Replay + digest + B0 | Oct 16 | replay clock with no-future guard, digest, B0 rules baseline | tests; B0 numbers on the dev slice |
| P3 Knowledge base | Oct 16 | ATT&CK parse → chunks → ChromaDB, retrieval test set | hit@k reported |
| P4 Detector agent | Oct 17 | LLM wrapper (throttle/cache), tools, detector, evidence check, decision gate | gate verdict on dev |
| P5 Downstream crew + response | Oct 18 | Threat-Intel, Strategist, Reporter, guardrails, executor, approval gate | one incident end-to-end; planted bad citation rejected |
| P6 Evaluation | Oct 18 | B1, B2 (and B2-hybrid if needed), graders, results table | table from one command |
| P7 Colab | Oct 18–19 | generated notebook, fresh runtime | "Run all" clean |
| P8 Polish | Oct 19 | README, report notes, demo script | rehearsed |

This is tight. Cut order if behind: B2-hybrid → PortScan slice → Reporter polish.

## Dependency order in code
`config/schema → data_cic → replay → digest → attack_kb → detector → crew → response → evaluate → notebook`

## Engineering protocol
- Docs first: non-obvious choices become ADRs when made; each session adds a `PROGRESS.md` entry.
- Test-first for deterministic parts; stubbed LLM in tests, real model only in evaluation runs.
- One module per step; its tests pass before the next starts.
- Secrets only via environment (`.env` locally, Colab Secrets remotely); never written to tracked files.
- Git: Conventional Commits, small single-purpose commits on feature branches, push only after lint,
  type check and code-graph analysis pass.
- Data is fetched by `scripts/fetch_data.py` and never committed.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| Provider rate limits (~1 req/s, ~50k tokens/min, unverified) | throttle, backoff, disk cache, bounded tool calls per window, subsampled windows |
| Agent detector worse than rules | pre-registered gate → B2-hybrid; reported honestly |
| LLM invents IDs / numbers | citation guardrail, evidence check; hallucination rate is a reported metric |
| CrewAI version drift | pinned version; CrewAI use confined to `crew.py` / `detector.py` |
| ChromaDB / sqlite trouble on Colab | corpus ≈ 700 chunks; numpy cosine fallback is one function |
| Colab automation fragility | manual "Run all" notebook always provided |
| Time | working local pipeline before Colab; additive phases last |

## Evaluation design
- Systems: **B0** rules + fixed map · **B1** single prompt · **B2** full crew · **B2-hybrid** (fallback).
- Slices (pre-registered in `config.yaml`): dev = FTP-Patator morning; test = SSH-Patator, Bot, PortScan.
- Metrics: recall / FP incidents / F1; technique accuracy and retrieval hit@k; grounding rate;
  mitigation overlap and policy pass rate; calls, tokens and seconds per window.
- Grading granularity and mapping: `label-mapping.md`.

# 03 — Architecture (final plan, approved 2026-10-15)

> Working name: **HuntCrew**. This document is the authoritative description of the system.
> Earlier designs are kept in `DECISIONS.md` as superseded ADRs.

## The crux: one picture

```
 REAL DATA                      REPLAY SIMULATOR (code)              AGENTS (Mistral via CrewAI)
 CIC-IDS2017 flows ─▶ slice ─▶ 5-min window ─▶ digest (stats) ─▶ 1 DETECTOR  (RAG + flow-query tools)
 (Label held aside)            no peeking ahead                      │ findings + quoted evidence
                                                                     ▼
 ATT&CK STIX ─▶ chunks ─▶ ChromaDB ◀──────────────────────────── evidence check (code)
 (techniques + mitigations)                                          │ merge into incidents
                                                                     ▼
                                          2 THREAT-INTEL (RAG) → technique ID + citation
                                          3 STRATEGIST (ATT&CK mitigations) → severity + actions
                                          4 REPORTER → incident report
                                                                     ▼
                                          guardrails (code) → approval gate (you) → simulated firewall
                                                                     ▼
                                          GRADER (code) vs dataset labels + official ATT&CK
```

Read it as three lanes: **real inputs** (left), **a replay simulator that controls what the
agents may see** (middle), **agents whose every output is checked by code** (right).

## Why this design is defensible (each point is an ADR)

| # | Principle | What it buys | ADR |
|---|---|---|---|
| 1 | **Nothing is graded by what produced it.** Ground truth = dataset authors' labels + the official ATT&CK IDs; the grader is plain code. | No circular evaluation; numbers mean something | 017 |
| 2 | **Real traffic, real handbook.** The only hand-made inputs are enumerated (see below). | Retrieval can genuinely fail; results are not self-fulfilling | 015 |
| 3 | **The agent decides what is suspicious; code only summarises and verifies.** The digest has no thresholds; the evidence check has no opinions. | Detection is genuinely agentic and still auditable | 016 |
| 4 | **No peeking.** A replay clock reveals one window at a time; labels never enter the agents' world. | No leakage from the future or from the answer key | 016 |
| 5 | **Every claim is checkable.** Quoted numbers must exist in the window; cited IDs must be in ATT&CK *and* in this run's retrieval trace; actions must be on the allow-list. | Hallucinations are measured, not hidden | 007 |
| 6 | **Rules are kept — as the baseline.** B0 is a classic rules+fixed-map SIEM. | The agent has to *earn* its place | 016 |
| 7 | **Pre-registered decision gate.** The bar for "agent detector is usable" is fixed before results are seen; otherwise fall back to hybrid. | No moving goalposts | 019 |
| 8 | **Simulation only, human gate.** Actions run on a simulated firewall; medium/high risk needs approval. | Safe agentic action-taking | 006 |

## Who does what

| Component | Done by | Source of truth |
|---|---|---|
| Traffic | CIC-IDS2017 (real) | dataset authors |
| Handbook (techniques, mitigations) | official MITRE ATT&CK STIX | MITRE |
| Digest (per-entity statistics) | code | arithmetic |
| **Detection decision** | **Detector agent (LLM + RAG + flow-query tools)** | the model, verified by code |
| Technique naming | Threat-Intel agent (LLM + RAG) | ATT&CK entries |
| Response plan | Strategist agent (LLM + RAG) | ATT&CK mitigations |
| Report | Reporter agent (LLM) | upstream outputs |
| Safety | code + human | policy |
| **Grading** | **code** | dataset labels + ATT&CK |

## Components (`src/huntcrew/`)

| Module | Responsibility |
|---|---|
| `config.py` + `config.yaml` | model, throttle, window size, top-k, paths, seeds |
| `schema.py` | Pydantic contracts (below) |
| `data_cic.py` | load CIC-IDS2017 parquet → flows; **labels split into a separate table**; time slicing |
| `replay.py` | replay clock → windows; history store that refuses future reads |
| `digest.py` | window → per-entity statistics (no thresholds) |
| `attack_kb.py` | STIX → chunks (+mitigations) → embeddings → ChromaDB; `search()` |
| `detector.py` | Detector agent, flow-query tools, evidence check, merge into incidents |
| `crew.py` | Threat-Intel, Strategist, Reporter agents; guardrails; LLM wrapper (throttle + cache) |
| `response.py` | action catalog/policy, simulated environment, approval gate, executor |
| `baselines.py` | B0 rules + fixed map; B1 single prompt |
| `evaluate.py` | graders and metrics |
| `scripts/fetch_data.py` | reproducible dataset download + checksums (data is never committed) |
| `notebooks/` + `build_notebook.py` | Colab submission generated from the package |

## Data contracts

- `Flow`: `ts, src_ip, dst_ip, src_port, dst_port, protocol, duration, fwd_pkts, bwd_pkts, bytes, ...` (final columns fixed after data inspection — see `docs/data-provenance.md`)
- `WindowDigest`: `window, entities[{ip, flows, distinct_dst_ports, distinct_dst_ips, mean_duration, bytes, interarrival_stats, top_ports}]`
- `Finding`: `window, entity, behaviour, evidence{metric: value}, technique_hints[{id, citation}], confidence`
- `Incident`: `id, entity, start, end, findings[]`
- `ThreatAssessment`: `techniques[{id, confidence, citation}], rationale`
- `ResponsePlan`: `severity, actions[{type, target, justification, mitigation_id}]`
- `ActionLog`: `executed[], pending[], denied[], rejected_by_policy[]`
- `GradeRecord`: per incident / per window verdicts vs labels

## RAG design

- **Corpus:** ATT&CK Enterprise `attack-pattern` objects (techniques and sub-techniques, excluding
  revoked/deprecated), with tactics, platforms, detection text and data sources; `course-of-action`
  (mitigations) joined via `mitigates` relationships.
- **Chunk:** one technique = one chunk; metadata carries `attack_id`, `name`, `tactics`, `mitigation_ids`.
- **Embeddings:** `all-MiniLM-L6-v2`, local (no API quota). Store: ChromaDB.
- **Retrieval:** cosine top-k with scores; every call is logged to a retrieval trace used by the guardrail.
- **Used in three places:** Detector (does this behaviour match known attacker behaviour?),
  Threat-Intel (name the technique), Strategist (official mitigations).

## Safety model

1. Executor accepts only the action catalog; each action has a static risk class.
2. `low` runs automatically; `medium`/`high` need human approval.
3. Protected assets (jump host, DNS, backup) can never be isolated or blocked.
4. Everything runs against a `SimulatedEnvironment`; nothing leaves the notebook.

## Evaluation (all graded by code)

Systems: **B0** rules+fixed map · **B1** single LLM prompt, no tools · **B2** full crew · **B2-hybrid** (fallback only).
Levels: L1 detection (recall / FP / F1) · L2 per-incident verdict · L3 technique accuracy + retrieval hit@k ·
L4 grounding rate · L5 mitigation overlap with official ATT&CK mitigations + policy pass rate · L6 cost.
Splits: thresholds for B0 and the digest statistics are chosen on a development slice; the test slice is untouched until the end.

## What is still hand-made (stated openly)

1. B0 baseline thresholds and the digest's choice of statistics.
2. The label→technique mapping (≈3–4 lines, published in `docs/label-mapping.md`).
3. The action catalog, risk classes and protected assets (organisational policy, not retrievable fact).

## Known limitations

Flows carry no payloads and no login outcome, so severity is judged from behaviour only; incident counts
are small (tens), so results show a pattern rather than a precise rate; CIC-IDS2017 label noise is
documented in the literature; replay is offline, not live.

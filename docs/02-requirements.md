# 02 — Problem Statement & Requirements (final plan)

**Project:** HuntCrew — agent-led threat detection and response on real network traffic
**Assigned title:** "Multi-Agent Cyber-Threat Detection and Response System Using CrewAI and RAG"
**Stack:** CrewAI · RAG (ChromaDB + local sentence-transformers) · Mistral via LiteLLM · Google Colab

## Problem statement

Security teams are overwhelmed by log data and alerts, and the work between "something looks odd"
and "here is what we do about it" is slow, manual and inconsistent. An analyst must dig through
traffic, identify the attack type from references such as MITRE ATT&CK, find the right response,
act, and write it up — which depends on who is on shift.

Two obvious shortcuts fail. Fixed-rule automation detects only what it was written for, cannot
explain, and acts blindly. A single LLM chatbot explains fluently but invents facts (non-existent
attack IDs), has no grounding in a real knowledge base, and cannot be trusted to act.

**Proposed solution:** a crew of cooperating agents in which a **detector agent decides what is
suspicious** in replayed real traffic using retrieval over the official ATT&CK knowledge base;
further agents name the technique, plan a policy-checked response from official mitigations, and
write the report. Code verifies every claim, a human approves risky actions, and **code — not the
agents — grades the result against labels the system never sees.**

## Objectives (measurable)

| # | Objective | Check |
|---|---|---|
| O1 | Detect real attacks in replayed traffic without flagging benign activity | recall / FP incidents / F1 per attack, vs dataset labels |
| O2 | Name the attack technique correctly | parent-level match with mapped ATT&CK ID |
| O3 | Back every claim with a real knowledge-base entry | grounding rate: cited IDs that exist in ATT&CK and were retrieved |
| O4 | Propose only allowed, relevant actions; risky ones need approval | policy pass rate; overlap with official ATT&CK mitigations |
| O5 | Show whether agent-led detection earns its place | B2 vs B0 (rules) vs B1 (single prompt), pre-registered gate |

## Functional requirements

| ID | Requirement | Acceptance check |
|----|-------------|------------------|
| FR1 | Load CIC-IDS2017 flows; labels returned as a separate object; timestamps repaired | counts match published; spans match schedule (tests) |
| FR2 | Replay clock exposes one window at a time; history queries cannot read the future | unit test: future read raises |
| FR3 | Digest: per-entity statistics for a window, no thresholds | deterministic; unit-tested |
| FR4 | ATT&CK knowledge base from official STIX: techniques, sub-techniques, mitigations, detection analytics; stable IDs; local embeddings in ChromaDB | retrieval hit@k measured on a test set |
| FR5 | **Detector agent**: given a digest, uses flow-query and RAG tools to emit findings with quoted evidence and technique hints | runs on a window; output validates against schema |
| FR6 | Evidence check (code): entity and every quoted number must exist in the window | planted false evidence is rejected |
| FR7 | Threat-Intel, Strategist, Reporter agents with typed outputs | one incident end-to-end |
| FR8 | Guardrails: cited IDs ∈ ATT&CK ∧ ∈ retrieval trace; actions ∈ catalog; targets ∉ protected assets | planted bad citation rejected |
| FR9 | Executor on a simulated environment; medium/high risk needs approval | one denied and one approved action shown |
| FR10 | Evaluation: B0 rules+map, B1 single prompt, B2 full crew (+B2-hybrid if gate trips) | one command produces the results table |
| FR11 | Model, throttle, windows, splits, mapping, gate bar are config | change without code edits |
| FR12 | Colab notebook generated from the package | "Run all" on a fresh runtime |

## Non-functional requirements
- Runs on Colab free tier (CPU). Respect Mistral free-tier limits (≈1 req/s, ≈50k tokens/min on small
  models — community-observed, to be verified in the provider dashboard): throttle, cache, bounded tool calls.
- Reproducible: pinned versions, data fetched by script with checksums, fixed splits.
- Safe: no real side effects; API key only via env var / Colab Secrets.
- Explainable: every decision traceable to flow evidence + knowledge-base citation.

## Out of scope
Payload-level attacks (SQL injection etc.), live streaming, model fine-tuning, real firewall/SIEM
integration, UI beyond the notebook.

## Success criteria for the demo
1. Fresh Colab runtime → "Run all" works without manual edits.
2. Results table for B0/B1/B2 on the pre-registered test slices, reported as-is.
3. Live demo: replay window → detector finding → technique + citation → plan → denied and approved action → report.

## Stated limitations
Flows carry no payload or login outcome; incident counts are small; CIC-IDS2017 labels contain known
noise; replay is offline.

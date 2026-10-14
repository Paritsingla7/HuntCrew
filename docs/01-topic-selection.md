# 01 — Topic Selection

**Date:** 2026-10-14 · **Deadline:** 2026-10-19 (demo in Google Colab) · **Status:** decided, see ADR-001

## The 15 assigned titles, rated for difficulty

Difficulty = how many distinct agentic-AI skills the project forces you to get right
(multi-agent orchestration, RAG, tool use, structured output, guardrails, action-taking,
evaluation against ground truth).

| # | Title | Orchestration | RAG | Tools / actions | Needs ground-truth eval | Overall |
|---|-------|:---:|:---:|:---:|:---:|:---:|
| 1 | **Multi-Agent Cyber-Threat Detection & Response (CrewAI + RAG)** | high | high | high (detect + respond) | yes — attacks are labelled | **Hardest** |
| 2 | Phishing email detection + explanation | low | low | low | yes | Easy |
| 3 | Malware detection + security recommendation | med | low | med | yes | Medium |
| 4 | College enquiry chatbot (RAG + LCEL) | low | med | low | weak | Easy |
| 5 | Personalised learning assistant | med | med | low | weak | Medium |
| 6 | Question-paper generation + validation | med | med | low | weak | Medium |
| 7 | Resume screening + job recommendation | med | med | low | med | Medium |
| 8 | Healthcare assistant (RAG) | low | med | low | weak (safety-sensitive) | Medium |
| 9 | Fake-news detection + fact verification | med | high | high (needs live web) | yes | Hard |
| 10 | Research-paper summarisation + lit. review | med | high | med | weak | Medium |
| 11 | Customer-support system (RAG + LCEL) | low | med | med | weak | Easy |
| 12 | Code generation + testing + review | high | low | high (code execution sandbox) | yes | Hard |
| 13 | Travel planning (CrewAI) | med | low | med (live APIs) | weak | Medium |
| 14 | Smart agriculture advisory | low | med | low | weak | Easy |
| 15 | Sales lead analysis + follow-up (RAG) | med | med | med | weak | Medium |

## Decision

**Title 1 — Multi-Agent Cyber-Threat Detection and Response System Using CrewAI and RAG.**

Why it is the hardest *and* the best one to defend in a viva:

1. It is the only title that combines **all** of: multi-agent orchestration, RAG over
   authoritative knowledge (MITRE ATT&CK, CVE, response playbooks), tool use, *and*
   taking (simulated) actions with a human-approval gate.
2. It has **objective ground truth**. Because we generate the attack logs ourselves, we
   know exactly which events are attacks and which ATT&CK technique each one is. That lets
   us report real precision/recall numbers instead of "it looks good".
3. It has a natural **safety story** (never auto-block without policy + approval), which is
   the part of agentic AI examiners tend to probe.
4. Cost is controllable: the detection layer is deterministic; the LLM is only used for
   reasoning over a handful of incidents, so a free-tier API is enough.

Runner-ups if this one is ever dropped: #12 (code gen/test/review) then #9 (fake news).

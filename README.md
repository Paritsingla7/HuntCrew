# HuntCrew

**Agent-led threat detection and response on real network traffic, graded by code against labels the
system never sees.**

A detector agent decides what is suspicious in replayed CIC-IDS2017 traffic using retrieval over the
official MITRE ATT&CK knowledge base. Further agents name the technique, plan a response from official
mitigations and write the report. Code verifies every claim, a human approves risky actions, and the
whole run is scored against the dataset's own labels.

## The crux

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

Why it is built this way:

1. **Nothing is graded by what produced it.** Labels come from the dataset authors; the grader is code.
2. **Real traffic, real handbook.** Hand-made inputs are few and listed.
3. **The agent decides; code summarises and verifies.** The digest has no thresholds; the evidence check has no opinions.
4. **No peeking.** The replay clock reveals one window at a time; labels never enter the agents' world.
5. **Every claim is checkable.** Quoted numbers, cited IDs and proposed actions are all verified by code.
6. **Rules stay as a baseline,** so the agent has to earn its place.
7. **Pre-registered gate.** The bar for "agent detection is usable" was fixed before any result.
8. **Simulation only, human gate** for risky actions.

## Status
Foundation (P1) done: data loader, config, schema, reproducible data fetch. See `docs/PROGRESS.md`.

## Quick start
```bash
conda create -n huntcrew python=3.12 -y && conda activate huntcrew
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
python -I scripts/fetch_data.py        # CIC-IDS2017 flows + ATT&CK STIX, with checksums
pytest -q
```
The LLM stage needs `MISTRAL_API_KEY` in the environment (a local `.env` is git-ignored).

## Docs
| File | Contents |
|---|---|
| `docs/01-topic-selection.md` | why this problem |
| `docs/02-requirements.md` | problem statement, objectives, requirements |
| `docs/03-architecture.md` | design, principles, components, evaluation |
| `docs/04-implementation-plan.md` | phases, risks, evaluation design |
| `docs/data-provenance.md` | where data came from, checks, quirks |
| `docs/label-mapping.md` | label → ATT&CK mapping and grading rules |
| `docs/DECISIONS.md` | architecture decision records |
| `docs/PROGRESS.md` | running worklog |

## Data and citations
CIC-IDS2017: Sharafaldin, Habibi Lashkari, Ghorbani, *Toward Generating a New Intrusion Detection Dataset
and Intrusion Traffic Characterization*, ICISSP 2018. MITRE ATT&CK® is used under the ATT&CK Terms of Use.

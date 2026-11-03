# HuntCrew — final report

## 1. What it is
HuntCrew is a multi-agent system that detects and responds to network attacks, built with CrewAI, RAG and the
Mistral API, and run in Google Colab. It answers the assignment title *"Multi-Agent Cyber-Threat Detection
and Response System Using CrewAI and RAG"*.

**Problem.** Security teams drown in traffic and alerts; going from "something looks odd" to "here is what we
do about it" is slow and inconsistent. Fixed rules detect only what they were written for and cannot explain;
a single chatbot explains fluently but invents facts and has no grounding in a real knowledge base.

**Approach.** Real network traffic (CIC-IDS2017 labelled flows) is replayed one 5-minute window at a time.
Code turns each window into plain statistics. Agents decide what is suspicious, name the attack using the
official MITRE ATT&CK knowledge base (retrieval), plan a policy-checked response from official mitigations
and write an incident report. Code verifies every claim, a human approves risky actions, everything executes
against a simulated firewall, and **code grades the result against the dataset's own labels**, which the
system never sees.

```
 CIC-IDS2017 flows ─▶ replay window ─▶ digest (stats) ─▶ DETECTOR (RAG + tools) ─▶ evidence check (code)
 ATT&CK STIX ─▶ chunks ─▶ ChromaDB ─────────────────────────┘             │
                                  THREAT-INTEL (RAG) ▶ STRATEGIST (mitigations) ▶ REPORTER
                                  guardrails (code) ▶ approval gate ▶ simulated firewall ▶ GRADER (code)
```

## 2. How it was built
| Step | What was done | Result |
|---|---|---|
| Topic | Rated all 15 titles; chose the one combining orchestration, RAG, tools, action and objective ground truth | ADR-001 |
| First design rejected | Self-generated logs + hand-written handbook + self-grading was circular | replaced by real data and an official handbook (ADR-015) |
| Data | CIC-IDS2017 (2.83M flows) and ATT&CK v20 (706 techniques/sub-techniques); fetched by script with checksums; timestamps repaired (day-first, mixed formats, 12-hour clock) | `data-provenance.md` |
| Replay simulator | One window at a time; look-back bounded; reading the future raises; labels held in a separate object | no leakage |
| Digest | Per-source statistics with no thresholds; listing structured because a window holds ~300–550 sources | ADR-022 |
| Knowledge base | One chunk per technique joined with official mitigations and detection analytics; local embeddings; every search traced | retrieval hit@5 0.95 on a smoke set |
| Baselines | B0 classic rules (frozen after dev refinement); B1 single prompt | to be beaten |
| Detector | First single-pass design anchored on busy hosts; redesigned as forced-coverage screening then tool-based verification with a verdict per candidate | ADR-025 |
| Gate | Bar fixed before results; agent-led detection missed it on dev → hybrid (rules propose, agent verifies) | ADR-027 |
| Downstream | Threat-intel (hypothesis searches + evidence-scoring judge), strategist, reporter; code guardrails; policy, simulated environment, approval gate | grounding 1.00, policy 1.00 |
| Evaluation | Test slices run once on frozen commit `19b8682`; all four systems graded by code | `05-evaluation.md` |
| Colab | Notebook generated from the package; verified on a fresh runtime | `notebooks/` |

Engineering practice: docs and decision records written as choices were made (`DECISIONS.md`, 28 ADRs);
tests for every deterministic part (74); ruff and mypy clean; secrets only via environment; data never
committed; small single-purpose commits.

## 3. Results (test slices, one frozen run, `ministral-14b-latest`)
Pooled over SSH-Patator, Bot and PortScan (95 attack-positive (window, entity) pairs):

| System | Recall | Precision | F1 | False positives |
|---|---|---|---|---|
| B0 rules | 0.29 | 0.27 | 0.28 | 76 |
| B1 single prompt | 0.03 | 0.01 | 0.01 | 401 |
| Agent-led | 0.36 | 0.11 | 0.17 | 273 |
| **Hybrid** | 0.29 | **0.41** | **0.34** | **40** |

Hybrid pipeline: grounding rate 1.00, policy pass rate 1.00, incident-level technique accuracy 1 of 9.

**Honest reading.** Verification by an agent with baselines and retrieval roughly halves the rules' false
positives without losing a detection. Agent-led first-pass detection is not usable alone with this model
class. Technique naming is weak, and low-and-slow beaconing is mostly missed. Samples are small and results
are for one model. Full protocol and limitations: `05-evaluation.md`, `ISSUES.md`.

## 4. The Colab version
**What it is.** `notebooks/huntcrew_colab.ipynb` is the standalone assignment notebook: one short file (22 cells,
about 380 lines of code) that shows the agentic part and runs on its own. It needs no repository clone and no other
file; it downloads its own data (CIC-IDS2017 flows and the ATT&CK bundle), builds the knowledge base and runs four
agents. It is a **condensed version** of the pipeline; the full, tested project (replay simulator, evaluation
harness, 78 tests, decision records) is this repository. The notebook is generated by `scripts/build_notebook.py`.

**What you see when it runs (about 10 minutes on a free CPU runtime).**
1. Install packages (restarts the session once, by design) and set up the language model.
2. Download and load the data; the answer key (labels) is kept apart from what the agents see.
3. Build the ATT&CK knowledge base (RAG) and show two sample retrievals.
4. Rules propose candidates in four 5-minute windows of real traffic.
5. **Detector agent** verifies each candidate with tools (tool calls are printed) and dismisses false alarms.
6. **Threat-Intel agent** names the technique (competing hypotheses, then an evidence-scoring judge; ungrounded IDs are dropped).
7. **Strategist agent** plans a response from official mitigations; code enforces policy and protected assets, and a
   **human approval gate** (`approve? [y/N]`) stands in front of risky actions; execution is simulated.
8. **Reporter agent** writes the incident report.
9. **Grading by code** against the dataset labels for the demo windows, then the results of the full evaluation.

**How to run it.**
1. In Colab, left sidebar → key icon → **Add new secret**: name `MISTRAL_API_KEY`, value = a valid key, switch
   **Notebook access** on.
2. Open https://colab.research.google.com/github/Paritsingla7/HuntCrew/blob/main/notebooks/huntcrew_colab.ipynb
3. **Runtime → Run all**. The first pass installs packages and restarts the session (Colab shows "session crashed",
   which is expected); run all again and click **Grant access** when asked.
4. Answer the approval prompt if a medium/high-risk action is proposed. For an unattended run set `APPROVAL = "deny"`.
5. To keep the outputs, **File → Download .ipynb** (or print to PDF) after the run.

**Troubleshooting.** `Mistral rejected the key` → create a new key in the Mistral console and re-create the Colab
secret without spaces. 429 on `mistral-small`/`medium` → the key has no quota for them; the notebook uses
`ministral-14b-latest`.

**Testing.** The notebook is checked against its generator, every code cell must parse, and a slow test runs the whole
notebook on the real data against a stand-in model (`HUNTCREW_SLOW=1 pytest tests/test_notebook.py`). A live run
with the real model needs a valid Mistral key.

## 5. Run it locally
```bash
conda create -n huntcrew python=3.12 -y && conda activate huntcrew
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -r requirements.txt
python -I scripts/fetch_data.py
cp .env.example .env   # or create .env with MISTRAL_API_KEY=...
pytest -q
python scripts/run_eval.py test --systems b0 b1 hybrid
```

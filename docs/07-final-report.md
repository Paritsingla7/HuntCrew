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
**What it is.** `notebooks/huntcrew_colab.ipynb`, generated from the repository by
`notebooks/build_notebook.py`. It contains no logic of its own: it clones the repo, installs dependencies,
downloads the two datasets, and calls the same `huntcrew` package used locally.

**What it does when run (about 10–15 minutes on a free CPU runtime).**
1. Clone the repo and install dependencies (restarts the session once, by design).
2. Download CIC-IDS2017 and ATT&CK (about 425 MB, checksum-verified).
3. Set up: load flows, build the 706-chunk ATT&CK knowledge base, wire the agents.
4. **Live detection** on two windows of the SSH-Patator test slice in hybrid mode.
5. **Live response**: technique assessment, plan, policy check, approval prompt for risky actions,
   simulated execution, incident report.
6. **Results table** from the pre-computed full evaluation (`results/final.json`).

**What it does not do.** It does not re-run the full evaluation (about an hour of API calls). That is
`scripts/run_eval.py`, which can also be run from a Colab cell after the setup cell.

**How to run it.**
1. In Colab, open the left sidebar → key icon → **Add new secret**: name `MISTRAL_API_KEY`, value = your key,
   switch **Notebook access** on.
2. Open https://colab.research.google.com/github/Paritsingla7/HuntCrew/blob/main/notebooks/huntcrew_colab.ipynb
3. Click **Connect**, then **Runtime → Run all**. Click **Run anyway** on the "not authored by Google" warning
   (the notebook comes from the project's GitHub repository).
4. The first pass installs packages and restarts the session; Colab shows "session crashed", which is
   expected. Run all again. When asked "Notebook does not have secret access", click **Grant access**.
5. If a medium/high-risk action is proposed, a prompt `approve? [y/N]` appears under the response cell.
6. Optional: **Copy to Drive** to keep your own copy.

**Troubleshooting.** `Invalid API Key` → re-paste the secret value without spaces; the setup cell prints a key
check showing only its length. 429 errors on `mistral-small`/`medium` → the key has no quota for them; the
project uses `ministral-14b-latest`.

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

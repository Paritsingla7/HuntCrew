# Decision Log (ADRs)

Format: **Context → Decision → Why → Consequences**. Newest at the bottom.
Status values: `accepted`, `superseded by ADR-xxx`.

---

## ADR-001 — Topic: multi-agent cyber-threat detection & response (CrewAI + RAG)
- **Status:** accepted
- **Context:** 15 candidate titles; the hardest one was requested.
- **Decision:** title 1 (scoring in `01-topic-selection.md`).
- **Why:** the only title combining orchestration, RAG, tools, action-taking and objective ground truth.

## ADR-002 — Deterministic detection, LLM reasoning
- **Status:** superseded by ADR-016
- **Why it was dropped:** it made the *detection* half of the title non-agentic, and rules written by the
  same author as the test data made evaluation circular.

## ADR-003 — Own RAG layer exposed as CrewAI tools (not CrewAI `knowledge_sources`)
- **Status:** accepted
- **Why:** CrewAI knowledge/embedder configuration changes between releases; retrieval trace and scores are
  needed for citation checks; the layer is testable without an LLM.

## ADR-004 — LLM: Mistral (`mistral-small-latest`) via LiteLLM
- **Status:** accepted
- **Context:** free "Experiment" tier. Community-observed limits (official page unreachable at the time):
  ~1 request/s, ~50k tokens/min and ~4M tokens/month on Small-class models; free-tier data may be used for
  provider training.
- **Decision:** model, temperature, throttle and retries in `config.yaml`; request throttle + disk cache + backoff.
- **Consequences:** limits must be confirmed in the provider dashboard; only public/synthetic data is sent.

## ADR-005 — Synthetic logs with injected, labelled attacks
- **Status:** superseded by ADR-015
- **Why it was dropped:** the same author wrote attacks, detection and grading, so a pass proved little.

## ADR-006 — Simulated response actions with a human approval gate; executor is plain code
- **Status:** accepted
- **Why:** shows safe action-taking without real side effects; executing a vetted action needs no LLM.

## ADR-007 — Deterministic guardrails instead of an LLM critic
- **Status:** accepted
- **Why:** an LLM judging an LLM is itself unreliable; code checks (citation, schema, allow-list, evidence) are exact and cheap.

## ADR-008 — Package for development, notebook generated from it
- **Status:** accepted; extended by ADR-018

## ADR-009 — Python 3.12 environment
- **Status:** accepted
- **Context:** CrewAI supports Python 3.10–3.13; the workstation default is 3.14.
- **Decision:** conda environment on Python 3.12, CPU-only torch locally; versions pinned in `requirements.txt`.

## ADR-010 — Lean scope
- **Status:** accepted; scope reshaped by ADR-015/016
- **Decision:** 4 agents, small attack set, no UI, no extra ML detector.

## ADR-011 — Develop and test locally; Colab only for the final run
- **Status:** accepted
- **Decision:** phases P1–P6 run locally; the Colab run is driven through browser automation, with a
  manual "Run all" path always kept as a fallback. Credentials are entered by the project owner.

## ADR-012 — Git workflow
- **Status:** accepted
- **Decision:** `main` holds only reviewed work; work happens on short-lived feature branches; Conventional
  Commits; a sequence of small, single-purpose commits; branches stay local until merge time, where lint,
  type check and a code-graph analysis pass run before anything is pushed.

## ADR-013 — Alerts carry no technique ID
- **Status:** superseded by ADR-016 (rules are now a baseline only; B0 uses a fixed rule→technique map)

## ADR-014 — Generator includes deliberate false-positive traps
- **Status:** superseded by ADR-015

## ADR-015 — Real traffic and the official ATT&CK handbook; hand-made inputs enumerated
- **Status:** accepted
- **Context:** self-written logs, handbook and grading form a closed loop.
- **Decision:** traffic = CIC-IDS2017 labelled flows; knowledge = MITRE ATT&CK Enterprise STIX (techniques,
  mitigations, detection analytics); ground truth = dataset labels. The only hand-made inputs are the
  baseline thresholds, the label→technique mapping and the action policy, all listed in the docs.
- **Consequences:** payload-level attacks are out of scope (flows only); retrieval over ~700 real entries can
  genuinely fail; see `data-provenance.md`.

## ADR-016 — Agent-led detection through a replay simulator
- **Status:** accepted
- **Decision:** a replay clock reveals one time window at a time; code computes a statistics-only digest
  (no thresholds); a **detector agent** with RAG and flow-query tools decides what is suspicious; code
  verifies the quoted evidence and merges findings into incidents. Hand-written rules remain only as the
  B0 baseline and as a fallback.
- **Why:** detection becomes genuinely agentic without letting the model read hundreds of thousands of
  rows; no future or label leakage; every claim checkable.
- **Consequences:** more LLM calls than a rules-first design; cost bounded by window size, call caps and caching.

## ADR-017 — Grading by code against external labels; systems never grade themselves
- **Status:** accepted
- **Decision:** metrics are computed by plain code from dataset labels and official ATT&CK IDs.
  An LLM judge, if ever added, is secondary and never a headline number.

## ADR-018 — One codebase, two deliverables
- **Status:** accepted
- **Decision:** the `huntcrew` package and docs form the public repository; the college submission is a
  Colab notebook generated from the same package. Data is fetched by script with checksums, never committed.

## ADR-019 — Pre-registered splits and decision gate
- **Status:** accepted (2026-10-15, before any detector result existed)
- **Decision:** dev/test slices and the gate bar are fixed in `config.yaml`. Digest statistics and B0
  thresholds may be tuned on dev and the benign baseline only. If the agent detector misses the bar, the
  hybrid system (B2-hybrid) is used and reported as such.

## ADR-020 — Timestamp repair rule for CIC-IDS2017
- **Status:** accepted
- **Context:** timestamps are day-first, mixed-format, on a 12-hour clock without AM/PM.
- **Decision:** parse day-first; hours < 8 are treated as afternoon (+12 h). Verified: capture spans
  08:55–17:02 and attack windows match the published schedule.

## ADR-021 — ATT&CK chunking uses detection strategies, not `x_mitre_detection`
- **Status:** accepted
- **Context:** in ATT&CK v20 the legacy detection text is gone; guidance lives in `x-mitre-detection-strategy`
  and `x-mitre-analytic` objects linked by `detects` relationships.
- **Decision:** one chunk per technique/sub-technique, joined with its mitigations and detection analytics.

## ADR-022 — Digest listing is structured, not a single top-N
- **Status:** accepted
- **Context:** a 5-minute CIC-IDS2017 window holds ~300–550 distinct sources (≈13 internal hosts, the rest
  public addresses with 1–3 flows). A single top-N-by-volume cut silently drops ~80% of sources and would
  hide low-and-slow behaviour.
- **Decision:** list every private source; list public sources that lead in any of several neutral views
  (flows, distinct ports, distinct destinations, outbound bytes, most regular timing); summarise the rest
  with explicit counts. The structure was chosen from benign Monday traffic and general reasoning, not from
  attack labels. Coverage of attack entities in test windows is reported afterwards, not tuned on.
- **Consequences:** ~1.7k tokens per window; the detector's tools can still query any source.

## ADR-023 — B0 baseline refined on benign/dev data only, then frozen
- **Status:** accepted
- **Context:** the first B0 had two real rule defects (counted a server's replies as "port scanning";
  flagged any regular HTTPS as beaconing).
- **Decision:** port-scan rule counts distinct ports per (source, destination) pair; beaconing requires a
  destination never seen in the benign baseline. Both refinements used only the Monday baseline and the dev
  slice (ADR-019). B0 is then frozen.
- **Result on dev (FTP-Patator, 21 windows):** before: 64 predicted / 13 TP / 51 FP (P 0.20, R 0.93);
  after: 48 predicted / 13 TP / 35 FP (P 0.27, R 0.93). Remaining FPs are regular HTTPS to unlisted external
  hosts and reply traffic of the attack itself.
- **Consequences:** B0 is deliberately a *classic* rules engine; a heavily tuned rule set could do better.
  This is stated as a limitation, not hidden.

## ADR-024 — Default model: `ministral-14b-latest`
- **Status:** accepted (supersedes the `mistral-small-latest` default in ADR-004)
- **Context:** probing the provider with tiny calls showed a request quota of 0 for `mistral-small*`,
  `mistral-medium-latest` and `magistral-small-latest` on this key, while `ministral-3b/8b/14b`,
  `open-mistral-nemo` and `codestral` work with much higher throughput than the dashboard figures for Small.
- **Decision:** default to `ministral-14b-latest` (30 req/min, ~937k tokens/min); `ministral-8b-latest` is the
  faster alternative. The model is configuration, so changing it needs no code edit.
- **Consequences:** results are specific to this model class and must be reported with the model name;
  response caching is keyed by model, so models never share cached answers.

## ADR-025 — Detector runs in two stages: forced-coverage screening, then tool-based verification
- **Status:** accepted
- **Context:** with the whole digest in one prompt, ministral-14b anchored on the busiest or most diverse
  sources (DNS-heavy workstations) and never opened the clearest anomaly (one source, one destination,
  one port, 650 flows, per-minute CV 0.04). Reading its tool calls showed it simply did not consider the row.
- **Decision:** stage 1 asks the model to judge **every** listed source against its peers in small chunks
  (at most 3 flagged per chunk); stage 2 gives only flagged sources to the tool-using agent, which must return
  an explicit verdict per candidate. Sources are listed in address order (not volume), a peers line gives
  typical values, and neutral concentration features (`top_port_share`, `top_dst_share`) were added.
- **Why:** forced coverage removes silent omission; an explicit verdict per candidate makes drops visible;
  none of this adds thresholds or rules.
- **Consequences:** ~15–20 LLM calls per window instead of ~4. All prompt iteration used the dev slice only.

## ADR-026 — Hybrid fallback is implemented as a mode of the same detector
- **Status:** accepted
- **Decision:** `--mode rules` takes candidates from the frozen B0 rules instead of stage-1 screening and
  runs the same verification stage, so the pre-registered fallback (ADR-019) is a one-flag change and both
  systems are graded by the same code.

## ADR-027 — Decision gate outcome: agent-led detection fails the bar; hybrid is the primary system
- **Status:** accepted (evaluated on the dev slice only, 2026-10-15; bar fixed in ADR-019 before any result)
- **Result:** B0 rules: recall 0.929, 35 false-positive (window, entity) pairs, precision 0.271.
  Agent-led (`ministral-14b`, two-stage, after fixing an output-truncation bug): recall 0.643, 95 false
  positives, precision 0.087, technique accuracy on true positives 0.33.
- **Gate:** required recall ≥ 0.70 × 0.929 = 0.650 and false positives ≤ 2 × 35 = 70. Both missed (0.643 and 95).
- **Decision:** the system under evaluation is the **hybrid** (rules propose candidates; the agent verifies,
  dismisses and names them with RAG). The agent-led result is reported as a finding and stays in the table.
- **Honest reading:** with a 14B-class model the agent over-flags busy-but-ordinary hosts; verification
  against baselines and retrieval is where it earns its place, not first-pass detection.
- **Not done:** no further prompt tuning to "pass" the gate. The test slices have not been used.

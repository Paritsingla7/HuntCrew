# 05 — Evaluation results

All numbers are produced by code (`scripts/run_eval.py`, assembled by `scripts/make_final_results.py`) against
the CIC-IDS2017 authors' labels and the official ATT&CK IDs. No agent grades another agent.

## Protocol
- Splits, label→technique mapping, grading granularity and the decision-gate bar were fixed in `config.yaml`
  **before any detector result existed** (ADR-019).
- Prompt and design iteration used the dev slice only (FTP-Patator) and the benign Monday baseline.
- The system was **frozen at commit `19b8682`**, then the three test slices were run **once**:
  SSH-Patator (Tue 14:00–15:30), Bot (Fri 10:00–12:00), PortScan (Fri 14:00–15:30); 60 five-minute windows.
- Model: `mistral/ministral-14b-latest` (larger Mistral models have a quota of 0 on the key used; see I-011).
- Grading unit: (window, entity). A source in a window is attack-positive with ≥ 5 attack-labelled flows.
  Technique matching is parent-level. See `label-mapping.md`.

## Systems
| System | What it is |
|---|---|
| B0 | Classic rules engine with a fixed rule→technique map (frozen after dev refinement, ADR-023) |
| B1 | One LLM prompt per window over the digest; no tools, no retrieval, no baseline |
| Agent-led | Two-stage LLM detector (screen every source, then verify with tools + RAG); no rules (ADR-025) |
| Hybrid | B0 rules propose candidates; the agent verifies, dismisses and grounds them (ADR-026, ADR-027) |

## Detection on the test slices
| Slice | System | Recall | Precision | F1 | False positives | Window recall |
|---|---|---|---|---|---|---|
| ssh_patator | B0 rules | 1.00 | 0.41 | 0.58 | 20 | 1.00 |
| ssh_patator | B1 single prompt | 0.00 | 0.00 | 0.00 | 120 | 0.00 |
| ssh_patator | Agent-led | 0.79 | 0.12 | 0.21 | 81 | 0.79 |
| ssh_patator | **Hybrid** | **1.00** | **0.70** | **0.82** | **6** | 1.00 |
| bot | B0 rules | 0.12 | 0.24 | 0.16 | 29 | 0.17 |
| bot | B1 single prompt | 0.03 | 0.01 | 0.02 | 148 | 0.08 |
| bot | Agent-led | 0.25 | 0.15 | 0.18 | 105 | **0.46** |
| bot | **Hybrid** | 0.12 | **0.36** | 0.18 | **16** | 0.17 |
| portscan | B0 rules | 0.62 | 0.16 | 0.25 | 27 | 0.62 |
| portscan | B1 single prompt | 0.12 | 0.01 | 0.01 | 133 | 0.12 |
| portscan | Agent-led | 0.62 | 0.05 | 0.10 | 87 | 0.62 |
| portscan | **Hybrid** | 0.62 | **0.22** | **0.32** | **18** | 0.62 |
| **all test slices** | B0 rules | 0.29 | 0.27 | 0.28 | 76 | |
| **all test slices** | B1 single prompt | 0.03 | 0.01 | 0.01 | 401 | |
| **all test slices** | Agent-led | **0.36** | 0.11 | 0.17 | 273 | |
| **all test slices** | **Hybrid** | 0.29 | **0.41** | **0.34** | **40** | |

(Pooled over slices: 95 attack-positive (window, entity) pairs.)

## Full pipeline on the hybrid system (27 incidents, 9 linked to an attack)
| Metric | Value |
|---|---|
| Grounding rate (cited technique IDs that exist in ATT&CK and were retrieved) | **1.00** |
| Policy pass rate (proposed actions that were allowed, not on protected assets) | **1.00** |
| Incident-level technique accuracy (attack-linked incidents) | **1 / 9 = 0.11** (SSH-Patator correct; Bot 0/7; PortScan 0/1) |
| Cost per slice | 78–137 LLM calls, ~134k–234k tokens, 4–8 min |
| Agent-led detection cost per slice | 158–202 calls, ~1.05–1.23M tokens, 16–19 min |

## What the numbers support
1. **Verification by an agent with baselines and retrieval roughly halves the rules' false positives without
   losing a detection** (pooled FP 76 → 40; precision 0.27 → 0.41; recall unchanged at 0.29). On the SSH-Patator
   slice the hybrid reaches F1 0.82 vs 0.58 for rules.
2. **Agent-led first-pass detection is not usable on its own with this model class**: it finds somewhat more
   (recall 0.36 vs 0.29; Bot window recall 0.46 vs 0.17) but pays 3.6× the false positives of rules and ~8× the
   tokens. This is why the pre-registered gate sent the project to the hybrid design (ADR-027).
3. **A single prompt without tools or retrieval does not work** (recall 0.03, 401 false positives): the
   structure around the model, not the model alone, is doing the useful work.
4. **Grounding and policy controls hold**: no cited technique ID was invented or unretrieved after the
   guardrails, and every proposed action was in the catalog and away from protected assets.

## What the numbers do not support (stated plainly)
- **Technique naming is weak** (1 of 9 attack-linked incidents). With flows only, brute force, flooding and
  exfiltration look alike to a 14B-class model; it also misread a high SYN counter as a SYN flood. B0's fixed
  map names techniques perfectly on what it detects, by construction, which an agent does not beat here.
- **Low-and-slow beaconing (Bot) is mostly missed** by both rules and hybrid (recall 0.12). Only the agent-led
  screening sees part of it (window recall 0.46), at an unacceptable false-positive cost. A union of rule and
  screening candidates before verification is an obvious next experiment; it was **not** tried on the test
  slices, to keep them single-use.
- **Small samples**: 95 attack-positive pairs in total, one attacker per slice. Differences between systems on
  a single slice should be read as indications, not as precise rates. The dev slice held one attack incident.
- **Labels are noisy and flows carry no payload**; severity is judged from behaviour only.
- **Everything is for one model** (`ministral-14b-latest`); results may differ with a stronger model.
- B0's thresholds are hand-made; a heavily tuned rules engine might narrow the precision gap.

## Post-hoc: does the LLM earn its place? (ADR-031, no LLM, same test slices)
Added after the frozen run, so it is **post-hoc** and kept apart from the headline. Three baselines use no LLM,
are fitted on the benign Monday only, and have parameters fixed in `config.yaml` before the run (single run,
no tuning on test). Reproduce with `python scripts/run_cheap.py test`.

| System (pooled, 95 attack-positive pairs) | Recall | Precision | F1 | False positives |
|---|---|---|---|---|
| b2 per-feature quantile outlier rule | 0.41 | 0.15 | 0.21 | 229 |
| b3 IsolationForest | 0.17 | 0.18 | 0.18 | 71 |
| b4 B0 rules AND b2 (no-LLM triage filter) | 0.20 | **0.50** | 0.29 | **19** |
| *for comparison, from the frozen run:* Agent-led | 0.36 | 0.11 | 0.17 | 273 |
| *for comparison, from the frozen run:* Hybrid | 0.29 | 0.41 | **0.34** | 40 |

What this shows:
1. **The LLM first-pass detector (agent-led) does not beat a trivial statistical rule.** b2 has higher recall (0.41
   vs 0.36), higher F1 (0.21 vs 0.17) and fewer false positives (229 vs 273), and runs in seconds, with no tokens.
   b3 ties it on F1 (0.18 vs 0.17). The earlier conclusion that agent-led is not usable on its own is therefore
   stronger than the original table suggested.
2. **The LLM verification step adds a real but narrow benefit.** The no-LLM filter b4 removes false positives as
   well as the LLM does or better (19 vs 40 pooled), but it loses true detections (19 vs 28 kept). Most of the gap
   (7 of 9) is the Bot slice: hybrid kept 9 of 73 Bot pairs, b4 only 2, because slow bot traffic does not look
   anomalous by volume and b4 filters it out; the other 2 are SSH-Patator pairs (14 vs 12). Per slice: hybrid is better on SSH-Patator (F1 0.82 vs 0.75) and Bot (0.18 vs
   0.05); **b4 is better on PortScan (0.48 vs 0.32)** with the same 5 detections and fewer false positives.
3. **Dev agrees:** b4 F1 0.57 vs hybrid 0.58 vs B0 0.42 (FTP-Patator, one incident).

Limits of this comparison: one attacker per slice and 95 pairs in total, so the differences are indications, not
significance-tested rates; b2 is very sensitive to its quantile (dev false positives 187 / 107 / 29 at q = 0.99 /
0.995 / 0.999, kept at the pre-declared 0.995); b3 and b4 are simple choices, not tuned baselines. Before this
formal run the same ideas were tried once informally on the test slices (disclosed in ADR-031).

## Post-hoc: union of rule and screening candidates (ADR-032, `ministral-14b`, test slices, one run)
The obvious next experiment named in ADR-028: the agent verifies the rule hits AND the sources the screening flagged. The
success criterion was committed before any result: pooled test F1 above the hybrid's 0.344 without lowering its recall (0.295).

| Slice | System | Recall | Precision | F1 | FP |
|---|---|---|---|---|---|
| ssh_patator | Hybrid / Union | 1.00 / 1.00 | 0.70 / 0.17 | 0.82 / 0.30 | 6 / 66 |
| bot | Hybrid / Union | 0.12 / 0.32 | 0.36 / 0.18 | 0.18 / 0.23 | 16 / 101 |
| portscan | Hybrid / Union | 0.62 / 0.62 | 0.22 / 0.06 | 0.32 / 0.11 | 18 / 80 |
| **all test slices** | Hybrid | 0.29 | 0.41 | **0.34** | 40 |
| **all test slices** | **Union** | **0.44** | 0.14 | 0.22 | 247 |

**Result: the criterion is not met (F1 0.22 < 0.34); this is a negative result.** The union does what it was meant to do on
recall (pooled 0.44 vs 0.29; Bot detections 23 vs 9 of 73), and the screening-only candidates are where the extra Bot hits
come from. But the verifier confirms most of the busy-but-ordinary hosts it is shown, so false positives rise sixfold
(247 vs 40) and the result lands on the plain volume rule b2 (recall 0.41, F1 0.21, 229 FP) at about four times the hybrid's
tokens (2.3M vs 0.55M). On dev the pattern is the same (recall equal to hybrid, 86 FP vs 18, F1 0.23 vs 0.58).
Reading: with this model the agent's verification step filters rule hits well but cannot reliably reject candidates that
merely look unusual, so widening the candidate set trades precision for recall at a poor rate. It does not show that a
stronger verifier would fail.

## How sure are these numbers? (ADR-033, post-hoc, no new model run)
Intervals come from a paired bootstrap that resamples whole 5-minute windows within each slice (the same windows for every
system), 2000 draws. Pooled test slices:

| System | Precision | Recall | F1 | F1 95% interval |
|---|---|---|---|---|
| B0 rules | 0.27 | 0.29 | 0.28 | 0.20 to 0.36 |
| b2 quantile rule (no LLM) | 0.15 | 0.41 | 0.21 | 0.15 to 0.27 |
| b3 IsolationForest (no LLM) | 0.18 | 0.17 | 0.18 | 0.10 to 0.24 |
| b4 rules AND b2 (no LLM) | 0.50 | 0.20 | 0.29 | 0.21 to 0.35 |
| Agent-led | 0.11 | 0.36 | 0.17 | 0.12 to 0.22 |
| **Hybrid** | 0.41 | 0.29 | **0.34** | 0.24 to 0.44 |
| Union (post-hoc) | 0.14 | 0.44 | 0.22 | 0.15 to 0.28 |

| Difference in F1 | Mean | 95% interval | Share of resamples above 0 |
|---|---|---|---|
| hybrid - B0 | +0.062 | +0.042 to +0.085 | 1.00 |
| hybrid - agent-led | +0.172 | +0.081 to +0.261 | 1.00 |
| hybrid - b4 (no-LLM filter) | +0.056 | -0.022 to +0.135 | 0.91 |
| agent-led - b2 | -0.045 | -0.092 to -0.000 | 0.02 |
| union - hybrid | -0.122 | -0.186 to -0.057 | 0.00 |

What this supports: the hybrid beats the rules it is built on and beats agent-led detection, and the union is worse than the
hybrid; those intervals exclude zero. What it does not: the hybrid's edge over the no-LLM filter b4 (+0.056) has an interval that
includes zero, and agent-led vs the plain rule b2 is borderline (upper end at zero). The intervals describe how much the result
depends on which windows were drawn. They are still narrower than a new attacker or a new day would justify, because the windows
of one attack are correlated and each slice has one attacker.

## Technique naming, read more closely (ADR-034, post-hoc)
Same nine attack-linked incidents of the hybrid system, `ministral-14b`, graded two ways:

| Metric | Result |
|---|---|
| Strict (parent-level match with the label's technique, the frozen headline) | 1 / 9 (SSH-Patator only) |
| Tactic-level (an assessed technique shares an ATT&CK tactic with the key) | 6 / 9 (SSH-Patator 1/1, Bot 5/7, PortScan 0/1) |

The Bot hosts are mostly named with other command-and-control techniques (proxy, data obfuscation, non-standard port, web
service) where the key says Application Layer Protocol T1071; the external port scanner is named Active Scanning (reconnaissance)
where the key says Network Service Discovery. The tactic-level number says the system is usually in the right area while picking
a different technique, which the strict metric hides. It does not say the names are correct: the answer key has one technique per
label, and the model also chose data-exfiltration techniques for two Bot hosts. One run of one model on nine incidents.

A reproducibility bug was fixed while measuring this: the judge's candidate order depended on the arrival order of parallel tool
calls, so re-runs changed the answer. The numbers above are from the fixed code, identical across two runs.

## Fresh data: do the conclusions hold? (ADR-037; never-used attack families and time ranges; one run, frozen prompts)
57 attack-positive (window, source) pairs in 5 slices: Bot (stretch outside the test slice) 24, web attacks 16, DoS 10, DDoS 5,
PortScan (stretch outside the test slice) 2. True positives / false positives per slice:

| Slice (positives) | B0 | b2 | b3 | b4 | Hybrid | Agent-led |
|---|---|---|---|---|---|---|
| bot_fresh_pm (24) | 2 / 17 | 0 / 10 | 0 / 1 | 0 / 1 | 1 / 13 | 3 / 48 |
| portscan_fresh (2) | 0 / 12 | 0 / 24 | 0 / 6 | 0 / 0 | 0 / 11 | not run |
| ddos_fri (5) | 0 / 16 | **5** / 23 | 0 / 8 | 0 / 7 | 0 / 11 | not run |
| dos_wed (10) | 0 / 22 | **9** / 55 | **6** / 18 | 0 / 19 | 0 / 16 | not run |
| web_thu (16) | 0 / 31 | 0 / 65 | 0 / 31 | 0 / 13 | 0 / 19 | not run |
| **pooled** | F1 0.03 | **F1 0.11** | F1 0.09 | F1 0.00 | F1 0.02 | n/a |

Pooled precision / recall / F1: B0 0.02 / 0.04 / 0.03; b2 0.07 / 0.25 / 0.11 (interval 0.08 to 0.14); b3 0.09 / 0.10 / 0.09;
b4 0 / 0 / 0; hybrid 0.01 / 0.02 / 0.02 (1 detection, 70 false positives).

**Reading: the earlier conclusions do not carry over to attacks the rules were not written for.**
- The hybrid, the project's primary system, detects almost nothing here, by construction: rules propose its candidates and none of
  them covers DoS, DDoS or web attacks (B0 has zero recall on those). Its test-slice advantage came from attack types the rules were
  written for. It is a triage layer for a rule set, not a general detector.
- The only thing that found the new volumetric attacks is the plain volume rule b2 (DDoS 5 of 5, DoS 9 of 10) and, partly,
  IsolationForest (DoS 6 of 10). Low-volume web attacks (brute force, XSS, SQL injection from one source) were found by nothing;
  Bot on this unused stretch was found by almost nothing (best: agent-led 3 of 24 with 48 false positives).
- The hybrid and b4 comparison reverses nothing statistically (hybrid - b4 +0.015, interval +0.000 to +0.047) because both are near zero.
- Guardrails kept working on new families: grounding 1.00 on every slice; policy pass rate 0.87 to 0.95 on four of five slices
  (the code rejected actions on protected assets or malformed targets; none reached the simulated environment).

**Not complete:** the agent-led system finished only `bot_fresh_pm` (12 windows) and 8 of 12 `portscan_fresh` windows. The provider
returned "backend out of capacity" for `ministral-14b` on every request for about 45 minutes, including a minimal one, while other
models answered. The remaining windows are not scored. Resume with
`python scripts/run_eval.py fresh --systems agent --no-downstream` (the run is resumable and the finished windows are kept).

**Small:** 57 positives, one attacker per attack family, two PortScan pairs. This supports "the conclusions are not general", not any
precise rate.

## Reproduce
```bash
python -I scripts/fetch_data.py
python scripts/run_eval.py test --systems b0 b1 agent hybrid --out results/test_repro.json   # needs MISTRAL_API_KEY
python scripts/run_cheap.py test                  # post-hoc no-LLM baselines (ADR-031), no API key needed
python scripts/make_final_results.py
```

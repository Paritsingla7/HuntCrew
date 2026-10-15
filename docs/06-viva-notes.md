# 06 — Viva notes

## One-minute summary
HuntCrew replays real network traffic (CIC-IDS2017) one 5-minute window at a time. Code summarises each window
into statistics. A detector agent decides what is suspicious using retrieval over the official MITRE ATT&CK
knowledge base; further agents name the technique, plan a response from official mitigations and write a
report. Code verifies every claim, risky actions need a human, and **code grades the outcome against the
dataset's own labels**, which the system never sees.

## Likely questions
**Why not generate your own logs and handbook?** An evaluation where the same author supplies the data, the
knowledge and the answer key only measures agreement with the author. Everything external here is real and
checksummed (`data-provenance.md`); the few hand-made inputs are listed in `03-architecture.md`.

**Where exactly is RAG used?** In three places: the detector (does this behaviour match a known attacker
behaviour?), the threat-intel step (name the technique; candidates from several hypothesis searches are then
scored against the facts), and the strategist (official ATT&CK mitigations). Every cited ID is checked to
exist and to have been retrieved in that run.

**What is agentic about it?** The detector chooses which sources to inspect and which tools to call; the
intel agent forms competing hypotheses and searches for each; the strategist selects actions under a policy;
a human gate sits before risky actions. Deterministic code surrounds them, on purpose.

**Does the agent beat rules?** Not as a first-pass detector. On the dev slice the agent-led detector missed
the pre-registered bar (recall 0.64 vs 0.93 for rules, 2.7× the false positives), so the primary system is a
hybrid: rules propose, the agent verifies. Pooled over the test slices the hybrid keeps the rules' recall
(0.29) and cuts false positives from 76 to 40 (precision 0.27 → 0.41). `05-evaluation.md` has the tables.

**What does not work?** Technique naming (1 of 9 attack-linked incidents correct) and low-and-slow
beaconing (recall 0.12). Flows carry no payloads or login results, so brute force, flooding and exfiltration
look alike to a 14B-class model.

**How do you know you didn't tune on the test set?** Splits and the gate bar were fixed in `config.yaml`
before any detector result existed (ADR-019). Iteration used the dev slice only. The code was frozen at
`19b8682` and the test slices were run once (ADR-028).

**Why that model?** Larger Mistral models have a request quota of 0 on the key used (measured from response
headers, I-011), so `ministral-14b-latest` is the strongest available. The model is configuration.

**What would you do next?** Union rule and screening candidates before verification (the agent-led screening
saw part of the beaconing that rules missed); evaluate on fresh days or a second dataset; try a stronger
model for the technique-judging step; add payload-bearing logs.

## Numbers to remember
- 2,827,677 flows, 15 labels; test slices: 60 five-minute windows, 95 attack-positive (window, entity) pairs.
- Rules: recall 0.29, precision 0.27, 76 FP. Hybrid: recall 0.29, precision 0.41, 40 FP.
  Agent-led: recall 0.36, precision 0.11, 273 FP. Single prompt: recall 0.03.
- Grounding 1.00, policy pass 1.00, technique naming 1/9.

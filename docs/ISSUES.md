# Issues, risks and open items

Running log. Newest first. `open` items need a decision or a later check; `noted` items are accepted limitations.

| ID | Date | Area | Description | Status |
|---|---|---|---|---|
| I-011 | 2026-10-15 | LLM limits | **`mistral-small*`, `mistral-medium-latest` and `magistral-small-latest` return HTTP 429 with `x-ratelimit-limit-req-minute: 0` on this key**, although the dashboard lists limits for them. Working (measured from response headers): `ministral-3b` 750 req/min, `ministral-8b` 188 req/min, `ministral-14b` 30 req/min (937,500 tokens/min), `open-mistral-nemo` 188 req/min, `codestral` 125 req/min, `mistral-embed` 60 req/min. Default model switched to `ministral-14b-latest` (ADR-024). Worth checking the plan/billing state in the provider console. | open |
| I-010 | 2026-10-15 | Integration | CrewAI adds a `cache_breakpoint` field to messages; Mistral rejects it (HTTP 422 `extra_forbidden`). The LLM middleware strips unsupported prompt-caching hints. | resolved |
| I-009 | 2026-10-15 | Colab | Secret `MISTRAL_API_KEY` verified readable (notebook access on) in a scratch notebook only. The generated submission notebook is a different notebook, so notebook access must be granted again once it is uploaded. | open (P7) |
| I-008 | 2026-10-15 | Tooling | Browser automation: closing a tab timed out once. Check that no stray Colab tab remains open. | open |
| I-007 | 2026-10-15 | Process | GitNexus code-graph analysis skipped for this repository by decision (small codebase). Revisit if the code grows substantially. | noted |
| I-006 | 2026-10-15 | Evaluation | Retrieval smoke set is hand-written, so hit@k is a sanity check, not an independent benchmark. | noted |
| I-005 | 2026-10-15 | Detection | Digest coverage of low-volume attack sources is unmeasured. It will be reported on test slices after the fact and not tuned on. | open (P6) |
| I-004 | 2026-10-15 | Baseline | B0 precision on dev is 0.27 (recall 0.93). Remaining false positives: regular HTTPS to unlisted external hosts; reply traffic of the attack itself. B0 is frozen (ADR-023); a heavily tuned rule set could do better. | noted |
| I-003 | 2026-10-15 | LLM limits | Monthly token quota is not shown on the provider limits page, only per-minute limits. A full evaluation might exhaust an unknown monthly cap. | open |
| I-002 | 2026-10-15 | LLM limits | Dashboard-listed limits (superseded by I-011 measurements): `mistral-small-2603` 20,000 tokens/min, 1 req/s; `mistral-medium-latest` 20,000 tokens/min; `ministral-8b-2512` 625,000 tokens/min, 3.13 req/s; `ministral-14b-2512` 937,500 tokens/min, 0.50 req/s; `ministral-3b-2512` 1,300,000 tokens/min, 12.5 req/s. The detector needs a token-aware throttle; a smaller model may be used for sweeps. | open (P4) |
| I-001 | 2026-10-15 | Data | Flows carry no payload and only minute-resolution timestamps on Tue–Fri, so sub-minute periodicity cannot be measured. | noted |

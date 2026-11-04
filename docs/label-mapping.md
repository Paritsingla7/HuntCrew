# Label → ATT&CK technique mapping

This is one of the few hand-made inputs of the evaluation (see `03-architecture.md`). It is short on
purpose so anyone can audit it. Source of truth in code: `config.yaml → labels.to_technique`.

| Dataset label | Technique | Name | Rationale |
|---|---|---|---|
| `FTP-Patator` | T1110 | Brute Force | Automated password guessing against FTP |
| `SSH-Patator` | T1110 | Brute Force | Automated password guessing against SSH |
| `Bot` | T1071 | Application Layer Protocol | ARES bot checks in with its C2 over HTTP (port 8080) |
| `PortScan` | T1046 | Network Service Discovery | Enumerating open ports/services |
| `BENIGN` | — | — | no technique expected |
| `DoS Hulk`, `DoS GoldenEye`, `DoS slowloris`, `DoS Slowhttptest`, `DDoS` | T1499 | Endpoint Denial of Service | HTTP floods and slow-HTTP attacks exhaust the web service (fresh split only) |
| `Web Attack – Brute Force` | T1110 | Brute Force | Web login guessing (fresh split only) |
| `Web Attack – XSS`, `Web Attack – Sql Injection` | T1190 | Exploit Public-Facing Application | Exploiting a web application (fresh split only) |

The last three rows were added on 2026-11-04 for the fresh split (ADR-037), before any system was run on it. They do not
change the ground truth of the dev and test splits (checked by `tests/test_fresh_split.py`).

Out of scope: Heartbleed and Infiltration (11 and 36 flows in total, too few to grade).

## Matching rule
**Parent-level match.** A truth of `T1110` is satisfied by `T1110` or any sub-technique (`T1110.001`…).
A prediction of `T1110.001` against truth `T1110` is correct; `T1021` against `T1110` is wrong.

## Grading granularity (to be fixed before test results are produced)
Ground truth is evaluated per **(entity, time-window)**: a window×entity is *attack-positive* when it
contains at least a minimum number of attack-labelled flows from that entity. The minimum is set in
`config.yaml` at the start of the evaluation phase and is not changed after seeing results.

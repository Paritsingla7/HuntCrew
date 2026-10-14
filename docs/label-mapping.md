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

Out of scope for now: DoS/DDoS classes, Web Attack classes, Heartbleed, Infiltration.

## Matching rule
**Parent-level match.** A truth of `T1110` is satisfied by `T1110` or any sub-technique (`T1110.001`…).
A prediction of `T1110.001` against truth `T1110` is correct; `T1021` against `T1110` is wrong.

## Grading granularity (to be fixed before test results are produced)
Ground truth is evaluated per **(entity, time-window)**: a window×entity is *attack-positive* when it
contains at least a minimum number of attack-labelled flows from that entity. The minimum is set in
`config.yaml` at the start of the evaluation phase and is not changed after seeing results.

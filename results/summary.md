| Slice | System | Recall | Precision | F1 | FP | Window recall |
|---|---|---|---|---|---|---|
| ssh_patator | B0 rules | 1.00 | 0.41 | 0.58 | 20 | 1.00 |
| ssh_patator | B1 single prompt | 0.00 | 0.00 | 0.00 | 120 | 0.00 |
| ssh_patator | Agent-led | 0.79 | 0.12 | 0.21 | 81 | 0.79 |
| ssh_patator | Hybrid (rules + agent) | 1.00 | 0.70 | 0.82 | 6 | 1.00 |
| bot | B0 rules | 0.12 | 0.24 | 0.16 | 29 | 0.17 |
| bot | B1 single prompt | 0.03 | 0.01 | 0.02 | 148 | 0.08 |
| bot | Agent-led | 0.25 | 0.15 | 0.18 | 105 | 0.46 |
| bot | Hybrid (rules + agent) | 0.12 | 0.36 | 0.18 | 16 | 0.17 |
| portscan | B0 rules | 0.62 | 0.16 | 0.25 | 27 | 0.62 |
| portscan | B1 single prompt | 0.12 | 0.01 | 0.01 | 133 | 0.12 |
| portscan | Agent-led | 0.62 | 0.05 | 0.10 | 87 | 0.62 |
| portscan | Hybrid (rules + agent) | 0.62 | 0.22 | 0.32 | 18 | 0.62 |
| **all test slices** | B0 rules | 0.29 | 0.27 | 0.28 | 76 | |
| **all test slices** | B1 single prompt | 0.03 | 0.01 | 0.01 | 401 | |
| **all test slices** | Agent-led | 0.36 | 0.11 | 0.17 | 273 | |
| **all test slices** | Hybrid (rules + agent) | 0.29 | 0.41 | 0.34 | 40 | |

Post-hoc, no-LLM comparison baselines (ADR-031; same test slices, parameters fixed beforehand):

| Slice | System | Recall | Precision | F1 | FP | Window recall |
|---|---|---|---|---|---|---|
| ssh_patator | b2 quantile outlier rule | 0.86 | 0.13 | 0.22 | 83 | 0.86 |
| ssh_patator | b3 IsolationForest | 0.14 | 0.07 | 0.10 | 25 | 0.14 |
| ssh_patator | b4 B0 rules AND b2 (no-LLM triage filter) | 0.86 | 0.67 | 0.75 | 6 | 0.86 |
| bot | b2 quantile outlier rule | 0.30 | 0.21 | 0.25 | 82 | 0.42 |
| bot | b3 IsolationForest | 0.12 | 0.26 | 0.17 | 26 | 0.29 |
| bot | b4 B0 rules AND b2 (no-LLM triage filter) | 0.03 | 0.29 | 0.05 | 5 | 0.08 |
| portscan | b2 quantile outlier rule | 0.62 | 0.07 | 0.13 | 64 | 0.62 |
| portscan | b3 IsolationForest | 0.62 | 0.20 | 0.30 | 20 | 0.62 |
| portscan | b4 B0 rules AND b2 (no-LLM triage filter) | 0.62 | 0.39 | 0.48 | 8 | 0.62 |
| **all test slices** | b2 quantile outlier rule | 0.41 | 0.15 | 0.21 | 229 | |
| **all test slices** | b3 IsolationForest | 0.17 | 0.18 | 0.18 | 71 | |
| **all test slices** | b4 B0 rules AND b2 (no-LLM triage filter) | 0.20 | 0.50 | 0.29 | 19 | |

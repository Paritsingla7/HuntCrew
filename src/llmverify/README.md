# llmverify

Make an LLM's claims checkable by code. Three small checks, no dependencies, no model calls. They were
extracted from HuntCrew, where each guards an agent's output before anything downstream trusts it.

| Check | Question it answers | Example |
|---|---|---|
| `check_numeric_claims` | Did the model quote numbers that match what my code computed? | `{"flows": 650}` vs the real flow count |
| `ground_ids` + `SearchTrace` | Did it cite only identifiers that exist **and** that it actually retrieved this run? | an ATT&CK technique ID, a CVE, a document ID |
| `ActionGate` | May this proposed action run: is it in the catalog, well-formed, off the protected list, low risk? | `block_ip 203.0.113.9` auto; `isolate_host` needs a human |

```python
from llmverify import ActionGate, SearchTrace, check_numeric_claims, ground_ids

check = check_numeric_claims({"flows": 650, "ports": 9}, {"flows": 652, "ports": 3}, checkable={"flows", "ports"})
check.verified      # {"flows": 650.0}
check.contradicted  # ["ports: claimed 9, actual 3"]
check.ok            # False (and also False when nothing at all could be checked)

kept, dropped = ground_ids(["T1110", "T9999"], known={"T1110"}, retrieved={"T1110"})   # (["T1110"], ["T9999"])

gate = ActionGate({"block_ip": {"risk": "low"}, "isolate_host": {"risk": "high"}}, protected={"10.0.0.1"})
gate.check("isolate_host", "10.0.0.2")   # Decision(status="needs_approval", ...)
```

Design rules: a claim with nothing checkable is **not** ok (it proves nothing); numbers outside the allowed
metric list are never "verified"; a dropped ID is counted, not silently lost, so hallucination rates are measurable.
These checks reduce unverified output reaching a decision. They do not make the model correct.

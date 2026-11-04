"""llmverify: make an LLM's claims checkable by code.

Three small, dependency-free checks, extracted from HuntCrew where each one guards an agent's output:

  * claims    - numbers the model quoted must match numbers your code computed;
  * grounding - identifiers it cited must exist and must have been retrieved in this run;
  * gate      - actions it proposes must be in a catalog, well-formed, off-limits-aware and risk-tiered.

None of them calls a model or knows about security: they take plain values and return plain results.
"""
from .claims import ClaimCheck, check_numeric_claims, numbers_close
from .gate import ActionGate, Decision
from .grounding import SearchTrace, ground_ids

__all__ = ["ActionGate", "ClaimCheck", "Decision", "SearchTrace", "check_numeric_claims", "ground_ids", "numbers_close"]

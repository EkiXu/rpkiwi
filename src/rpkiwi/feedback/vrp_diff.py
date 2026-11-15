from __future__ import annotations

from src.rpkiwi.objective.overclaim_oracle import OracleVerdict, CLASS_NONE, CLASS_ERROR

def is_interesting(verdict: OracleVerdict) -> bool:
    # ERROR is an infrastructure failure, not a finding; NONE is no deviation.
    return verdict.classification not in (CLASS_NONE, CLASS_ERROR)

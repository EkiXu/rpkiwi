from __future__ import annotations

from dataclasses import dataclass, field

from src.rpkiwi.observer.vrp_observer import (
    Observation,
    ValidatorSemantics,
)

CLASS_NONE = "NONE"
CLASS_V1 = "V1"
CLASS_V2 = "V2"
CLASS_V3 = "V3"
# Not a class of finding: the harness or container tooling failed, so the run
# says nothing about the input. Kept distinct from a target crash, which is V3.
CLASS_ERROR = "ERROR"

CRASH_REASON = "target process died while processing the injected input"

@dataclass(frozen=True)
class ClassEvidence:
    classification: str
    reason: str

@dataclass
class Scenario:
    expected_canary_vrps: set[tuple[str, int, int, int]] = field(default_factory=set)
    expected_canary_vaps: set[tuple[int, frozenset[int]]] = field(default_factory=set)
    expected_victim_vrps: set[tuple[str, int, int, int]] = field(default_factory=set)
    expected_victim_vaps: set[tuple[int, frozenset[int]]] = field(default_factory=set)
    published_victim_vrps: set[tuple[str, int, int, int]] = field(default_factory=set)
    published_victim_vaps: set[tuple[int, frozenset[int]]] = field(default_factory=set)

@dataclass
class OracleVerdict:
    classification: str
    reason: str
    evidence: list[str] = field(default_factory=list)
    validator_classes: dict[str, str] = field(default_factory=dict)

def classify_validator(
    semantics: ValidatorSemantics,
    scenario: Scenario,
    validator_name: str,
) -> ClassEvidence:
    from src.rpkiwi.observer.vrp_observer import EXPECT_ASPA, CANARY_VRP_T2
    validator_has_aspa = EXPECT_ASPA.get(validator_name, False)

    canary_t2_arrived = CANARY_VRP_T2 in semantics.canary_zone_vrps

    victim_vrps_ok = semantics.victim_zone_vrps == scenario.expected_victim_vrps
    victim_vaps_ok = (semantics.victim_zone_vaps == scenario.expected_victim_vaps
                      if validator_has_aspa else True)
    victim_intact = victim_vrps_ok and victim_vaps_ok

    unauthorized_vrps = semantics.victim_zone_unauthorized_vrps - scenario.expected_victim_vrps
    unauthorized_vaps = semantics.victim_zone_unauthorized_vaps - scenario.expected_victim_vaps

    if unauthorized_vrps or unauthorized_vaps:
        replayed_vrps = unauthorized_vrps & scenario.published_victim_vrps
        replayed_vaps = unauthorized_vaps & scenario.published_victim_vaps
        if replayed_vrps or replayed_vaps:
            return ClassEvidence(CLASS_V1, "withdrawn victim object reappeared from an unauthorized publisher")
        return ClassEvidence(CLASS_V1, "unauthorized object appeared in victim zone")

    if not canary_t2_arrived and not victim_intact:
        return ClassEvidence(CLASS_V3, "validator failed to process T2 updates (canary T2 ROA absent, victim incomplete)")

    if not victim_intact and canary_t2_arrived:
        return ClassEvidence(CLASS_V2, "victim records missing while canary T2 update arrived (targeted withdrawal)")

    return ClassEvidence(CLASS_NONE, "no semantic deviation from expected state")

def crash_verdict(validator: str) -> OracleVerdict:
    """A target crash denies service for that validator, which is V3.

    The validator produced no output to compare, so this is classified from the
    crash itself rather than from VRP semantics. It stays a candidate until a
    replay from the same T1 baseline reproduces it.
    """
    return OracleVerdict(
        classification=CLASS_V3,
        reason=CRASH_REASON,
        evidence=[f"{validator}: {CRASH_REASON}"],
        validator_classes={validator: CLASS_V3},
    )


def error_verdict(validator: str, detail: str) -> OracleVerdict:
    """Infrastructure or harness failure: the run says nothing about the input."""
    return OracleVerdict(
        classification=CLASS_ERROR,
        reason=f"execution infrastructure failure: {detail}",
        evidence=[f"{validator}: {detail}"],
        validator_classes={validator: CLASS_ERROR},
    )


def evaluate(
    observation: Observation,
    scenario: Scenario,
) -> OracleVerdict:
    validator_classes: dict[str, str] = {}
    evidence: list[str] = []
    non_none: set[str] = set()

    for name, semantics in observation.semantics.items():
        result = classify_validator(semantics, scenario, name)
        validator_classes[name] = result.classification
        if result.classification != CLASS_NONE:
            non_none.add(result.classification)
            evidence.append(f"{name}: {result.reason}")

    if not non_none:
        classification = CLASS_NONE
    elif len(non_none) == 1:
        classification = next(iter(non_none))
    else:
        classification = "MIXED"

    reason = "semantic impact observed" if classification != CLASS_NONE else "no semantic impact observed"
    return OracleVerdict(
        classification=classification,
        reason=reason,
        evidence=evidence,
        validator_classes=validator_classes,
    )

"""Confirm a finding by replaying it from the same T1 baseline (paper §5.4).

A single execution is a discovery, not a finding: the validator state it ran on
carries whatever the previous iteration left behind. This module re-runs the
same input from a restored T1 baseline and keeps the finding only when the
classification reproduces.

Three things are recorded for every attempt and never papered over:
  * the classification and per-validator classes,
  * how each validator's state actually came about (``state_origin``) — a
    warmup fallback is not a T1 replay, and
  * the identity of the publication baseline the attempt started from, so two
    attempts can be shown to have started from the same place.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from src.rpkiwi.executor.state_manager import T1_REPLAY_ORIGINS

PHASE_DISCOVERY = "discovery"
PHASE_REPLAY = "replay"


def publication_fingerprint(build_dir: str | Path) -> str:
    """Identity of the publication trees the validators fetch from.

    Hashes every published file's path and contents, so a replay that silently
    started from a different baseline cannot be reported as the same one.
    """
    root = Path(build_dir) / "publication"
    digest = hashlib.sha256()
    if not root.is_dir():
        return "no-publication"
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        digest.update(str(path.relative_to(root)).encode())
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()[:16]


@dataclass
class Attempt:
    """One injection → T2 → observation round."""
    phase: str
    classification: str
    baseline_id: str
    per_validator: dict[str, str] = field(default_factory=dict)
    state_origins: dict[str, str] = field(default_factory=dict)
    crashed: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    @property
    def replayed_from_t1(self) -> bool:
        """Every validator that reported a class ran from a restored baseline."""
        relevant = [v for v, cls in self.per_validator.items()
                    if cls not in ("ERROR",)]
        if not relevant:
            return False
        return all(self.state_origins.get(v) in T1_REPLAY_ORIGINS for v in relevant)

    def record(self) -> dict:
        return {
            "phase": self.phase,
            "classification": self.classification,
            "baseline_id": self.baseline_id,
            "per_validator": dict(sorted(self.per_validator.items())),
            "state_origins": dict(sorted(self.state_origins.items())),
            "crashed": sorted(self.crashed),
            "replayed_from_t1": self.replayed_from_t1,
            "evidence": list(self.evidence),
        }


@dataclass
class ReplayResult:
    confirmed: bool
    reason: str
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def classification(self) -> str | None:
        return self.attempts[-1].classification if self.attempts else None

    def record(self) -> dict:
        return {"confirmed": self.confirmed, "reason": self.reason,
                "attempts": [a.record() for a in self.attempts]}

    def summary(self) -> str:
        tail = self.attempts[-1] if self.attempts else None
        where = f" ({tail.baseline_id})" if tail else ""
        return f"{'confirmed' if self.confirmed else 'discarded'}: {self.reason}{where}"


def confirm_from_t1(
    discovery: Attempt,
    *,
    restore_t1: Callable[[], str],
    run_once: Callable[[str], Attempt],
    logger: Callable[[str], None] | None = None,
) -> ReplayResult:
    """Replay ``discovery`` from a restored T1 baseline and judge reproducibility.

    ``restore_t1`` must put publication and validator state back to the T1
    baseline and return that baseline's identity. ``run_once`` re-injects the
    same input, advances to T2 and observes, returning the replay attempt.
    Neither callback may be run concurrently with another publication writer.
    """
    logger = logger or (lambda message: None)
    attempts = [discovery]

    if discovery.classification in ("NONE", "ERROR"):
        return ReplayResult(False, f"nothing to confirm: discovery was "
                                   f"{discovery.classification}", attempts)

    baseline_id = restore_t1()
    replay = run_once(baseline_id)
    attempts.append(replay)

    if replay.classification != discovery.classification:
        return ReplayResult(
            False,
            f"not reproducible: {discovery.classification} on discovery, "
            f"{replay.classification} on replay from T1",
            attempts,
        )
    # The aggregate classification string alone is not enough: in
    # parallel/differential mode, DiffVerdict collapses to a single label
    # whenever exactly one DISTINCT non-NONE class exists among all
    # validators (parallel_loop.py:_differential_evaluate, "len(non_none)
    # == 1"), regardless of WHICH validator(s) produced it. Two runs can
    # show the identical aggregate label (e.g. both "V2") while a
    # different validator drove it each time -- that is not the same
    # finding reproducing, it is two unrelated single-validator blips that
    # happen to share a class name. Require the same set of validators to
    # be the ones actually reporting a non-NONE, non-ERROR class, with the
    # same individual classification each.
    def _interesting(per_validator: dict[str, str]) -> dict[str, str]:
        return {v: cls for v, cls in per_validator.items() if cls not in ("NONE", "ERROR")}

    discovery_interesting = _interesting(discovery.per_validator)
    replay_interesting = _interesting(replay.per_validator)
    if discovery_interesting != replay_interesting:
        return ReplayResult(
            False,
            f"not reproducible: same aggregate classification "
            f"({discovery.classification}) but different validators behind it "
            f"(discovery: {discovery_interesting}, replay: {replay_interesting})",
            attempts,
        )
    if not replay.replayed_from_t1:
        origins = dict(sorted(replay.state_origins.items()))
        return ReplayResult(
            False,
            f"replay did not run from the T1 baseline (state origins {origins})",
            attempts,
        )
    if replay.baseline_id != discovery.baseline_id:
        return ReplayResult(
            False,
            f"replay started from a different publication baseline "
            f"({discovery.baseline_id} then {replay.baseline_id})",
            attempts,
        )
    return ReplayResult(
        True,
        f"{replay.classification} reproduced from T1 baseline {replay.baseline_id}",
        attempts,
    )

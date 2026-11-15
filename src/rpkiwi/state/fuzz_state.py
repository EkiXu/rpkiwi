from __future__ import annotations

import time
from dataclasses import dataclass, field

@dataclass
class Finding:
    iteration: int
    classification: str
    mutation_name: str
    mutation_description: str
    evidence: list[str]
    corpus_path: str | None = None
    # §5.4 replay confirmation: a finding is a candidate until a replay from the
    # same T1 baseline reproduces it. None means confirmation was not attempted.
    confirmed: bool | None = None
    replay: dict | None = None

@dataclass
class FuzzState:
    total_iterations: int = 0
    findings: list[Finding] = field(default_factory=list)
    classifications: dict[str, int] = field(default_factory=lambda: {
        "NONE": 0, "V1": 0, "V2": 0, "V3": 0, "MIXED": 0, "ERROR": 0,
    })
    start_time: float = field(default_factory=time.monotonic)
    errors: int = 0
    vrp_divergences: int = 0
    # Discoveries that did not reproduce on replay from T1 (paper §5.4): kept
    # separate so an unconfirmed candidate is never counted as a finding.
    discarded_unconfirmed: int = 0

    def record(self, classification: str) -> None:
        self.total_iterations += 1
        if classification in self.classifications:
            self.classifications[classification] += 1
        else:
            self.classifications[classification] = 1

    def record_error(self) -> None:
        self.total_iterations += 1
        self.errors += 1
        self.classifications["ERROR"] += 1

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def record_discarded(self) -> None:
        self.discarded_unconfirmed += 1

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.start_time

    @property
    def iterations_per_second(self) -> float:
        e = self.elapsed
        return self.total_iterations / e if e > 0 else 0.0

    def summary(self) -> str:
        lines = [
            f"iterations: {self.total_iterations}",
            f"elapsed: {self.elapsed:.1f}s ({self.iterations_per_second:.2f} it/s)",
            f"findings: {len(self.findings)}",
            f"discarded (unconfirmed on replay): {self.discarded_unconfirmed}",
            f"errors: {self.errors}",
            f"classes: {dict(self.classifications)}",
            f"vrp_divergences: {self.vrp_divergences}",
        ]
        return "\n".join(lines)

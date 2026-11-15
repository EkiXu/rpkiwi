from __future__ import annotations

from typing import Callable

from src.rpkiwi.config import RPKIConfig
from src.rpkiwi.corpus.on_disk import OnDiskCorpus
from src.rpkiwi.input.generator import generate
from src.rpkiwi.input.test_input import TestInput
from src.rpkiwi.mutator import mutate as mutate_test_input

ANNEAL_INTERVAL = 5
DECAY_FACTOR = 0.8

class FuzzScheduler:
    def __init__(
        self,
        corpus: OnDiskCorpus,
        config: RPKIConfig,
        *,
        logger: Callable[[str], None] | None = None,
    ):
        self._corpus = corpus
        self._config = config
        self._logger = logger or (lambda m: None)

    def next(self, otype: str) -> TestInput:
        entry = self._corpus.pop(otype)
        if entry is not None:
            return entry
        fresh = generate(otype, self._config)
        self._corpus.enqueue(fresh, tags={"source": "generator"})
        return fresh

    def mutate(self, seed: TestInput) -> TestInput:
        return mutate_test_input(seed, self._config)

    def feedback(
        self,
        seed: TestInput,
        mutated: TestInput,
        interesting: bool,
        *,
        verdict_class: str = "",
        iteration: int = 0,
    ) -> None:
        if interesting:
            seed.metadata["fuzz_count"] = 0
            self._corpus.enqueue(mutated, tags={
                "source": "mutation",
                "verdict": verdict_class,
                "iteration": iteration,
            })
            return

        fc = seed.metadata.get("fuzz_count", 0) + 1
        seed.metadata["fuzz_count"] = fc

        energy = seed.metadata.get("mutate_energy")
        if energy and fc % ANNEAL_INTERVAL == 0:
            seed.metadata["mutate_energy"] = {
                k: round(v * DECAY_FACTOR, 3) for k, v in energy.items()
            }
            self._logger(f"  [scheduler] energy decayed (fuzz_count={fc})")

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from src.rpkiwi.config import RPKIConfig
from src.rpkiwi.input.generator import generate
from src.rpkiwi.input.scaffold import PPScaffold, detect_aspa
from src.rpkiwi.executor.docker_oneshot import DockerOneshotExecutor
from src.rpkiwi.executor.state_manager import VALIDATOR_STATE_MODES
from src.rpkiwi.observer.vrp_observer import (
    collect_validator_observations,
    EXPECT_ASPA,
    CANARY_VRP, CANARY_VRP_T2, VICTIM_VRP_A, VICTIM_VRP_B, VICTIM_VRP_C,
    CANARY_ASPA, VICTIM_ASPA,
)
from src.rpkiwi.objective.overclaim_oracle import (
    evaluate, Scenario, CLASS_NONE, crash_verdict, error_verdict,
)
from src.rpkiwi.corpus.on_disk import OnDiskCorpus
from src.rpkiwi.scheduler import FuzzScheduler
from src.rpkiwi.state.fuzz_state import FuzzState, Finding
from src.rpkiwi.feedback.vrp_diff import is_interesting
from src.rpkiwi.replay import Attempt, PHASE_DISCOVERY, PHASE_REPLAY, confirm_from_t1, publication_fingerprint
from src.rpkiwi.loop import (
    _warmup_checkpoint, _checkpoint_lock_valid, ALL_OBJECT_TYPES,
)

PARALLEL_VALIDATORS = ["routinator", "cfrpki", "rpki-client", "fort-validator", "rpki-validator-3", "rpstir2", "rpki-prover"]

REFRESH_INTERVALS = {
    "routinator": 10.0, "cfrpki": 10.0, "rpki-client": 20.0,
    "fort-validator": 20.0, "rpki-validator-3": 30.0, "rpstir2": 45.0, "rpki-prover": 30.0,
}

@dataclass
class DiffVerdict:
    classification: str
    interesting: bool
    per_validator: dict[str, str] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    has_vrp_divergence: bool = False
    state_origins: dict[str, str] = field(default_factory=dict)
    crashed: list[str] = field(default_factory=list)

    @property
    def reason(self) -> str:
        return f"differential: {self.per_validator}"

    @property
    def validator_classes(self) -> dict[str, str]:
        return self.per_validator

def _execute_observe_one(
    validator: str,
    executor: DockerOneshotExecutor,
    scenario: Scenario,
    logger: Callable[[str], None],
) -> tuple[str, str, list[str], frozenset | None, str]:
    """Run one validator and classify it.

    Returns (validator, classification, evidence, fingerprint, state_origin).
    A target crash is classified V3 (service denied) rather than discarded as an
    infrastructure ERROR; only harness/container failures are ERROR.
    """
    try:
        exec_result = executor.execute()
        origin = exec_result.state_origin
        if not exec_result.success and exec_result.returncode == -1:
            verdict = error_verdict(validator, "execution error")
            return validator, verdict.classification, verdict.evidence, None, origin
        if exec_result.target_crashed:
            verdict = crash_verdict(validator)
            return validator, verdict.classification, verdict.evidence, None, origin
        obs = collect_validator_observations([validator], logger=logger)
        verdict = evaluate(obs, scenario)
        sem = obs.semantics.get(validator)
        fp = frozenset(
            sem.canary_zone_vrps | sem.victim_zone_vrps | sem.attacker_vrps
            | sem.canary_zone_vaps | sem.victim_zone_vaps | sem.attacker_vaps
        ) if sem else None
        return validator, verdict.classification, verdict.evidence, fp, origin
    except Exception as exc:
        verdict = error_verdict(validator, str(exc))
        return validator, verdict.classification, verdict.evidence, None, "warmup"

def _check_vrp_divergence(
    results: dict[str, tuple[str, list[str], frozenset | None]],
) -> tuple[bool, list[str]]:
    fps = {v: fp for v, (_, _, fp) in results.items() if fp is not None}
    unique_fps = set(fps.values())
    if len(unique_fps) <= 1:
        return False, []
    counts = {v: len(fp) for v, fp in fps.items()}
    majority = max(set(counts.values()), key=list(counts.values()).count)
    detail = []
    for v in sorted(fps):
        c = counts[v]
        if c == majority:
            detail.append(f"{v}:NONE({c})")
        elif c < majority:
            detail.append(f"{v}:FEWER({c})")
        else:
            detail.append(f"{v}:MORE({c})")
    return True, [f"VRP output divergence: {'; '.join(detail)}"]

def _differential_evaluate(
    results: dict[str, tuple[str, list[str], frozenset | None]],
    *,
    no_differential: bool = False,
    state_origins: dict[str, str] | None = None,
    crashed: list[str] | None = None,
) -> DiffVerdict:
    per_validator = {v: cls for v, (cls, _, _) in results.items()}
    all_evidence = []
    for v, (cls, ev, _) in results.items():
        all_evidence.extend(ev)

    classes = set(per_validator.values()) - {"ERROR"}
    has_divergence, div_evidence = _check_vrp_divergence(results)
    origins = state_origins or {}
    crashed = crashed or []

    if not classes:
        return DiffVerdict("NONE", interesting=False, per_validator=per_validator,
                           has_vrp_divergence=has_divergence,
                           state_origins=origins, crashed=crashed)

    non_none = classes - {"NONE"}
    if non_none:
        if len(non_none) == 1:
            cls = next(iter(non_none))
            return DiffVerdict(cls, interesting=True,
                               per_validator=per_validator, evidence=all_evidence,
                               has_vrp_divergence=has_divergence,
                               state_origins=origins, crashed=crashed)
        label = "MIXED" if no_differential else "DIFFERENTIAL"
        return DiffVerdict(label, interesting=True,
                           per_validator=per_validator, evidence=all_evidence,
                           has_vrp_divergence=True,
                           state_origins=origins, crashed=crashed)

    if has_divergence:
        all_evidence.extend(div_evidence)
        if no_differential:
            return DiffVerdict("NONE", interesting=False, per_validator=per_validator,
                               evidence=all_evidence, has_vrp_divergence=True,
                               state_origins=origins, crashed=crashed)
        return DiffVerdict("DIFFERENTIAL", interesting=True,
                           per_validator=per_validator, evidence=all_evidence,
                           has_vrp_divergence=True,
                           state_origins=origins, crashed=crashed)

    return DiffVerdict("NONE", interesting=False, per_validator=per_validator,
                       has_vrp_divergence=False,
                       state_origins=origins, crashed=crashed)

def _run_round(
    mutated_input,
    scaffold: PPScaffold,
    executors: dict[str, DockerOneshotExecutor],
    active: list[str],
    scenario: Scenario,
    *,
    no_differential: bool,
    logger: Callable[[str], None],
) -> DiffVerdict:
    """One injection round: scaffold the input, switch to T2, observe all.

    Each validator's executor restores its own T1 baseline before injection, so
    the round starts from the recorded baseline rather than the residue of the
    previous iteration.
    """
    scaffold.scaffold(mutated_input)
    scaffold.switch_scenario("t2")

    results: dict[str, tuple[str, list[str], frozenset | None]] = {}
    origins: dict[str, str] = {}
    crashed: list[str] = []
    with ThreadPoolExecutor(max_workers=len(active)) as pool:
        futures = {
            pool.submit(_execute_observe_one, v, executors[v], scenario, logger): v
            for v in active
        }
        for f in as_completed(futures):
            v_name, cls, ev, fp, origin = f.result()
            results[v_name] = (cls, ev, fp)
            origins[v_name] = origin
            if executors[v_name].target_crashed:
                crashed.append(v_name)

    return _differential_evaluate(
        results, no_differential=no_differential,
        state_origins=origins, crashed=crashed,
    )


def _attempt_from(phase: str, verdict: DiffVerdict, baseline_id: str) -> Attempt:
    return Attempt(
        phase=phase,
        classification=verdict.classification,
        baseline_id=baseline_id,
        per_validator=dict(verdict.per_validator),
        state_origins=dict(verdict.state_origins),
        crashed=list(verdict.crashed),
        evidence=list(verdict.evidence),
    )


def run_parallel_fuzz_loop(
    config: RPKIConfig,
    *,
    object_type: str = "ROA",
    iterations: int = 100,
    corpus_dir: str = "corpus",
    logger: Callable[[str], None] | None = None,
    no_aspa: bool = False,
    debug: bool = False,
    no_differential: bool = False,
    no_feedback: bool = False,
    initial_seed_folder: str | None = None,
) -> FuzzState:
    logger = logger or print
    state = FuzzState()
    corpus = OnDiskCorpus(corpus_dir, debug=debug, log=logger)

    build_has_aspa = detect_aspa(config.build_dir)
    if not build_has_aspa:
        no_aspa = True

    scaffold = PPScaffold(config, exclude_asa=no_aspa)

    otype = object_type.upper()
    if otype not in ALL_OBJECT_TYPES:
        logger(f"[!] unknown object type, falling back to ROA")
        otype = "ROA"

    if initial_seed_folder:
        from pathlib import Path
        seed_dir = Path(initial_seed_folder)
        if seed_dir.is_dir():
            loaded = corpus.load_initial_seeds(seed_dir, config)
            loaded = [s for s in loaded if s.object_type == otype]
            for s in loaded:
                corpus.enqueue(s, tags={"source": "initial_seed"})
            logger(f"[*] loaded {len(loaded)} {otype} initial seeds from {seed_dir}")

    initial_test_input = generate(otype, config)
    corpus.enqueue(initial_test_input, tags={"source": "generator"})
    scheduler = FuzzScheduler(corpus, config, logger=logger)

    if no_feedback:
        logger(f"[*] ALL corpus feedback DISABLED — pure random mutation baseline")
    elif no_differential:
        logger(f"[*] differential feedback DISABLED — only per-validator V1/V2/V3 drive corpus admission")

    canary_vaps = set() if no_aspa else {CANARY_ASPA}
    victim_vaps = set() if no_aspa else {VICTIM_ASPA}
    published_vaps = set() if no_aspa else {VICTIM_ASPA}
    scenario = Scenario(
        expected_canary_vrps={CANARY_VRP, CANARY_VRP_T2},
        expected_canary_vaps=canary_vaps,
        expected_victim_vrps={VICTIM_VRP_B, VICTIM_VRP_C},
        expected_victim_vaps=victim_vaps,
        published_victim_vrps={VICTIM_VRP_A},
        published_victim_vaps=published_vaps,
    )

    executors: dict[str, DockerOneshotExecutor] = {}
    for v in PARALLEL_VALIDATORS:
        logger(f"\n[*] ===== warmup: {v} =====")
        refresh = REFRESH_INTERVALS.get(v, 35.0)
        exe = DockerOneshotExecutor(validator=v, logger=logger, refresh_interval=refresh)
        try:
            _warmup_checkpoint(config, scaffold, exe, v, no_aspa, logger)
            executors[v] = exe
            logger(f"[+] {v} ready")
        except Exception as exc:
            logger(f"[!] {v} warmup failed: {exc} — skipping")

    active = list(executors.keys())
    if not active:
        raise RuntimeError("No validators passed warmup")
    logger(f"\n[*] {len(active)} validators ready: {', '.join(active)}")

    dry_run_seeds = []
    if initial_seed_folder:
        from pathlib import Path as _Path
        _sd = _Path(initial_seed_folder)
        if _sd.is_dir():
            _all = corpus.load_initial_seeds(_sd, config)
            dry_run_seeds = [s for s in _all if s.object_type == otype]
        if dry_run_seeds:
            logger(f"[*] seed dry-run: executing {len(dry_run_seeds)} {otype} seed(s) without mutation...")
            for idx, seed_input in enumerate(dry_run_seeds):
                seed_name = seed_input.metadata.get("ir_name", seed_input.metadata.get("source", f"seed-{idx}"))
                logger(f"  [dry-run {idx+1}/{len(dry_run_seeds)}] {seed_name} ({len(seed_input.data)} bytes)")
                try:
                    baseline_id = publication_fingerprint(config.build_dir)
                    diff = _run_round(seed_input, scaffold, executors, active, scenario,
                                      no_differential=no_differential, logger=logger)
                    state.record(diff.classification)
                    if diff.has_vrp_divergence:
                        state.vrp_divergences += 1

                    if diff.interesting:
                        tags = " ".join(f"{v}={c}" for v, c in sorted(diff.per_validator.items()))
                        discovery = _attempt_from(PHASE_DISCOVERY, diff, baseline_id)

                        # A dry-run execution is not a finding on its own: the
                        # seed must still reproduce from a restored T1 baseline.
                        def _restore_t1() -> str:
                            scaffold.switch_scenario("t1")
                            scaffold.restore_baseline()
                            return publication_fingerprint(config.build_dir)

                        def _replay(bid: str, _seed=seed_input) -> Attempt:
                            v = _run_round(_seed, scaffold, executors, active, scenario,
                                           no_differential=no_differential, logger=logger)
                            return _attempt_from(PHASE_REPLAY, v, bid)

                        replay = confirm_from_t1(
                            discovery, restore_t1=_restore_t1, run_once=_replay, logger=logger)
                        if replay.confirmed:
                            finding = Finding(
                                iteration=0,
                                classification=diff.classification,
                                mutation_name=f"ir_seed:{seed_name}",
                                mutation_description=f"IR seed executed as-is [{tags}]",
                                evidence=diff.evidence,
                                confirmed=True,
                                replay=replay.record(),
                            )
                            finding.corpus_path = corpus.save_solution(seed_input, finding, diff)
                            state.add_finding(finding)
                            logger(f"  [dry-run {idx+1}] >>> CONFIRMED {diff.classification}: {tags}")
                        else:
                            state.record_discarded()
                            logger(f"  [dry-run {idx+1}] discovery not confirmed: {replay.summary()}")
                    else:
                        logger(f"  [dry-run {idx+1}] NONE")
                except Exception as exc:
                    logger(f"  [dry-run {idx+1}] error: {exc}")
                finally:
                    scaffold.switch_scenario("t1")
                    scaffold.restore_baseline()
                    for v in active:
                        try:
                            executors[v].stop_container()
                        except Exception:
                            pass

    logger(f"[*] starting parallel fuzz loop: {iterations} iterations × {len(active)} validators")

    for i in range(1, iterations + 1):
        seed = scheduler.next(otype)
        mutated_input = scheduler.mutate(seed)
        mut_name = mutated_input.metadata.get("mutation_name", "unknown")
        mut_desc = mutated_input.metadata.get("mutation_description", "")

        logger(f"  [{i}] {mut_name} -- {mut_desc}")

        try:
            baseline_id = publication_fingerprint(config.build_dir)
            diff = _run_round(mutated_input, scaffold, executors, active, scenario,
                              no_differential=no_differential, logger=logger)
            state.record(diff.classification)
            if diff.has_vrp_divergence:
                state.vrp_divergences += 1

            tags = " ".join(f"{v}={c}" for v, c in sorted(diff.per_validator.items()))
            if diff.interesting:
                discovery = _attempt_from(PHASE_DISCOVERY, diff, baseline_id)

                # §5.4: a single run is a discovery. Restore the T1 baseline and
                # replay the same input; keep the finding only if it reproduces.
                def _restore_t1() -> str:
                    scaffold.switch_scenario("t1")
                    scaffold.restore_baseline()
                    return publication_fingerprint(config.build_dir)

                def _replay(bid: str) -> Attempt:
                    v = _run_round(mutated_input, scaffold, executors, active, scenario,
                                   no_differential=no_differential, logger=logger)
                    return _attempt_from(PHASE_REPLAY, v, bid)

                replay = confirm_from_t1(
                    discovery, restore_t1=_restore_t1, run_once=_replay, logger=logger)

                if replay.confirmed:
                    finding = Finding(
                        iteration=i,
                        classification=diff.classification,
                        mutation_name=mut_name,
                        mutation_description=f"{mut_desc} [{tags}]",
                        evidence=diff.evidence,
                        confirmed=True,
                        replay=replay.record(),
                    )
                    finding.corpus_path = corpus.save_solution(mutated_input, finding, diff)
                    state.add_finding(finding)
                    logger(f"  [{i}] >>> CONFIRMED {diff.classification}: {tags} — {replay.summary()}")
                else:
                    state.record_discarded()
                    logger(f"  [{i}] discovery {diff.classification} NOT confirmed: {replay.summary()}")
            elif diff.has_vrp_divergence:
                logger(f"  [{i}] NONE (VRP divergence detected but not used for feedback)")
            else:
                logger(f"  [{i}] NONE")

            scheduler.feedback(
                seed, mutated_input, diff.interesting and not no_feedback,
                verdict_class=diff.classification, iteration=i,
            )

        except Exception as exc:
            logger(f"  [{i}] error: {exc}")
            state.record_error()
        finally:
            scaffold.switch_scenario("t1")
            for v in active:
                try:
                    executors[v].stop_container()
                except Exception:
                    pass

        if i % 5 == 0 or i == iterations:
            logger(f"  [{i}/{iterations}] {state.iterations_per_second:.2f} it/s | findings: {len(state.findings)}")

    scaffold.switch_scenario("t0")
    logger(f"\n[*] parallel fuzz complete\n{state.summary()}")
    return state

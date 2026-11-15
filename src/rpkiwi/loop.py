from __future__ import annotations

import hashlib
import json
import random
import time
from pathlib import Path
from typing import Callable

from src.rpkiwi.config import RPKIConfig
from src.rpkiwi.input.test_input import TestInput
from src.rpkiwi.input.generator import generate
from src.rpkiwi.input.scaffold import PPScaffold, detect_aspa
from src.rpkiwi.input.utils import compute_sha256
from src.rpkiwi.executor.docker_oneshot import (
    DockerOneshotExecutor,
    ValidatorWithdrawalError,
)
from src.rpkiwi.executor.state_manager import VALIDATOR_STATE_MODES
from src.rpkiwi.observer.vrp_observer import (
    collect_validator_observations,
    run_baseline_check,
    run_warmup_baseline_check,
    EXPECT_ASPA,
    CANARY_VRP,
    CANARY_VRP_T2,
    VICTIM_VRP_A,
    VICTIM_VRP_B,
    VICTIM_VRP_C,
    ATTACKER_VRP,
    CANARY_ASPA,
    VICTIM_ASPA,
    ATTACKER_ASPA,
)
from src.rpkiwi.objective.overclaim_oracle import (
    evaluate,
    Scenario,
    CLASS_NONE,
    CLASS_ERROR,
    crash_verdict,
    error_verdict,
)
from src.rpkiwi.mutator import mutate as mutate_test_input
from src.rpkiwi.feedback.vrp_diff import is_interesting
from src.rpkiwi.replay import (
    Attempt, PHASE_DISCOVERY, PHASE_REPLAY, confirm_from_t1, publication_fingerprint,
)
from src.rpkiwi.scheduler import FuzzScheduler
from src.rpkiwi.corpus.on_disk import OnDiskCorpus
from src.rpkiwi.state.fuzz_state import FuzzState, Finding

CMS_TYPES = {"ROA", "MFT", "ASPA"}
X509_TYPES = {"CRL", "CER"}
XML_TYPES = {"SNAPSHOT", "NOTIFICATION", "DELTA"}

ALL_OBJECT_TYPES = CMS_TYPES | X509_TYPES | XML_TYPES

def _checkpoint_lock_path(build_dir: str, validator: str) -> Path:
    return Path(build_dir) / ".checkpoint-locks" / f"{validator}.lock"

def _checkpoint_lock_valid(build_dir: str, validator: str) -> bool:
    lock_path = _checkpoint_lock_path(build_dir, validator)
    if not lock_path.exists():
        return False
    try:
        lock = json.loads(lock_path.read_text())
    except (json.JSONDecodeError, OSError):
        return False
    tal_path = Path(build_dir) / "identity" / "ta" / "myta.tal"
    if not tal_path.exists():
        return False
    current_hash = hashlib.sha256(tal_path.read_bytes()).hexdigest()
    manifest_path = Path(build_dir) / ".manifest.json"
    if not manifest_path.exists():
        return False
    try:
        manifest = json.loads(manifest_path.read_text())
    except (json.JSONDecodeError, OSError):
        return False
    return (lock.get("tal_hash") == current_hash
            and lock.get("with_aspa") == manifest.get("with_aspa", True))

def _write_checkpoint_lock(build_dir: str, validator: str, t2_calibration: float = 0) -> None:
    tal_path = Path(build_dir) / "identity" / "ta" / "myta.tal"
    tal_hash = hashlib.sha256(tal_path.read_bytes()).hexdigest()
    manifest_path = Path(build_dir) / ".manifest.json"
    with_aspa = True
    if manifest_path.exists():
        try:
            with_aspa = json.loads(manifest_path.read_text()).get("with_aspa", True)
        except (json.JSONDecodeError, OSError):
            pass
    lock_path = _checkpoint_lock_path(build_dir, validator)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps({
        "tal_hash": tal_hash,
        "timestamp": int(time.time()),
        "with_aspa": with_aspa,
        "t2_calibration": t2_calibration,
    }))

def _warmup_checkpoint(
    config: RPKIConfig,
    scaffold: PPScaffold,
    executor: DockerOneshotExecutor,
    validator: str,
    no_aspa: bool,
    logger: Callable[[str], None],
    mode_override: str | None = None,
) -> None:
    if _checkpoint_lock_valid(config.build_dir, validator):
        logger("[+] checkpoint lock valid — skipping warmup")
        executor._has_checkpoint = True
        lock_path = _checkpoint_lock_path(config.build_dir, validator)
        try:
            lock_data = json.loads(lock_path.read_text())
            t2_cal = lock_data.get("t2_calibration", 0)
            if t2_cal > 0:
                executor._state._t2_calibration = t2_cal
                logger(f"  T2 calibration from lock: {t2_cal:.1f}s")
        except Exception:
            pass
        return

    executor.start_attacker_pp()
    time.sleep(2)

    scaffold.restore_baseline()
    scaffold.switch_scenario("t0")
    logger("[*] applying T0 (victim + canary + attacker baseline)...")

    t0_vrps = {CANARY_VRP, ATTACKER_VRP, VICTIM_VRP_A}
    logger("[*] warmup: waiting for T0 VRPs (canary + attacker + victim baseline)...")

    warmup_ok = False
    for attempt in range(1, 3):
        exec_result = executor.execute(force_restart=(attempt == 1))
        if not exec_result.success:
            logger(f"  warmup attempt {attempt}/3: execution failed, waiting 10s...")
            time.sleep(10)
            continue
        _, failures = run_warmup_baseline_check([validator], expected_vrps=t0_vrps, logger=logger)
        if not failures:
            logger(f"[+] T0 warmup passed (attempt {attempt})")
            warmup_ok = True
            break
        for f in failures:
            logger(f"  warmup attempt {attempt}/3: {f}")
        if attempt < 20:
            time.sleep(10)
    if not warmup_ok:
        raise RuntimeError("T0 warmup never stabilized after 20 attempts -- aborting")

    logger("[*] switching victim to T1 (ROA-A withdrawn)...")
    scaffold.switch_scenario("t1")

    executor._state.prepare_for_t1()

    logger("[*] waiting for validator to pick up T1 via RRDP delta...")

    def _t1_reflected() -> bool:
        obs = collect_validator_observations([validator], logger=logger)
        sem = obs.semantics.get(validator)
        if sem is None:
            return False
        return (CANARY_VRP in sem.canary_vrps
                and ATTACKER_VRP in sem.attacker_vrps
                and VICTIM_VRP_A not in sem.victim_zone_vrps
                and VICTIM_VRP_B in sem.victim_zone_vrps)

    try:
        executor.wait_for_withdrawal(_t1_reflected, timeout=300.0, max_refreshes=6)
        logger("[+] T1 verified: ROA-A withdrawn, ROA-B + attacker present")
    except (ValidatorWithdrawalError, TimeoutError) as e:
        logger(f"[!] T1 withdrawal not reflected: {e}")
        raise RuntimeError(f"T1 withdrawal failed: {e}")

    # mode_override must take precedence over the validator's default mode
    # here too -- it already does for which StateManager subclass gets
    # constructed (DockerOneshotExecutor's mode_override), but this second,
    # independent lookup used to ignore it, so e.g. --mode hot on a
    # CRIU-default validator would still try to CRIU-checkpoint a
    # HotStateManager instance (a silent no-op, not an error, but not what
    # --mode hot asked for either). Found 2026-11-10 while diagnosing why
    # CRIU restore does not propagate T2 content for daemon-style validators.
    use_criu = (mode_override or VALIDATOR_STATE_MODES.get(validator, "hot")) == "criu"

    if use_criu:
        logger("[*] creating CRIU checkpoint (container will stop)...")
        checkpoint_ok = False
        for ckpt_attempt in range(1, 4):
            if executor.create_baseline_checkpoint():
                logger("[+] checkpoint created")
                checkpoint_ok = True
                break
            logger(f"  checkpoint attempt {ckpt_attempt}/3 failed, waiting 5s...")
            time.sleep(5)
        if not checkpoint_ok:
            logger("[!] checkpoint creation failed -- falling back to hot mode")
    else:
        logger("[*] creating filesystem snapshot (snapshot_restart mode)...")
        checkpoint_ok = executor.create_baseline_snapshot()
        if checkpoint_ok:
            logger("[+] filesystem snapshot created")

    if checkpoint_ok:
        logger("[+] checkpoint created")

    logger("[*] T2 calibration: switching victim to T2 and measuring refresh time...")
    scaffold.switch_scenario("t2")
    t2_start = time.monotonic()

    exec_result = executor.execute()

    def _t2_reflected() -> bool:
        obs = collect_validator_observations([validator], logger=logger)
        sem = obs.semantics.get(validator)
        if sem is None:
            return False
        return (CANARY_VRP in sem.canary_vrps
                and CANARY_VRP_T2 in sem.canary_zone_vrps
                and VICTIM_VRP_B in sem.victim_zone_vrps
                and VICTIM_VRP_C in sem.victim_zone_vrps)

    t2_time = None
    for _ in range(30):
        time.sleep(5)
        if _t2_reflected():
            t2_time = time.monotonic() - t2_start
            break

    if t2_time is not None:
        logger(f"[+] T2 calibrated: ROA-C appeared in {t2_time:.1f}s")
        executor._state._t2_calibration = t2_time * 2
    else:
        logger(f"[!] T2 calibration failed: ROA-C did not appear in 150s, using default timeout")
        executor._state._t2_calibration = executor._refresh_interval

    scaffold.switch_scenario("t1")
    if checkpoint_ok:
        executor.stop_container()

    if checkpoint_ok:
        t2_cal = getattr(executor._state, '_t2_calibration', 0)
        _write_checkpoint_lock(config.build_dir, validator, t2_calibration=t2_cal)
        logger(f"[+] checkpoint lock written (T2 calibration: {t2_cal:.1f}s)")

def _warmup_default(
    executor: DockerOneshotExecutor,
    scaffold: PPScaffold,
    config: RPKIConfig,
    validator: str,
    skip_baseline: bool,
    logger: Callable[[str], None],
) -> None:
    if not skip_baseline:
        logger("[*] running baseline check (will retry up to 10 times)...")
        baseline_ok = False
        for attempt in range(1, 11):
            exec_result = executor.execute(force_restart=(attempt == 1))
            if not exec_result.success:
                logger(f"  baseline attempt {attempt}/10: execution failed, waiting 10s...")
                time.sleep(10)
                continue
            _, failures = run_baseline_check([validator], logger=logger)
            if not failures:
                logger(f"[+] baseline check passed (attempt {attempt})")
                baseline_ok = True
                break
            for f in failures:
                logger(f"  baseline attempt {attempt}/10: {f}")
            if attempt < 10:
                time.sleep(10)
        if not baseline_ok:
            raise RuntimeError("Baseline never stabilized after 10 attempts (100s) -- aborting")

    logger("[*] capturing baseline snapshot...")
    scaffold.save_baseline()

    logger("[*] switching victim to T1 from disk...")
    scaffold.switch_scenario("t1")
    executor.execute(force_restart=True)

def run_fuzz_loop(
    config: RPKIConfig,
    *,
    object_type: str = "ROA",
    validator: str = "cfrpki",
    iterations: int = 100,
    corpus_dir: str = "corpus",
    logger: Callable[[str], None] | None = None,
    settle_seconds: float = 2.0,
    skip_baseline: bool = False,
    no_aspa: bool = False,
    initial_seed_folder: str | None = None,
    debug: bool = False,
    mode_override: str | None = None,
) -> FuzzState:
    logger = logger or print

    state = FuzzState()
    corpus = OnDiskCorpus(corpus_dir, debug=debug, log=logger)

    build_has_aspa = detect_aspa(config.build_dir)
    if not build_has_aspa or not EXPECT_ASPA.get(validator, False):
        no_aspa = True

    scaffold = PPScaffold(config, exclude_asa=no_aspa)
    refresh = {"cfrpki": 10.0, "fort-validator": 20.0, "rpki-prover": 30.0, "rpki-client": 20.0, "rpki-validator-3": 30.0, "routinator": 10.0, "rpstir2": 45.0}.get(validator, 35.0)
    executor = DockerOneshotExecutor(validator=validator, logger=logger, refresh_interval=refresh, mode_override=mode_override)

    actual_mode = mode_override or VALIDATOR_STATE_MODES.get(validator, "hot")
    if actual_mode == "hot":
        from src.rpkiwi.executor.hot_state import HotStateManager
        from src.rpkiwi.input.scaffold import apply_version as _apply_version
        sm = executor._state
        if isinstance(sm, HotStateManager):
            def _check_warmup():
                obs = collect_validator_observations([validator], logger=logger)
                sem = obs.semantics.get(validator)
                return sem is not None and CANARY_VRP in sem.canary_vrps

            def _check_t1():
                obs = collect_validator_observations([validator], logger=logger)
                sem = obs.semantics.get(validator)
                return (sem is not None
                        and CANARY_VRP in sem.canary_vrps
                        and VICTIM_VRP_A not in sem.victim_zone_vrps
                        and VICTIM_VRP_B in sem.victim_zone_vrps)

            sm.configure(
                apply_version=lambda pp, ver: _apply_version(pp, ver, config.build_dir),
                check_warmup=_check_warmup,
                check_t1_withdrawal=_check_t1,
            )

    otype = object_type.upper()

    loaded = corpus.load_queue(config)
    if loaded > 0:
        logger(f"[*] restored {loaded} entries from queue on disk")

    initial_seeds: list[TestInput] = []
    if initial_seed_folder:
        seed_dir = Path(initial_seed_folder)
        if seed_dir.is_dir():
            initial_seeds = corpus.load_initial_seeds(seed_dir, config)
            logger(f"[*] loaded {len(initial_seeds)} initial seed(s) from {seed_dir}")
        else:
            logger(f"[!] initial seed folder does not exist: {seed_dir}")

    if otype not in ALL_OBJECT_TYPES:
        logger(f"[!] unknown object type {object_type!r}; valid types: {', '.join(sorted(ALL_OBJECT_TYPES))}")
        logger(f"[!] falling back to ROA")
        otype = "ROA"

    initial_test_input = generate(otype, config)
    corpus.enqueue(initial_test_input, tags={"source": "generator"})
    logger(f"[*] initial seed: {len(initial_test_input.data)} bytes ({otype})")

    scheduler = FuzzScheduler(corpus, config, logger=logger)

    # Use the already-override-aware actual_mode (see its computation above),
    # not a second, override-blind lookup -- that was the same class of bug
    # just fixed in _warmup_checkpoint's own use_criu.
    validator_mode = actual_mode
    is_checkpoint_mode = validator_mode in ("criu", "snapshot_restart", "rpstir2", "validator3")

    if is_checkpoint_mode:
        _warmup_checkpoint(config, scaffold, executor, validator,
                           no_aspa, logger, mode_override=mode_override)
    else:
        _warmup_default(executor, scaffold, config, validator, skip_baseline, logger)

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

    is_daemon = validator_mode != "hot"
    use_checkpoint = executor._has_checkpoint

    def _run_round_single(test_input):
        """Inject one input, advance to T2, observe. Returns (verdict, origin).

        Shared by discovery and replay, and by the seed dry-run and the main
        loop, so a replay reproduces the discovery's conditions exactly.
        """
        if not use_checkpoint:
            executor.clear_cache()
        scaffold.switch_scenario("t2")
        scaffold.scaffold(test_input)
        exec_result = executor.execute()
        origin = exec_result.state_origin
        if not exec_result.success and exec_result.returncode == -1:
            return error_verdict(validator, exec_result.stderr or "execution error"), origin
        if exec_result.target_crashed:
            return crash_verdict(validator), origin
        if settle_seconds > 0 and not is_daemon:
            time.sleep(settle_seconds)
        observation = collect_validator_observations([validator], logger=logger)
        return evaluate(observation, scenario), origin

    def _restore_t1_single() -> str:
        scaffold.switch_scenario("t1")
        scaffold.restore_baseline()
        return publication_fingerprint(config.build_dir)

    def _confirm_single(test_input, verdict, origin, baseline_id):
        """§5.4: replay `test_input` from a restored T1 baseline."""
        discovery = Attempt(
            phase=PHASE_DISCOVERY, classification=verdict.classification,
            baseline_id=baseline_id,
            per_validator={validator: verdict.classification},
            state_origins={validator: origin},
            crashed=[validator] if executor.target_crashed else [],
            evidence=verdict.evidence,
        )

        def _replay(bid: str) -> Attempt:
            v, o = _run_round_single(test_input)
            return Attempt(
                phase=PHASE_REPLAY, classification=v.classification,
                baseline_id=bid, per_validator={validator: v.classification},
                state_origins={validator: o},
                crashed=[validator] if executor.target_crashed else [],
                evidence=v.evidence,
            )

        return confirm_from_t1(
            discovery, restore_t1=_restore_t1_single, run_once=_replay, logger=logger)

    if initial_seeds:
        initial_seeds = [s for s in initial_seeds if s.object_type == otype]
        logger(f"[*] seed dry-run: executing {len(initial_seeds)} {otype} seed(s) without mutation...")
        for idx, seed_input in enumerate(initial_seeds):
            seed_name = seed_input.metadata.get("ir_name", seed_input.metadata.get("source", f"seed-{idx}"))
            logger(f"  [dry-run {idx+1}/{len(initial_seeds)}] {seed_name} ({len(seed_input.data)} bytes)")
            try:
                baseline_id = publication_fingerprint(config.build_dir)
                verdict, origin = _run_round_single(seed_input)
                if verdict.classification == CLASS_ERROR:
                    logger(f"  [dry-run {idx+1}] execution error: {verdict.reason}")
                    continue
                state.record(verdict.classification)

                if is_interesting(verdict):
                    replay = _confirm_single(seed_input, verdict, origin, baseline_id)
                    if replay.confirmed:
                        finding = Finding(
                            iteration=0,
                            classification=verdict.classification,
                            mutation_name=f"ir_seed:{seed_name}",
                            mutation_description="IR seed executed as-is",
                            evidence=verdict.evidence,
                            confirmed=True,
                            replay=replay.record(),
                        )
                        finding.corpus_path = corpus.save_solution(seed_input, finding, verdict)
                        state.add_finding(finding)
                        logger(f"  [dry-run {idx+1}] CONFIRMED {verdict.classification}: {seed_name} — {replay.summary()}")
                    else:
                        state.record_discarded()
                        logger(f"  [dry-run {idx+1}] discovery {verdict.classification} NOT confirmed: {replay.summary()}")
                else:
                    logger(f"  [dry-run {idx+1}] NONE (seed did not trigger)")
            except Exception as exc:
                logger(f"  [dry-run {idx+1}] error: {exc}")
            finally:
                scaffold.switch_scenario("t1")
                scaffold.restore_baseline()
                if use_checkpoint:
                    executor.stop_container()

    logger(f"[*] starting fuzz loop: {iterations} iterations against {validator}")
    if use_checkpoint:
        logger(f"[*] checkpoint mode active — each iteration: restore → inject → T2 → observe → stop")

    for i in range(1, iterations + 1):
        seed = scheduler.next(otype)
        mutated_input = scheduler.mutate(seed)

        mutated = mutated_input.data
        mut_name = mutated_input.metadata.get("mutation_name", "unknown")
        mut_desc = mutated_input.metadata.get("mutation_description", "")

        logger(f"  [{i}] mutating: {mut_name} -- {mut_desc}")

        try:
            baseline_id = publication_fingerprint(config.build_dir)
            verdict, origin = _run_round_single(mutated_input)
            if verdict.classification == CLASS_ERROR:
                logger(f"  [{i}] execution error: {verdict.reason}")
                state.record_error()
                continue
            state.record(verdict.classification)

            interesting = is_interesting(verdict)
            if interesting:
                replay = _confirm_single(mutated_input, verdict, origin, baseline_id)

                if replay.confirmed:
                    finding = Finding(
                        iteration=i,
                        classification=verdict.classification,
                        mutation_name=mut_name,
                        mutation_description=mut_desc,
                        evidence=verdict.evidence,
                        confirmed=True,
                        replay=replay.record(),
                    )
                    finding.corpus_path = corpus.save_solution(mutated_input, finding, verdict)
                    state.add_finding(finding)
                    logger(f"  [{i}] CONFIRMED {verdict.classification}: {mut_name} — {replay.summary()}")
                else:
                    state.record_discarded()
                    interesting = False
                    logger(f"  [{i}] discovery {verdict.classification} NOT confirmed: {replay.summary()}")

            scheduler.feedback(
                seed, mutated_input, interesting,
                verdict_class=verdict.classification, iteration=i,
            )

            corpus.save_tested(mutated_input, tags={
                "mutation": mut_name,
                "iteration": i,
            })

        except Exception as exc:
            logger(f"  [{i}] error: {exc}")
            state.record_error()
        finally:
            scaffold.switch_scenario("t1")
            scaffold.restore_baseline()
            if use_checkpoint:
                executor.stop_container()

        if i % 10 == 0 or i == iterations:
            logger(f"  [{i}/{iterations}] {state.iterations_per_second:.1f} it/s | findings: {len(state.findings)}")

    scaffold.switch_scenario("t0")

    logger(f"\n[*] fuzz loop complete\n{state.summary()}")
    return state

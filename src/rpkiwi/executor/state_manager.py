from __future__ import annotations

import subprocess
import time
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[3]

# How the validator state an observation was made on actually came about.
# Only SNAPSHOT_RESTORE and HOT are a replay from the recorded T1 baseline:
# WARMUP_FALLBACK means the restore failed and the run is a cold warmup, which
# must never be reported as a T1 replay.
ORIGIN_WARMUP = "warmup"
ORIGIN_WARMUP_FALLBACK = "warmup_fallback"
ORIGIN_SNAPSHOT_RESTORE = "snapshot_restore"
ORIGIN_HOT = "hot"
T1_REPLAY_ORIGINS = frozenset({ORIGIN_SNAPSHOT_RESTORE, ORIGIN_HOT})


class ExecutionResult:
    __slots__ = ("returncode", "stdout", "stderr", "validator", "success",
                 "state_origin", "target_crashed")

    def __init__(self, returncode: int, stdout: str, stderr: str, validator: str,
                 success: bool = True, state_origin: str = ORIGIN_WARMUP,
                 target_crashed: bool = False):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.validator = validator
        self.success = success
        self.state_origin = state_origin
        self.target_crashed = target_crashed

    @property
    def is_t1_replay(self) -> bool:
        return self.state_origin in T1_REPLAY_ORIGINS


class StateManager(ABC):

    def __init__(self, validator: str, project_name: str,
                 refresh_interval: float, logger: Callable[[str], None]):
        self.validator = validator
        self.project_name = project_name
        self._refresh_interval = refresh_interval
        self._logger = logger
        self._has_baseline = False
        self._last_crash = False

    @property
    def container_name(self) -> str:
        return f"{self.project_name}_{self.validator}_1"

    @property
    def has_baseline(self) -> bool:
        return self._has_baseline

    @property
    def target_crashed(self) -> bool:
        """The validator process died while processing the injected input."""
        return bool(self._last_crash)

    def clear_crash(self) -> None:
        self._last_crash = False

    def container_running(self) -> bool:
        try:
            probe = subprocess.run(
                ["sudo", "podman", "inspect", "--format={{.State.Running}}",
                 self.container_name],
                capture_output=True, text=True, timeout=15,
            )
        except (subprocess.SubprocessError, OSError):
            return True  # cannot tell; do not invent a crash
        if probe.returncode != 0:
            return False
        return probe.stdout.strip() == "true"

    def detect_crash(self) -> bool:
        """Record a target crash if the container is no longer running."""
        if not self.container_running():
            self._last_crash = True
        return self.target_crashed

    @abstractmethod
    def warmup_execute(self, force_restart: bool = False) -> ExecutionResult:
        pass

    @abstractmethod
    def create_baseline(self) -> bool:
        pass

    @abstractmethod
    def restore_and_execute(self) -> ExecutionResult:
        pass

    @abstractmethod
    def stop(self) -> bool:
        pass

    def prepare_for_t1(self) -> None:
        pass

    def _ok(self, origin: str = ORIGIN_WARMUP) -> ExecutionResult:
        return ExecutionResult(0, "", "", self.validator, True, state_origin=origin,
                               target_crashed=self.target_crashed)

    def _fail(self, stderr: str = "", origin: str = ORIGIN_WARMUP) -> ExecutionResult:
        return ExecutionResult(-1, "", stderr, self.validator, False, state_origin=origin,
                               target_crashed=self.target_crashed)


class SnapshotStateManager(StateManager):

    @abstractmethod
    def _do_capture(self) -> bool:
        pass

    @abstractmethod
    def _do_restore_and_start(self) -> bool:
        pass

    def create_baseline(self) -> bool:
        ok = self._do_capture()
        if ok:
            self._has_baseline = True
        return ok

    def restore_and_execute(self) -> ExecutionResult:
        if not self._has_baseline:
            return self.warmup_execute()
        # Clear any crash recorded by the previous iteration before restoring,
        # so a crash reported here belongs to this run's input.
        self.clear_crash()
        ok = self._do_restore_and_start()
        if not ok:
            # A fallback warmup is not a T1 replay; say so in the result so
            # callers cannot mistake it for one.
            self._logger("  [snapshot] restore failed, falling back to warmup")
            result = self.warmup_execute()
            result.state_origin = ORIGIN_WARMUP_FALLBACK
            return result
        self._wait_for_output()
        self.detect_crash()
        return self._ok(ORIGIN_SNAPSHOT_RESTORE)

    def _wait_for_output(self) -> None:
        self._logger(f"  waiting {self._refresh_interval}s for refresh...")
        time.sleep(self._refresh_interval)

VALIDATOR_STATE_MODES: dict[str, str] = {
    "routinator": "criu",
    "cfrpki": "criu",
    "fort-validator": "criu",
    "rpki-client": "criu",
    "rpki-prover": "criu",
    "rpki-validator-3": "validator3",
    "rpstir2": "rpstir2",
}

def create_state_manager(
    validator: str,
    project_name: str = "rpkiwi-fuzz",
    refresh_interval: float = 35.0,
    logger: Callable[[str], None] | None = None,
    mode_override: str | None = None,
) -> StateManager:
    from src.rpkiwi.executor.criu_snapshot import CriuContainerSnapshotManager
    from src.rpkiwi.executor.validator3_snapshot import Validator3ContainerSnapshotManager
    from src.rpkiwi.executor.rpstir2_snapshot import Rpstir2ContainerSnapshotManager
    from src.rpkiwi.executor.hot_state import HotStateManager

    logger = logger or (lambda m: None)
    mode = mode_override or VALIDATOR_STATE_MODES.get(validator, "hot")

    if mode == "criu":
        return CriuContainerSnapshotManager(validator, project_name, refresh_interval, logger)
    elif mode == "validator3":
        return Validator3ContainerSnapshotManager(validator, project_name, refresh_interval, logger)
    elif mode == "rpstir2":
        return Rpstir2ContainerSnapshotManager(validator, project_name, refresh_interval, logger)
    else:
        return HotStateManager(validator, project_name, refresh_interval, logger)



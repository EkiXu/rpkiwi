from __future__ import annotations

import subprocess
import time
from typing import Callable

from src.rpkiwi.executor.state_manager import (
    StateManager, ExecutionResult, REPO_ROOT, ORIGIN_HOT,
)
from src.rpkiwi.executor.docker_oneshot import ValidatorWithdrawalError

class HotStateManager(StateManager):

    def __init__(self, validator, project_name, refresh_interval, logger):
        super().__init__(validator, project_name, refresh_interval, logger)
        self._compose_file = "docker-compose.yml"
        self._apply_version: Callable[[str, str], None] | None = None
        self._check_vrps: Callable[[], bool] | None = None
        self._check_t1: Callable[[], bool] | None = None

    def configure(
        self,
        *,
        apply_version: Callable[[str, str], None],
        check_warmup: Callable[[], bool],
        check_t1_withdrawal: Callable[[], bool],
    ) -> None:
        self._apply_version = apply_version
        self._check_vrps = check_warmup
        self._check_t1 = check_t1_withdrawal

    def warmup_execute(self, force_restart: bool = False) -> ExecutionResult:
        if force_restart:
            self._restart()
        self._logger(f"  [hot] waiting {self._refresh_interval}s for {self.validator}...")
        time.sleep(self._refresh_interval)
        return self._ok(ORIGIN_HOT)

    def create_baseline(self) -> bool:
        self._has_baseline = True
        return True

    def restore_and_execute(self) -> ExecutionResult:
        self._logger(f"  [hot] recreating {self.validator} from scratch...")

        subprocess.run(
            ["sudo", "podman-compose", "-f", self._compose_file, "down", self.validator],
            capture_output=True, timeout=60, cwd=REPO_ROOT,
        )
        subprocess.run(
            ["sudo", "podman-compose", "-f", self._compose_file, "up", "-d", self.validator],
            capture_output=True, timeout=60, cwd=REPO_ROOT,
        )

        if self._apply_version:
            self._apply_version("victim-pp", "t0")
            self._apply_version("attacker-pp", "baseline")

        self._logger(f"  [hot] waiting {self._refresh_interval}s for T0 warmup...")
        warmup_ok = False
        for attempt in range(5):
            time.sleep(self._refresh_interval)
            if self._check_vrps and self._check_vrps():
                self._logger(f"  [hot] T0 warmup passed (attempt {attempt+1})")
                warmup_ok = True
                break
            self._logger(f"  [hot] T0 warmup attempt {attempt+1}/5: VRPs not ready")
        if not warmup_ok:
            self._logger(f"  [hot] T0 warmup failed after 5 attempts")
            return self._fail("T0 warmup failed", ORIGIN_HOT)

        if self._apply_version:
            self._apply_version("victim-pp", "t1")

        self._clear_cache()

        self._logger(f"  [hot] waiting for T1 withdrawal...")
        t1_ok = False
        for attempt in range(5):
            time.sleep(self._refresh_interval)
            if self._check_t1 and self._check_t1():
                self._logger(f"  [hot] T1 withdrawal confirmed (attempt {attempt+1})")
                t1_ok = True
                break
            self._logger(f"  [hot] T1 not reflected (attempt {attempt+1}/5)")
        if not t1_ok:
            self._logger(f"  [hot] T1 withdrawal not confirmed after 5 attempts")

        return self._ok(ORIGIN_HOT)

    def stop(self) -> bool:
        try:
            subprocess.run(
                ["sudo", "podman", "kill", self.container_name],
                capture_output=True, timeout=30,
            )
            return True
        except Exception:
            return False

    def _restart(self) -> None:
        subprocess.run(
            ["sudo", "podman-compose", "-f", self._compose_file, "down", self.validator],
            capture_output=True, timeout=60, cwd=REPO_ROOT,
        )
        subprocess.run(
            ["sudo", "podman-compose", "-f", self._compose_file, "up", "-d", self.validator],
            capture_output=True, timeout=60, cwd=REPO_ROOT,
        )

    def _clear_cache(self) -> None:
        from src.rpkiwi.executor.mixins import TAR_INCLUDE_PATHS
        cache_map = {
            "routinator": "/home/routinator",
            "cfrpki": "/cache",
            "fort-validator": "/var/cache/fort",
            "rpki-client": "/var/cache/rpki-client",
            "rpki-prover": "/rpki-data",
            "rpki-validator-3": "/data",
            "rpstir2": "/root/rpki/data/rrdprepo",
        }
        cache_dir = cache_map.get(self.validator)
        if cache_dir:
            subprocess.run(
                ["sudo", "podman", "exec", self.container_name, "sh", "-c",
                 f"rm -rf {cache_dir}/* {cache_dir}/.[!.]*"],
                capture_output=True, timeout=30,
            )
            self._logger(f"  [hot] cleared cache ({cache_dir})")

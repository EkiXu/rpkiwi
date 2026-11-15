from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Callable

from src.rpkiwi.executor.state_manager import (
    ExecutionResult,
    StateManager,
    VALIDATOR_STATE_MODES,
    create_state_manager,
    REPO_ROOT,
)

import json
from urllib.request import urlopen, Request

DAEMON_API_ENDPOINTS: dict[str, str] = {
    "cfrpki": "http://127.0.0.1:35002/output.json",
}

def _get_generated_timestamp(url: str) -> int | None:
    try:
        with urlopen(Request(url), timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        meta = data.get("metadata", {})
        return meta.get("generated", meta.get("generatedUnix"))
    except Exception:
        return None

ONESHOT_COMMANDS: dict[str, list[str]] = {
    "routinator": [
        "sudo", "podman-compose",
        "exec", "-T", "routinator",
        "routinator", "--config", "/config/routinator.conf",
        "--allow-dubious-hosts", "--no-rir-tals", "--fresh",
        "--rrdp-root-cert", "/ssl/ca.crt",
        "vrps", "--format", "json",
    ],
    "fort-validator": [
        "sudo", "podman-compose",
        "exec", "-T", "fort-validator",
        "fort",
        "--configuration-file", "/etc/fort/fort.conf",
        "--mode", "standalone",
    ],
    "rpki-client": [
        "sudo", "podman-compose",
        "exec", "-T", "rpki-client",
        "rpki-client",
        "-t", "/etc/tals/myta.tal",
        "/var/lib/rpki-client",
    ],
}

class ValidatorWithdrawalError(RuntimeError):
    def __init__(self, validator: str, refreshes: int, hint: str = ""):
        self.validator = validator
        self.refreshes = refreshes
        super().__init__(f"{validator}: withdrawal not reflected after {refreshes} refreshes. {hint}")

class DockerOneshotExecutor:
    def __init__(
        self,
        validator: str = "cfrpki",
        compose_file: str = "docker-compose.yml",
        project_name: str = "rpkiwi-fuzz",
        timeout: int = 120,
        logger: Callable[[str], None] | None = None,
        poll_interval: float = 2.0,
        poll_timeout: float = 60.0,
        refresh_interval: float = 35.0,
        mode_override: str | None = None,
    ):
        self.validator = validator
        self.compose_file = compose_file
        self.project_name = project_name
        self.timeout = timeout
        self.poll_interval = poll_interval
        self.poll_timeout = poll_timeout
        self._refresh_interval = refresh_interval
        self._logger = logger or (lambda m: None)

        self._state: StateManager = create_state_manager(
            validator, project_name, refresh_interval,
            logger=self._logger, mode_override=mode_override,
        )

    @property
    def _has_checkpoint(self) -> bool:
        return self._state.has_baseline

    @_has_checkpoint.setter
    def _has_checkpoint(self, value: bool):
        self._state._has_baseline = value

    def execute(self, force_restart: bool = False) -> ExecutionResult:
        if force_restart:
            return self._state.warmup_execute(force_restart=True)
        if not self._state.has_baseline:
            return self._state.warmup_execute()
        return self._state.restore_and_execute()

    @property
    def target_crashed(self) -> bool:
        """The validator process died while processing the last injected input."""
        return self._state.target_crashed

    def create_baseline_checkpoint(self) -> bool:
        return self._state.create_baseline()

    def create_baseline_snapshot(self) -> bool:
        return self._state.create_baseline()

    def stop_container(self) -> bool:
        return self._state.stop()

    def clear_cache(self) -> bool:
        container = f"{self.project_name}_{self.validator}_1"
        if self.validator == "cfrpki":
            try:
                subprocess.run(
                    ["sudo", "podman", "exec", container, "sh", "-c",
                     "rm -rf /cache/attacker-pp.com /cache/victim-pp.com /cache/myta.com/ta /cache/rrdp.json && mkdir -p /cache/myta.com/ta && if [ -d /cache/myta.com/ta/ta.cer ] && [ -f /cache/myta.com/ta/ta.cer/ta.cer ]; then mv /cache/myta.com/ta/ta.cer/ta.cer /cache/myta.com/ta/ta.cer.file && rmdir /cache/myta.com/ta/ta.cer 2>/dev/null || true && mv /cache/myta.com/ta/ta.cer.file /cache/myta.com/ta/ta.cer; fi"],
                    capture_output=True, text=True, timeout=30, cwd=REPO_ROOT,
                )
                self._logger(f"  cleared {self.validator} cache (attacker-pp + victim-pp)")
                return True
            except Exception:
                return False
        if self.validator == "rpstir2":
            try:
                subprocess.run(
                    ["sudo", "podman", "exec", container, "sh", "-c",
                     "rm -rf /root/rpki/data/rrdprepo/* /root/rpki/data/rsyncrepo/*"],
                    capture_output=True, text=True, timeout=30, cwd=REPO_ROOT,
                )
                self._logger(f"  cleared rpstir2 RRDP/rsync cache")
                return True
            except Exception:
                return False
        if self.validator == "routinator":
            try:
                subprocess.run(
                    ["sudo", "podman", "exec", container, "sh", "-c",
                     "rm -rf /home/routinator/rrdp /home/routinator/stored "
                     "/home/routinator/rsync/* 2>/dev/null; "
                     "mkdir -p /home/routinator/rrdp /home/routinator/stored "
                     "/home/routinator/rsync"],
                    capture_output=True, text=True, timeout=30, cwd=REPO_ROOT,
                )
                self._logger(f"  cleared routinator RRDP session + stored state")
                return True
            except Exception:
                return False
        if self.validator == "rpki-prover":
            try:
                subprocess.run(
                    ["sudo", "podman", "exec", container, "sh", "-c",
                     "rm -rf /rpki-data/cache /rpki-data/tmp 2>/dev/null; "
                     "mkdir -p /rpki-data/cache /rpki-data/tmp /rpki-data/tals"],
                    capture_output=True, text=True, timeout=30, cwd=REPO_ROOT,
                )
                self._logger(f"  cleared rpki-prover cache (preserved structure)")
                return True
            except Exception:
                return False
        cache_dirs = {
            "fort-validator": "/var/cache/fort",
            "rpki-client": "/var/cache/rpki-client",
            "rpki-validator-3": "/data",
        }
        cache_dir = cache_dirs.get(self.validator)
        if cache_dir is None:
            return True
        try:
            result = subprocess.run(
                ["sudo", "podman", "exec", container, "sh", "-c", f"rm -rf {cache_dir}/* {cache_dir}/.[!.]*"],
                capture_output=True, text=True, timeout=30, cwd=REPO_ROOT,
            )
            if result.returncode == 0:
                self._logger(f"  cleared {self.validator} cache ({cache_dir})")
            return result.returncode == 0
        except Exception:
            return False

    def wait_for_withdrawal(
        self,
        check_fn: Callable[[], bool],
        *,
        max_refreshes: int = 3,
        timeout: float = 120.0,
    ) -> None:
        url = DAEMON_API_ENDPOINTS.get(self.validator)
        deadline = time.monotonic() + timeout

        if url is not None:
            last_ts = _get_generated_timestamp(url)
            refreshes = 0
            while time.monotonic() < deadline:
                time.sleep(self.poll_interval)
                cur_ts = _get_generated_timestamp(url)
                if cur_ts is None or cur_ts == last_ts:
                    continue
                refreshes += 1
                last_ts = cur_ts
                if check_fn():
                    self._logger(f"  withdrawal reflected after {refreshes} refresh(es)")
                    return
                if refreshes >= max_refreshes:
                    raise ValidatorWithdrawalError(
                        self.validator, refreshes,
                        "ROA withdrawn from manifest but validator still produces it",
                    )
                self._logger(f"  refresh #{refreshes}: withdrawal not yet reflected, waiting...")
        else:
            refreshes = 0
            while time.monotonic() < deadline:
                self._trigger_sync_if_rpstir2()
                time.sleep(self._refresh_interval)
                refreshes += 1
                if check_fn():
                    self._logger(f"  withdrawal reflected after {refreshes} cycle(s)")
                    return
                if refreshes >= max_refreshes:
                    raise ValidatorWithdrawalError(
                        self.validator, refreshes,
                        "ROA withdrawn from manifest but validator still produces it",
                    )
                self._logger(f"  cycle #{refreshes}: withdrawal not yet reflected, waiting...")

        if refreshes == 0:
            raise TimeoutError(f"{self.validator} produced no new output within {timeout}s")
        raise TimeoutError(f"T1 transition incomplete after {refreshes} refreshes")

    def _trigger_sync_if_rpstir2(self) -> None:
        if self.validator != "rpstir2":
            return
        from src.rpkiwi.executor.rpstir2_snapshot import Rpstir2ContainerSnapshotManager
        if isinstance(self._state, Rpstir2ContainerSnapshotManager):
            self._state._trigger_sync()

    def start_attacker_pp(self) -> bool:
        return self.ensure_infrastructure()

    def ensure_infrastructure(self) -> bool:
        infra = ["myta", "victim-pp", "attacker-pp"]
        if self.validator == "rpstir2":
            infra.append("rpstir2-mysql")
        self._logger(f"  ensuring infrastructure ({', '.join(infra)})...")
        try:
            result = subprocess.run(
                ["sudo", "podman-compose", "-f", self.compose_file, "-p", self.project_name,
                 "up", "-d"] + infra,
                capture_output=True, text=True, timeout=60, cwd=REPO_ROOT,
            )
            if result.returncode != 0:
                self._logger(f"  infrastructure start failed: {result.stderr[:200]}")
                return False
        except Exception as exc:
            self._logger(f"  infrastructure start error: {exc}")
            return False

        import urllib.request, ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        for attempt in range(1, 11):
            try:
                urllib.request.urlopen("https://myta.com/ta/ta.cer",
                                       timeout=3, context=ctx)
                self._logger(f"  myta HTTPS ready (attempt {attempt})")
                return True
            except Exception:
                if attempt < 10:
                    time.sleep(1)
        self._logger("  [!] myta HTTPS not reachable after 10 attempts")
        return True

    def restart_validator(self) -> bool:
        cmd = ["sudo", "podman-compose", "-f", self.compose_file, "restart", self.validator]
        try:
            return subprocess.run(cmd, capture_output=True, timeout=60, cwd=REPO_ROOT).returncode == 0
        except Exception:
            return False

    def baseline_check(self) -> ExecutionResult:
        return self.execute()

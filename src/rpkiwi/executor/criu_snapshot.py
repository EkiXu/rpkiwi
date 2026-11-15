from __future__ import annotations

import subprocess
import time

from src.rpkiwi.executor.state_manager import SnapshotStateManager, ExecutionResult, REPO_ROOT
from src.rpkiwi.executor.mixins import TarSnapshot, CriuProcess, TAR_INCLUDE_PATHS

POLL_VALIDATORS: dict[str, dict] = {
    "cfrpki": {"type": "http", "url": "http://127.0.0.1:35002/output.json"},
    "routinator": {"type": "http", "url": "http://localhost:35000/api/v1/origins/"},
    "rpki-prover": {"type": "http", "url": "http://localhost:39999/api/vrps"},
    "rpki-validator-3": {"type": "http", "url": "http://localhost:35011/api/objects/validated"},
}

class CriuContainerSnapshotManager(SnapshotStateManager):

    def __init__(self, validator, project_name, refresh_interval, logger):
        super().__init__(validator, project_name, refresh_interval, logger)
        snapshot_dir = REPO_ROOT / "build" / ".snapshots"
        self._tar = TarSnapshot(
            self.container_name, snapshot_dir,
            include_paths=TAR_INCLUDE_PATHS.get(validator),
            logger=logger,
        )
        self._criu = CriuProcess(
            checkpoint_dir=snapshot_dir / "criu", logger=logger,
        )

    def warmup_execute(self, force_restart: bool = False) -> ExecutionResult:
        if force_restart:
            subprocess.run(
                ["sudo", "podman-compose",
                 "-p", self.project_name, "up", "-d", "--force-recreate",
                 self.validator],
                capture_output=True, timeout=60, cwd=REPO_ROOT)
        self._logger(f"  waiting {self._refresh_interval * 3:.0f}s for {self.validator} (3 refresh cycles)...")
        time.sleep(self._refresh_interval * 3)
        return self._ok()

    def _do_capture(self) -> bool:
        return self._criu.checkpoint(self.container_name)

    def _do_restore_and_start(self) -> bool:
        return self._criu.restore(self.container_name)

    def _wait_container_state(self, expected_paused: str, *, label: str, retries: int = 10) -> None:
        for i in range(retries):
            try:
                r = subprocess.run(
                    ["sudo", "podman", "inspect", "--format={{.State.Paused}}",
                     self.container_name],
                    capture_output=True, text=True, timeout=5)
                if r.returncode == 0 and r.stdout.strip() == expected_paused:
                    return
            except Exception:
                pass
            time.sleep(0.3)
        self._logger(f"  [criu] warning: container state not confirmed as {label} after {retries} retries")

    def _wait_for_output(self) -> None:
        import json
        from urllib.request import urlopen, Request
        from src.rpkiwi.observer.vrp_observer import VICTIM_VRP_C

        t2_cal = getattr(self, '_t2_calibration', 0)
        timeout = t2_cal if t2_cal > 0 else self._refresh_interval

        poll_cfg = POLL_VALIDATORS.get(self.validator)
        if poll_cfg and poll_cfg["type"] == "http":
            url = poll_cfg["url"]
            baseline_count = 0
            try:
                with urlopen(Request(url), timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                roas = data if isinstance(data, list) else data.get("roas", [])
                baseline_count = len(roas)
            except Exception:
                pass
            self._logger(f"  polling {self.validator} (baseline {baseline_count} VRPs, timeout {timeout:.0f}s)...")

            deadline = time.monotonic() + timeout
            time.sleep(1)
            while time.monotonic() < deadline:
                try:
                    with urlopen(Request(url), timeout=5) as resp:
                        data = json.loads(resp.read().decode("utf-8"))
                    roas = data if isinstance(data, list) else data.get("roas", [])
                    has_roa_c = any(
                        (r.get("prefix", "").split("/")[0], int(str(r.get("asn", 0)).replace("AS", "")))
                        == (VICTIM_VRP_C[0], VICTIM_VRP_C[3])
                        for r in roas
                    )
                    if has_roa_c and len(roas) >= 5:
                        elapsed = timeout - (deadline - time.monotonic())
                        self._logger(f"  output changed ({baseline_count} → {len(roas)} VRPs, {elapsed:.1f}s)")
                        return
                except Exception:
                    pass
                time.sleep(0.5)
            self._logger(f"  poll timeout ({baseline_count} VRPs unchanged)")
            return

        if self.validator == "rpki-client":
            self._logger(f"  polling rpki-client JSON (timeout {timeout:.0f}s)...")
            deadline = time.monotonic() + timeout
            time.sleep(1)
            while time.monotonic() < deadline:
                try:
                    r = subprocess.run(
                        ["sudo", "podman", "exec", self.container_name, "stat", "-c", "%Y",
                         "/var/lib/rpki-client/json"],
                        capture_output=True, text=True, timeout=5)
                    if r.returncode == 0 and r.stdout.strip():
                        elapsed = timeout - (deadline - time.monotonic())
                        self._logger(f"  rpki-client JSON updated ({elapsed:.1f}s)")
                        return
                except Exception:
                    pass
                time.sleep(0.5)
            self._logger(f"  poll timeout, proceeding anyway")
            return

        if self.validator == "fort-validator":
            self._logger(f"  polling fort CSV (timeout {timeout:.0f}s)...")
            deadline = time.monotonic() + timeout
            time.sleep(1)
            while time.monotonic() < deadline:
                try:
                    r = subprocess.run(
                        ["sudo", "podman", "exec", self.container_name, "wc", "-l",
                         "/var/local/fort/vrps.csv"],
                        capture_output=True, text=True, timeout=5)
                    if r.returncode == 0:
                        lines = int(r.stdout.strip().split()[0])
                        if lines > 1:
                            elapsed = timeout - (deadline - time.monotonic())
                            self._logger(f"  fort CSV ready ({lines} lines, {elapsed:.1f}s)")
                            return
                except Exception:
                    pass
                time.sleep(0.5)
            self._logger(f"  poll timeout, proceeding anyway")
            return

        super()._wait_for_output()

    def stop(self) -> bool:
        subprocess.run(["sudo", "podman", "kill", self.container_name], capture_output=True, timeout=20)
        return True

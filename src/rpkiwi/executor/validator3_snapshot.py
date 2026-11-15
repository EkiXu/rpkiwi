from __future__ import annotations

import subprocess
import time

from src.rpkiwi.executor.state_manager import SnapshotStateManager, ExecutionResult, REPO_ROOT
from src.rpkiwi.executor.mixins import TarSnapshot, DockerRestart, TAR_INCLUDE_PATHS

class Validator3ContainerSnapshotManager(SnapshotStateManager):

    def __init__(self, validator, project_name, refresh_interval, logger):
        super().__init__(validator, project_name, refresh_interval, logger)
        snapshot_dir = REPO_ROOT / "build" / ".snapshots"
        self._tar = TarSnapshot(
            self.container_name, snapshot_dir,
            include_paths=TAR_INCLUDE_PATHS.get(validator),
            logger=logger,
        )
        self._restart = DockerRestart(logger=logger)

    def warmup_execute(self, force_restart: bool = False) -> ExecutionResult:
        if force_restart:
            subprocess.run(
                ["sudo", "podman-compose", "-p", self.project_name,
                 "down", self.validator],
                capture_output=True, timeout=60, cwd=REPO_ROOT)
            subprocess.run(
                ["sudo", "podman-compose", "-p", self.project_name,
                 "up", "-d", self.validator],
                capture_output=True, timeout=60, cwd=REPO_ROOT)
        self._wait_for_initial_validation()
        return self._ok()

    def _wait_for_initial_validation(self, timeout: int = 180) -> None:
        import json
        from urllib.request import urlopen, Request

        cfg = self._POLL_CONFIG.get(self.validator)
        if cfg is None:
            self._logger(f"  waiting {self._refresh_interval}s for {self.validator}...")
            time.sleep(self._refresh_interval)
            return

        url = cfg["url"]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with urlopen(Request(url), timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                tas = data.get("data", {}).get("trustAnchors", [{}])
                if tas and tas[0].get("initialCertificateTreeValidationRunCompleted"):
                    elapsed = timeout - (deadline - time.monotonic())
                    self._logger(f"  {self.validator} initial validation done ({elapsed:.0f}s)")
                    return
            except Exception:
                pass
            time.sleep(2)
        self._logger(f"  {self.validator} initial validation timeout ({timeout}s)")

    def _do_capture(self) -> bool:
        if self.validator == "rpki-prover":
            subprocess.run(
                ["sudo", "podman", "exec", self.container_name,
                 "touch", "/.wait-for-restore"],
                capture_output=True, timeout=5)
        return self._tar.capture()

    def _do_restore_and_start(self) -> bool:
        subprocess.run(["sudo", "podman", "kill", self.container_name], capture_output=True, timeout=10)
        if self._tar.exists:
            if self.validator == "rpki-prover":
                self._tar.restore_with_sentinel(self.container_name)
            else:
                self._tar.restore()
        return self._restart.restart(self.container_name)

    _POLL_CONFIG = {
        "rpki-validator-3": {
            "url": "http://localhost:35011/api/objects/validated",
            "extract": lambda d: d.get("data", {}).get("roas", []),
        },
        "rpki-prover": {
            "url": "http://localhost:39999/api/vrps",
            "extract": lambda d: d if isinstance(d, list) else d.get("roas", []),
        },
    }

    def _wait_for_output(self) -> None:
        import json
        from urllib.request import urlopen, Request
        from src.rpkiwi.observer.vrp_observer import VICTIM_VRP_C

        cfg = self._POLL_CONFIG.get(self.validator)
        if cfg is None:
            time.sleep(self._refresh_interval)
            return
        url = cfg["url"]
        extract = cfg["extract"]

        api_ready = False
        for attempt in range(60):
            try:
                with urlopen(Request(url), timeout=3) as resp:
                    resp.read()
                api_ready = True
                self._logger(f"  {self.validator} API responsive (attempt {attempt + 1})")
                break
            except Exception:
                pass
            time.sleep(2)
        if not api_ready:
            self._logger(f"  {self.validator} API never responded after 120s")
            return

        t2_cal = getattr(self, '_t2_calibration', 0)
        timeout = t2_cal * 2 if t2_cal > 0 else self._refresh_interval * 3
        self._logger(f"  polling {self.validator} API for ROA-C (timeout {timeout:.0f}s)...")

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with urlopen(Request(url), timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                roas = extract(data)
                for r in roas:
                    prefix = r.get("prefix", "").split("/")[0]
                    asn = r.get("asn", 0)
                    if isinstance(asn, str):
                        asn = int(asn.replace("AS", ""))
                    if (prefix, asn) == (VICTIM_VRP_C[0], VICTIM_VRP_C[3]):
                        self._logger(f"  {self.validator} API: {len(roas)} VRPs (ROA-C present)")
                        return
            except Exception:
                pass
            time.sleep(1)
        self._logger(f"  poll timeout, proceeding anyway")

    def stop(self) -> bool:
        try:
            subprocess.run(["sudo", "podman", "kill", self.container_name], capture_output=True, timeout=30)
        except subprocess.TimeoutExpired:
            pass
        return True

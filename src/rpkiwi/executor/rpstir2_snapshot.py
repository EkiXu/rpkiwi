from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from src.rpkiwi.executor.state_manager import SnapshotStateManager, ExecutionResult, REPO_ROOT

TABLES_TO_CLEAR = [
    "lab_rpki_rtr_full", "lab_rpki_rtr_asa_full",
    "lab_rpki_rtr_full_log", "lab_rpki_rtr_incremental", "lab_rpki_rtr_serial_number",
    "lab_rpki_roa", "lab_rpki_roa_ipaddress", "lab_rpki_roa_ee_ipaddress",
    "lab_rpki_roa_sia", "lab_rpki_roa_aia",
    "lab_rpki_asa", "lab_rpki_asa_provider_asn", "lab_rpki_asa_customer_asn",
    "lab_rpki_asa_sia", "lab_rpki_asa_aia",
    "lab_rpki_cer", "lab_rpki_cer_ipaddress", "lab_rpki_cer_asn",
    "lab_rpki_cer_sia", "lab_rpki_cer_aia", "lab_rpki_cer_crldp",
    "lab_rpki_crl",
    "lab_rpki_mft", "lab_rpki_mft_aia", "lab_rpki_mft_sia", "lab_rpki_mft_file_hash",
    "lab_rpki_sync_rrdp_log", "lab_rpki_sync_log", "lab_rpki_sync_log_file",
]

class Rpstir2ContainerSnapshotManager(SnapshotStateManager):

    def __init__(self, validator, project_name, refresh_interval, logger):
        super().__init__(validator, project_name, refresh_interval, logger)
        self._dump_path = REPO_ROOT / "build" / ".snapshots" / "rpstir2-data-only.sql"
        self._attacker_cache_snapshot: dict[str, bytes] | None = None
        self._warmup_data_initialized = False

    @property
    def _mysql_container(self) -> str:
        return self.container_name.replace("rpstir2_1", "rpstir2-mysql_1")

    def _is_running(self) -> bool:
        r = subprocess.run(
            ["sudo", "podman", "inspect", self.container_name, "--format", "{{.State.Running}}"],
            capture_output=True, text=True, timeout=10)
        return r.stdout.strip() == "true"

    def _start_and_wait_api(self) -> None:
        subprocess.run(["sudo", "podman", "start", self.container_name], capture_output=True, timeout=30)
        for i in range(90):
            r = subprocess.run(
                ["sudo", "podman", "exec", self.container_name, "curl", "-sk",
                 "-d", '{"operate":"get"}', "-H", "Content-type: application/json",
                 "-X", "POST", "https://127.0.0.1:8071/sys/servicestate"],
                capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and "runningState" in r.stdout:
                self._logger(f"  [rpstir2] API ready ({i}s)")
                return
            time.sleep(1)

    def _mysql_exec_external(self, sql: str, *, timeout: int = 60) -> bool:
        r = subprocess.run(
            ["sudo", "podman", "exec", self._mysql_container,
             "mysql", "-u", "rpstir2", f"-p{os.environ.get('RPKIWI_MYSQL_PASSWORD', '')}", "rpstir2", "-e", sql],
            capture_output=True, text=True, timeout=timeout)
        return r.returncode == 0

    def _wait_for_idle(self, timeout: int = 180) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                r = subprocess.run(
                    ["sudo", "podman", "exec", self.container_name, "curl", "-sk",
                     "-d", '{"operate":"get"}', "-H", "Content-type: application/json",
                     "-X", "POST", "https://127.0.0.1:8071/sys/servicestate"],
                    capture_output=True, text=True, timeout=10)
                if r.returncode == 0 and '"isRunning":"false"' in r.stdout:
                    return
            except Exception:
                pass
            time.sleep(2)
        self._logger("  [rpstir2] wait-for-idle timeout")

    def warmup_execute(self, force_restart: bool = False) -> ExecutionResult:
        if force_restart:
            subprocess.run(
                ["sudo", "podman-compose",
                 "-p", self.project_name, "up", "-d", self.validator],
                capture_output=True, timeout=60, cwd=REPO_ROOT)
            self._start_and_wait_api()
            self._wait_for_idle()
            if not self._warmup_data_initialized:
                self._reset_all_data_external()
                self._warmup_data_initialized = True
        self._trigger_sync()
        time.sleep(5)
        self._wait_for_idle()
        return self._ok()

    def _reset_all_data_external(self) -> None:
        deletes = "; ".join(f"DELETE FROM {t}" for t in TABLES_TO_CLEAR)
        subprocess.run(
            ["sudo", "podman", "exec", self._mysql_container,
             "mysql", "-u", "rpstir2", f"-p{os.environ.get('RPKIWI_MYSQL_PASSWORD', '')}", "rpstir2",
             "-e", f"SET FOREIGN_KEY_CHECKS=0; {deletes}; SET FOREIGN_KEY_CHECKS=1;"],
            capture_output=True, text=True, timeout=60)
        subprocess.run(
            ["sudo", "podman", "exec", self.container_name, "sh", "-c",
             "rm -rf /root/rpki/data/rrdprepo/* /root/rpki/data/rsyncrepo/*"],
            capture_output=True, timeout=10)
        self._logger("  [rpstir2] MySQL + RRDP cache reset for clean warmup")

    def _trigger_sync(self) -> None:
        subprocess.run(
            ["sudo", "podman", "exec", self.container_name, "curl", "-sk",
             "-d", '{"syncStyle": "sync"}',
             "-H", "Content-type: application/json",
             "-X", "POST", "https://127.0.0.1:8071/entiresync/syncstart"],
            capture_output=True, timeout=60)

    def prepare_for_t1(self) -> None:
        self._mysql_exec_external(
            "SET FOREIGN_KEY_CHECKS=0;"
            " DELETE FROM lab_rpki_asa_sia;"
            " DELETE FROM lab_rpki_asa_aia;"
            " DELETE FROM lab_rpki_asa_customer_asn;"
            " DELETE FROM lab_rpki_asa_provider_asn;"
            " DELETE FROM lab_rpki_asa;"
            " SET FOREIGN_KEY_CHECKS=1;"
        )
        self._logger("  [rpstir2] cleared ASPA FK dependencies for T1 snapshot update")

    def _do_capture(self) -> bool:
        self._dump_path.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["sudo", "podman", "exec", self._mysql_container,
             "mysqldump", "-u", "rpstir2", f"-p{os.environ.get('RPKIWI_MYSQL_PASSWORD', '')}",
             "--skip-lock-tables", "--no-create-info", "--skip-triggers",
             "--replace", "--ignore-table=rpstir2.lab_rpki_conf",
             "rpstir2"],
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            self._logger(f"  [rpstir2] dump failed: {r.stderr.strip()[:120]}")
            return False
        self._dump_path.write_text(r.stdout)
        size_kb = self._dump_path.stat().st_size // 1024
        self._logger(f"  [rpstir2] T1 baseline dumped ({size_kb} KB, data-only)")

        self._snapshot_attacker_cache()
        return True

    def _snapshot_attacker_cache(self) -> None:
        self._attacker_cache_tar = self._dump_path.parent / "rpstir2-attacker-cache.tar"
        r = subprocess.run(
            ["sudo", "podman", "exec", self.container_name, "tar", "cf", "-",
             "-C", "/root/rpki/data/rrdprepo", "attacker-pp.com"],
            capture_output=True, timeout=30)
        if r.returncode == 0 and r.stdout:
            self._attacker_cache_tar.write_bytes(r.stdout)
            self._logger(f"  [rpstir2] attacker cache snapshot: {len(r.stdout) // 1024} KB tar")
        else:
            self._attacker_cache_tar = None
            self._logger("  [rpstir2] attacker cache snapshot failed")

    def _do_restore_and_start(self) -> bool:
        if self._is_running():
            subprocess.run(["sudo", "podman", "kill", self.container_name], capture_output=True, timeout=10)
        self.clear_crash()

        deletes = "; ".join(f"DELETE FROM {t}" for t in TABLES_TO_CLEAR)
        post_restore_sql = (
            "DELETE FROM lab_rpki_roa_ipaddress WHERE roaId IN (SELECT id FROM lab_rpki_roa WHERE filePath LIKE '%attacker%');"
            " DELETE FROM lab_rpki_roa_ee_ipaddress WHERE roaId IN (SELECT id FROM lab_rpki_roa WHERE filePath LIKE '%attacker%');"
            " DELETE FROM lab_rpki_roa_sia WHERE roaId IN (SELECT id FROM lab_rpki_roa WHERE filePath LIKE '%attacker%');"
            " DELETE FROM lab_rpki_roa_aia WHERE roaId IN (SELECT id FROM lab_rpki_roa WHERE filePath LIKE '%attacker%');"
            " DELETE FROM lab_rpki_roa WHERE filePath LIKE '%attacker%';"
            " DELETE FROM lab_rpki_mft_file_hash WHERE mftId IN (SELECT id FROM lab_rpki_mft WHERE filePath LIKE '%attacker%');"
            " DELETE FROM lab_rpki_mft_sia WHERE mftId IN (SELECT id FROM lab_rpki_mft WHERE filePath LIKE '%attacker%');"
            " DELETE FROM lab_rpki_mft_aia WHERE mftId IN (SELECT id FROM lab_rpki_mft WHERE filePath LIKE '%attacker%');"
            " DELETE FROM lab_rpki_mft WHERE filePath LIKE '%attacker%';"
            " DELETE FROM lab_rpki_crl WHERE filePath LIKE '%attacker%';"
            " DELETE FROM lab_rpki_sync_log_file WHERE syncLogId IN"
            "   (SELECT id FROM lab_rpki_sync_log WHERE syncUrl LIKE '%attacker%');"
            " DELETE FROM lab_rpki_asa_sia; DELETE FROM lab_rpki_asa_aia;"
            " DELETE FROM lab_rpki_asa_customer_asn; DELETE FROM lab_rpki_asa_provider_asn;"
            " DELETE FROM lab_rpki_asa;"
        )
        dump_sql = self._dump_path.read_text() if self._dump_path.exists() else ""
        combined = f"SET FOREIGN_KEY_CHECKS=0; {deletes}; SET FOREIGN_KEY_CHECKS=1;\n{dump_sql}\nSET FOREIGN_KEY_CHECKS=0; {post_restore_sql} SET FOREIGN_KEY_CHECKS=1;"
        r = subprocess.run(
            ["sudo", "podman", "exec", "-i", self._mysql_container,
             "mysql", "--force", "-u", "rpstir2", f"-p{os.environ.get('RPKIWI_MYSQL_PASSWORD', '')}", "rpstir2"],
            input=combined, capture_output=True, text=True, timeout=90)
        if r.returncode != 0 and "ERROR" in r.stderr and "doesn't exist" not in r.stderr:
            self._logger(f"  [rpstir2] mysql restore failed: {r.stderr.strip()[:120]}")

        self._start_and_wait_api()
        self._restore_attacker_cache()
        self._trigger_sync()
        self._logger("  [rpstir2] restored + sync triggered")
        return True

    def _wait_for_output(self) -> None:
        timeout = getattr(self, '_t2_calibration', 0) or self._refresh_interval
        deadline = time.monotonic() + timeout
        self._logger(f"  [rpstir2] waiting for sync (timeout {timeout:.1f}s)...")
        time.sleep(1)
        while time.monotonic() < deadline:
            if not self._is_running():
                self._logger("  [rpstir2] container crashed during sync")
                self._last_crash = True
                return
            try:
                r = subprocess.run(
                    ["sudo", "podman", "exec", self.container_name, "curl", "-sk",
                     "-d", '{"operate":"get"}', "-H", "Content-type: application/json",
                     "-X", "POST", "https://127.0.0.1:8071/sys/servicestate"],
                    capture_output=True, text=True, timeout=10)
                if r.returncode == 0 and '"isRunning":"false"' in r.stdout:
                    elapsed = timeout - (deadline - time.monotonic())
                    self._logger(f"  [rpstir2] sync complete ({elapsed:.1f}s)")
                    return
            except Exception:
                pass
            time.sleep(1)
        self._logger("  [rpstir2] sync timeout")

    def _restore_attacker_cache(self) -> None:
        tar_path = getattr(self, '_attacker_cache_tar', None)
        if tar_path is None or not tar_path.exists():
            subprocess.run(
                ["sudo", "podman", "exec", self.container_name, "sh", "-c",
                 "rm -rf /root/rpki/data/rrdprepo/attacker-pp.com;"
                 " mkdir -p /root/rpki/data/rrdprepo/attacker-pp.com"],
                capture_output=True, timeout=10)
            return

        subprocess.run(
            ["sudo", "podman", "exec", self.container_name, "sh", "-c",
             "rm -rf /root/rpki/data/rrdprepo/attacker-pp.com"],
            capture_output=True, timeout=10)
        subprocess.run(
            ["sudo", "podman", "exec", "-i", self.container_name, "tar", "xf", "-",
             "-C", "/root/rpki/data/rrdprepo"],
            input=tar_path.read_bytes(),
            capture_output=True, timeout=10)

    def stop(self) -> bool:
        return True

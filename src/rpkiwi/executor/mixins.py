from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Callable

REPO_ROOT = Path(__file__).resolve().parents[3]

TAR_INCLUDE_PATHS: dict[str, list[str]] = {
    "routinator": ["home/routinator"],
    "cfrpki": ["cache"],
    "fort-validator": ["var/local/fort", "tmp"],
    "rpki-client": ["var/cache/rpki-client", "var/lib/rpki-client"],
    "rpki-prover": ["rpki-data"],
    "rpki-validator-3": ["data"],
    "rpstir2": ["root/rpki/data"],
}

_TAR_EXCLUDE = ["proc", "sys", "dev"]

class TarSnapshot:

    def __init__(self, container: str, snapshot_dir: Path,
                 include_paths: list[str] | None = None,
                 logger: Callable[[str], None] | None = None):
        self.container = container
        self.snapshot_dir = snapshot_dir
        self.include_paths = include_paths or ["tmp", "home", "root", "var"]
        self._logger = logger or (lambda m: None)
        self._tar_host_path = snapshot_dir / f"{container}.tar"

    @property
    def exists(self) -> bool:
        return self._tar_host_path.exists()

    def capture(self) -> bool:
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        exclude_args = []
        for ex in _TAR_EXCLUDE:
            exclude_args.extend(["--exclude", ex])
        try:
            with open(self._tar_host_path, "wb") as f:
                r = subprocess.run(
                    ["sudo", "podman", "exec", self.container, "tar", "cf", "-", "-C", "/"]
                    + exclude_args + self.include_paths,
                    stdout=f, stderr=subprocess.PIPE, timeout=30)
            if r.returncode != 0:
                self._logger(f"  [tar] capture failed: {r.stderr.decode()[:80]}")
                self._tar_host_path.unlink(missing_ok=True)
                return False
            size_kb = self._tar_host_path.stat().st_size // 1024
            self._logger(f"  [tar] captured {self.container} ({size_kb} KB)")
            return True
        except Exception as exc:
            self._logger(f"  [tar] capture error: {exc}")
            return False

    def restore(self) -> bool:
        if not self.exists:
            self._logger(f"  [tar] no snapshot for {self.container}")
            return False
        try:
            subprocess.run(["sudo", "podman", "start", self.container],
                           capture_output=True, timeout=30)
            with open(self._tar_host_path, "rb") as f:
                r = subprocess.run(
                    ["sudo", "podman", "exec", "-i", self.container,
                     "tar", "xf", "-", "-C", "/"],
                    stdin=f, capture_output=True, timeout=30)
            subprocess.run(["sudo", "podman", "kill", self.container],
                           capture_output=True, timeout=10)
            if r.returncode != 0:
                self._logger(f"  [tar] exec tar failed: {r.stderr.decode()[:120]}")
                return False
            self._logger(f"  [tar] restored {self.container}")
            return True
        except Exception as exc:
            self._logger(f"  [tar] restore error: {exc}")
            subprocess.run(["sudo", "podman", "kill", self.container],
                           capture_output=True, timeout=10)
            return False

    def restore_with_sentinel(self, container: str | None = None) -> bool:
        target = container or self.container
        if not self.exists:
            self._logger(f"  [tar] no snapshot for {target}")
            return False
        try:
            subprocess.run(["sudo", "podman", "start", target],
                           capture_output=True, timeout=30)
            with open(self._tar_host_path, "rb") as f:
                r = subprocess.run(
                    ["sudo", "podman", "exec", "-i", target,
                     "tar", "xf", "-", "-C", "/"],
                    stdin=f, capture_output=True, timeout=30)
            if r.returncode != 0:
                self._logger(f"  [tar] exec tar failed: {r.stderr.decode()[:120]}")
                subprocess.run(["sudo", "podman", "kill", target],
                               capture_output=True, timeout=10)
                return False
            subprocess.run(
                ["sudo", "podman", "exec", target, "touch", "/.ready"],
                capture_output=True, timeout=5)
            subprocess.run(["sudo", "podman", "kill", target],
                           capture_output=True, timeout=10)
            self._logger(f"  [tar] restored {target} (with sentinel)")
            return True
        except Exception as exc:
            self._logger(f"  [tar] restore error: {exc}")
            subprocess.run(["sudo", "podman", "kill", target],
                           capture_output=True, timeout=10)
            return False

    def restore_to_host(self, host_dir) -> bool:
        import shutil
        from pathlib import Path
        if not self.exists:
            self._logger(f"  [tar] no snapshot for {self.container}")
            return False
        try:
            host_dir = Path(host_dir)
            if host_dir.exists():
                for entry in host_dir.iterdir():
                    if entry.is_dir():
                        shutil.rmtree(entry, ignore_errors=True)
                    else:
                        entry.unlink(missing_ok=True)
            host_dir.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(
                ["tar", "xf", str(self._tar_host_path), "-C", str(host_dir),
                 "--strip-components=1"],
                capture_output=True, timeout=30)
            if r.returncode != 0:
                self._logger(f"  [tar] host extract failed: {r.stderr.decode()[:120]}")
                return False
            self._logger(f"  [tar] restored to host {host_dir}")
            return True
        except Exception as exc:
            self._logger(f"  [tar] host restore error: {exc}")
            return False

    def restore_into_running(self) -> bool:
        if not self.exists:
            return False
        try:
            with open(self._tar_host_path, "rb") as f:
                subprocess.run(
                    ["sudo", "podman", "exec", "-i", self.container, "tar", "xf", "-", "-C", "/"],
                    stdin=f, capture_output=True, timeout=30)
            self._logger(f"  [tar] restored {self.container}")
            return True
        except Exception as exc:
            self._logger(f"  [tar] restore-into-running error: {exc}")
            return False

class CriuProcess:

    def __init__(self, checkpoint_dir: Path, logger: Callable[[str], None] | None = None):
        self._checkpoint_dir = checkpoint_dir
        self._logger = logger or (lambda m: None)

    def _checkpoint_path(self, container: str) -> Path:
        return self._checkpoint_dir / f"{container}-baseline.tar.gz"

    def checkpoint(self, container: str) -> bool:
        self._checkpoint_dir.mkdir(parents=True, exist_ok=True)
        ckpt = self._checkpoint_path(container)
        ckpt.unlink(missing_ok=True)
        self._logger(f"  [criu] creating checkpoint for {container}...")
        r = subprocess.run(
            ["sudo", "podman", "container", "checkpoint",
             "--tcp-established",
             "--export", str(ckpt), container],
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            self._logger(f"  [criu] checkpoint failed: {r.stderr.strip()[:80]}")
            return False
        size_kb = ckpt.stat().st_size // 1024
        self._logger(f"  [criu] checkpoint created ({size_kb} KB)")
        return True

    def restore(self, container: str) -> bool:
        ckpt = self._checkpoint_path(container)
        if not ckpt.exists():
            self._logger(f"  [criu] no checkpoint file for {container}")
            return False
        subprocess.run(["sudo", "podman", "rm", "-f", "--volumes", container],
                       capture_output=True, timeout=20)
        subprocess.run(["sudo", "podman", "volume", "prune", "-f"],
                       capture_output=True, timeout=10)
        r = subprocess.run(
            ["sudo", "podman", "container", "restore",
             "--tcp-established",
             "--import", str(ckpt)],
            capture_output=True, text=True, timeout=300)
        if r.returncode == 0:
            try:
                resolv = Path("/etc/resolv.conf").read_text()
                subprocess.run(
                    ["sudo", "podman", "exec", container,
                     "sh", "-c", f"cat > /etc/resolv.conf << 'RESOLV'\n{resolv}RESOLV"],
                    capture_output=True, timeout=5)
            except Exception:
                pass
            self._logger(f"  [criu] restored {container}")
            return True
        self._logger(f"  [criu] restore failed: {r.stderr.strip()[:80]}")
        return False

class DockerRestart:

    def __init__(self, logger: Callable[[str], None] | None = None):
        self._logger = logger or (lambda m: None)

    def restart(self, container: str) -> bool:
        subprocess.run(["sudo", "podman", "start", container], capture_output=True, timeout=30)
        self._logger(f"  [restart] started {container}")
        return True

class MysqlDumpSnapshot:

    def __init__(self, container: str, dump_path: Path,
                 logger: Callable[[str], None] | None = None):
        self.container = container
        self.dump_path = dump_path
        self._logger = logger or (lambda m: None)

    @property
    def exists(self) -> bool:
        return self.dump_path.exists()

    def capture(self) -> bool:
        self.dump_path.parent.mkdir(parents=True, exist_ok=True)
        r = subprocess.run(
            ["sudo", "podman", "exec", self.container,
             "mysqldump", "-h", "127.0.0.1", "-u", "rpstir2", f"-p{os.environ.get('RPKIWI_MYSQL_PASSWORD', '')}",
             "--skip-lock-tables", "rpstir2"],
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            self._logger(f"  [mysql] dump failed: {r.stderr.strip()[:80]}")
            return False
        self.dump_path.write_text(r.stdout)
        size_kb = self.dump_path.stat().st_size // 1024
        self._logger(f"  [mysql] dumped ({size_kb} KB)")
        return True

    def restore(self) -> bool:
        if not self.exists:
            self._logger(f"  [mysql] no dump file")
            return False
        r = subprocess.run(
            ["sudo", "podman", "exec", "-i", self.container,
             "mysql", "-h", "127.0.0.1", "-u", "rpstir2", f"-p{os.environ.get('RPKIWI_MYSQL_PASSWORD', '')}", "rpstir2"],
            input=self.dump_path.read_text(),
            capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            self._logger(f"  [mysql] restore failed: {r.stderr.strip()[:80]}")
            return False
        self._logger(f"  [mysql] restored")
        return True

    def clear_rrdp_cache(self) -> bool:
        subprocess.run(
            ["sudo", "podman", "exec", self.container, "sh", "-c",
             "rm -rf /root/rpki/data/rrdprepo/* /root/rpki/data/rrdprepo/.[!.]*"],
            capture_output=True, timeout=10)
        r = subprocess.run(
            ["sudo", "podman", "exec", self.container,
             "mysql", "-h", "127.0.0.1", "-u", "rpstir2", f"-p{os.environ.get('RPKIWI_MYSQL_PASSWORD', '')}", "rpstir2",
             "-e", "TRUNCATE lab_rpki_sync_rrdp_log; TRUNCATE lab_rpki_sync_log; TRUNCATE lab_rpki_sync_log_file"],
            capture_output=True, timeout=10)
        self._logger(f"  [mysql] cleared RRDP cache + sync logs")
        return True

    def trigger_sync(self) -> bool:
        subprocess.run(
            ["sudo", "podman", "exec", self.container, "curl", "-sk",
             "-d", '{"syncStyle": "sync"}',
             "-H", "Content-type: application/json",
             "-X", "POST", "https://127.0.0.1:8071/entiresync/syncstart"],
            capture_output=True, timeout=10)
        self._logger(f"  [mysql] sync triggered")
        return True

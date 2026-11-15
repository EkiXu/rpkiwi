from __future__ import annotations

import hashlib
import json
import shutil
import time
from pathlib import Path
from typing import Union

from src.rpkiwi.config import RPKIConfig
from src.rpkiwi.input.test_input import TestInput
from src.rpkiwi.input.utils import compute_sha256
from src.rpkiwi.input.generator import generate_manifest, generate_crl, generate_roa
from src.rpkiwi.input.xmlme.rrdp import write_snapshot, write_notification

PP_CONFIGS = {
    "attacker-pp": ("attacker-pp.com", "attacker-ca"),
    "victim-pp": ("victim-pp.com", "victim-ca"),
}

def _clear_dir_contents(directory: Path) -> None:
    if directory.exists():
        for entry in directory.iterdir():
            try:
                if entry.is_dir():
                    shutil.rmtree(entry, ignore_errors=True)
                else:
                    entry.unlink(missing_ok=True)
            except OSError:
                pass

def apply_version(pp_name: str, version: str, build_dir: str) -> None:
    version_dir = Path(build_dir) / "versions" / pp_name / version
    if not version_dir.exists():
        raise FileNotFoundError(f"Version directory not found: {version_dir}")

    domain, ca_name = PP_CONFIGS[pp_name]
    config = RPKIConfig(base_domain=domain, ca_name=ca_name, build_dir=build_dir)

    pp_dir = Path(config.ca_publish_dir)
    rrdp_dir = Path(config.ca_publication_dir) / config.ca_local_rrdp_base_path
    src_dir = Path(config.ca_source_dir)

    _clear_dir_contents(pp_dir)
    repo_src = version_dir / "repo"
    if repo_src.exists():
        for f in repo_src.rglob("*"):
            if f.is_file():
                rel = f.relative_to(repo_src)
                target = pp_dir / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, target)

    _clear_dir_contents(rrdp_dir)
    rrdp_src = version_dir / "rrdp"
    if rrdp_src.exists():
        for f in rrdp_src.rglob("*"):
            if f.is_file():
                rel = f.relative_to(rrdp_src)
                target = rrdp_dir / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, target)

    source_src = version_dir / "source"
    if source_src.exists():
        for f in src_dir.iterdir():
            if f.is_file() and not f.name.endswith(".key"):
                f.unlink(missing_ok=True)
        for f in source_src.iterdir():
            if f.is_file():
                shutil.copy2(f, src_dir / f.name)

    import os
    notif = rrdp_dir / "notification.xml"
    if notif.exists():
        os.utime(notif)

def detect_aspa(build_dir: str) -> bool:
    manifest_path = Path(build_dir) / ".manifest.json"
    if manifest_path.exists():
        try:
            return json.loads(manifest_path.read_text()).get("with_aspa", True)
        except (json.JSONDecodeError, OSError):
            pass
    return True

class PPScaffold:
    def __init__(
        self,
        config: RPKIConfig,
        *,
        exclude_asa: bool = False,
    ):
        self.config = config
        self.exclude_asa = exclude_asa

        self._pp_dir = Path(config.ca_publish_dir)
        self._source_dir = Path(config.ca_source_dir)
        self._rrdp_base = Path(config.ca_publication_dir) / config.ca_local_rrdp_base_path

        self._baseline_source: dict[str, bytes] = {}
        self._capture_source_baseline()

    def _capture_source_baseline(self) -> None:
        self._baseline_source.clear()
        if self._source_dir.exists():
            for f in self._source_dir.iterdir():
                if f.is_file() and not f.name.endswith('.key'):
                    self._baseline_source[f.name] = f.read_bytes()

    def save_baseline(self) -> None:
        pass

    def restore_baseline(self) -> None:
        versions_dir = Path(self.config.build_dir) / "versions" / "attacker-pp" / "baseline"
        if versions_dir.exists():
            apply_version("attacker-pp", "baseline", self.config.build_dir)
            self._capture_source_baseline()
        else:
            pass

    def switch_victim_version(self, version: str) -> None:
        apply_version("victim-pp", version, self.config.build_dir)
        self._resync_attacker_notification_to_foreign_rpki_notify()

    def switch_canary_version(self, version: str) -> None:
        import os
        try:
            from src.rpkiwi.lab.bootstrap import _restore_myta, _config_for_ca
        except ImportError as exc:
            raise RuntimeError(
                "laboratory provisioning is not included in this artifact; "
                "switch_canary_version requires a full laboratory deployment") from exc
        version_dir = Path(self.config.build_dir) / "versions" / "myta" / version
        if not version_dir.exists():
            return
        myta_pub = Path(self.config.build_dir) / "publication" / "myta.com"
        canary_config = _config_for_ca("canary-ca")
        canary_src = Path(canary_config.ca_source_dir)
        _restore_myta(myta_pub, canary_src, version_dir)
        # _restore_myta() copies version files with copy2, which preserves their
        # old mtimes. Validators that honor HTTP If-Modified-Since (FORT among
        # them) then see a 304 for the new notification and never detect the
        # version change, so their canary/myta RRDP workspace is never updated.
        # apply_version() already does this for victim/attacker PP versions;
        # do the same for the myta publication notification; otherwise an
        # If-Modified-Since-aware validator can miss the T2 canary update.
        notif = myta_pub / "rrdp" / "notification.xml"
        if notif.exists():
            os.utime(notif)

    def switch_scenario(self, version: str) -> None:
        self.switch_victim_version(version)
        self.switch_canary_version(version)

    def _resync_attacker_notification_to_foreign_rpki_notify(self) -> None:
        if not self._pp_dir.exists():
            return
        for cer_path in sorted(self._pp_dir.glob("*.cer")):
            try:
                self._sync_notification_from_ca_notify(cer_path.read_bytes())
            except Exception:
                continue

    def _clear_pp_contents(self) -> None:
        if self._pp_dir.exists():
            for entry in self._pp_dir.iterdir():
                try:
                    if entry.is_dir():
                        shutil.rmtree(entry, ignore_errors=True)
                    else:
                        entry.unlink(missing_ok=True)
                except OSError:
                    pass

    def _clear_rrdp_session_dirs(self) -> None:
        if self._rrdp_base.exists():
            for entry in self._rrdp_base.iterdir():
                try:
                    if entry.is_dir():
                        shutil.rmtree(entry, ignore_errors=True)
                    elif entry.name != "notification.xml":
                        entry.unlink(missing_ok=True)
                except OSError:
                    pass

    def _write_source_file(self, name: str, data: bytes) -> Path:
        self._source_dir.mkdir(parents=True, exist_ok=True)
        path = self._source_dir / name
        path.write_bytes(data)
        return path

    def _find_snapshot_file(self) -> Path | None:
        for p in self._rrdp_base.rglob("snapshot.xml"):
            return p
        return None

    def _find_baseline_filename(self, ext: str) -> str | None:
        for name in self._baseline_source:
            if name.endswith(ext) and not name.endswith('-ee.cer'):
                return name
        return None

    def scaffold(self, test_input: Union[TestInput, bytes], object_type: str | None = None) -> Path:
        _APPEND_DEFAULT_TYPES = {"ROA", "ASPA"}

        if isinstance(test_input, TestInput):
            raw_bytes = test_input.data
            object_type = test_input.object_type
            default_mode = "append" if object_type.upper() in _APPEND_DEFAULT_TYPES else "replace"
            scaffold_mode = test_input.metadata.get("scaffold_mode", default_mode)
        else:
            raw_bytes = test_input
            scaffold_mode = "replace"
            if object_type is None:
                raise ValueError("object_type is required when passing raw bytes")

        object_type = object_type.upper()

        if scaffold_mode == "append":
            return self._scaffold_append(raw_bytes, object_type, test_input)

        if object_type == "SNAPSHOT":
            self._clear_pp_contents()
            self._clear_rrdp_session_dirs()

            meta_ast = self._get_rrdp_ast(test_input)
            session_id = self._ast_field(meta_ast, "session_id", "direct")
            serial = self._ast_field(meta_ast, "serial", 1)

            snapshot_dir = self._rrdp_base / str(session_id)
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            snapshot_path = snapshot_dir / "snapshot.xml"
            snapshot_path.write_bytes(raw_bytes)
            snapshot_hash = hashlib.sha256(raw_bytes).hexdigest()
            snapshot_uri = (
                f"https://{self.config.ca_base_domain}/"
                f"{self.config.ca_rrdp_base_path}/{session_id}/snapshot.xml"
            )
            notif_xml = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<notification version="1" session_id="{session_id}" serial="{serial}" '
                f'xmlns="http://www.ripe.net/rpki/rrdp">\n'
                f'  <snapshot uri="{snapshot_uri}" '
                f'hash="{snapshot_hash}"/>\n'
                f'</notification>'
            )
            notif_path = Path(self.config.ca_rrdp_notification_path)
            notif_path.parent.mkdir(parents=True, exist_ok=True)
            notif_path.write_text(notif_xml)
            return self._pp_dir

        if object_type == "NOTIFICATION":
            notif_path = Path(self.config.ca_rrdp_notification_path)
            notif_path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(test_input, TestInput) and test_input.metadata.get("bump_victim_rrdp"):
                self._bump_victim_rrdp()
                raw_bytes = self._rewrite_notification_with_current_victim(raw_bytes)

            meta_ast = self._get_rrdp_ast(test_input)
            if meta_ast is not None:
                session_id = self._ast_field(meta_ast, "session_id")
                serial = self._ast_field(meta_ast, "serial")
                if session_id is not None and serial is not None:
                    self._ensure_snapshot_for_notification(session_id, serial)

            notif_path.write_bytes(raw_bytes)
            return self._pp_dir

        if object_type == "DELTA":
            import re as _re

            notif_path = Path(self.config.ca_rrdp_notification_path)
            if not notif_path.exists():
                self._logger("  [scaffold] no existing notification — cannot inject delta")
                return self._pp_dir

            old_notif = notif_path.read_text(encoding="utf-8")
            m_session = _re.search(r'session_id="([^"]+)"', old_notif)
            m_serial = _re.search(r'serial="(\d+)"', old_notif)
            if not m_session or not m_serial:
                self._logger("  [scaffold] cannot parse existing notification")
                return self._pp_dir

            session_id = m_session.group(1)
            old_serial = int(m_serial.group(1))

            delta_text = raw_bytes.decode("utf-8", errors="replace")
            m_delta_session = _re.search(r'session_id="([^"]+)"', delta_text)
            m_delta_serial = _re.search(r'serial="(\d+)"', delta_text)
            if m_delta_session:
                session_id = m_delta_session.group(1)
            new_serial = int(m_delta_serial.group(1)) if m_delta_serial else old_serial + 1

            delta_hash_short = hashlib.sha256(raw_bytes).hexdigest()[:16]
            delta_dir = self._rrdp_base / session_id / str(new_serial) / delta_hash_short
            delta_dir.mkdir(parents=True, exist_ok=True)
            delta_path = delta_dir / "delta.xml"
            delta_path.write_bytes(raw_bytes)
            delta_hash = hashlib.sha256(raw_bytes).hexdigest()
            delta_uri = (
                f"https://{self.config.ca_base_domain}/"
                f"{self.config.ca_rrdp_base_path}/"
                f"{session_id}/{new_serial}/{delta_hash_short}/delta.xml"
            )

            snap_path, _, snap_hash = write_snapshot(
                self.config, session_id=session_id, serial=new_serial,
            )

            from src.rpkiwi.input.xmlme.rrdp import (
                write_notification as _write_notif,
                write_delta as _write_delta,
            )
            dummy_xml = (
                f'<?xml version="1.0" encoding="UTF-8"?>\n'
                f'<delta version="1" session_id="{session_id}" serial="{old_serial}" '
                f'xmlns="http://www.ripe.net/rpki/rrdp"></delta>'
            ).encode("utf-8")
            dummy_dir = self._rrdp_base / session_id / str(old_serial)
            dummy_hash_short = hashlib.sha256(dummy_xml).hexdigest()[:16]
            (dummy_dir / dummy_hash_short).mkdir(parents=True, exist_ok=True)
            (dummy_dir / dummy_hash_short / "delta.xml").write_bytes(dummy_xml)
            dummy_hash = hashlib.sha256(dummy_xml).hexdigest()

            _write_notif(
                self.config, session_id, new_serial, snap_hash,
                deltas=[
                    (old_serial, dummy_hash),
                    (new_serial, delta_hash),
                ],
            )
            return self._pp_dir

        self._clear_source_dir_objects()
        self._clear_pp_contents()

        ca_name = self.config.ca_name
        if object_type == "ROA":
            baseline_name = self._find_baseline_filename(".roa") or "fuzz.roa"
            self._write_source_file(baseline_name, raw_bytes)
            self._write_baseline_objects_except("roa")
        elif object_type == "ASPA":
            baseline_name = self._find_baseline_filename(".asa") or "fuzz.asa"
            self._write_source_file(baseline_name, raw_bytes)
            self._write_baseline_objects_except("asa")
        elif object_type == "MFT":
            self._write_source_file(f"{ca_name}.mft", raw_bytes)
            self._write_baseline_objects_except("mft")
            # Deliberately not _regenerate_mft_and_deploy(): that synthesizes a
            # fresh manifest from file_list, which would overwrite the exact
            # bytes we just injected. But deploy_ca_files() (source -> publish
            # copy) is still required before _deploy_and_rrdp() rebuilds the
            # RRDP snapshot/notification from the publish dir — without it,
            # the injected manifest was never copied into ca_publish_dir, so
            # neither rsync nor RRDP ever served it and the validator kept
            # seeing the stale baseline manifest. The publish copy must be
            # refreshed before the RRDP snapshot is rebuilt, otherwise the
            # injected manifest never reaches the validator.
            self.config.deploy_ca_files()
            self._deploy_and_rrdp()
            return self._pp_dir
        elif object_type == "CRL":
            self._write_source_file(f"{ca_name}.crl", raw_bytes)
            self._write_baseline_objects_except("crl")
            self._regenerate_mft_and_deploy()
            return self._pp_dir
        elif object_type == "CER":
            self._write_source_file("child-ca.cer", raw_bytes)
            self._write_baseline_objects_except("cer")
            self._regenerate_mft_and_deploy()
            sync_with_ca_notify = True
            if isinstance(test_input, TestInput):
                sync_with_ca_notify = test_input.metadata.get("sync_notification_with_ca", True)
            if sync_with_ca_notify:
                self._sync_notification_from_ca_notify(raw_bytes)
            return self._pp_dir
        else:
            self._write_source_file(f"fuzz-object.{object_type.lower()}", raw_bytes)
            self._write_baseline_objects_except(object_type.lower())

        self._regenerate_mft_and_deploy()
        return self._pp_dir

    def _scaffold_append(self, raw_bytes: bytes, object_type: str, test_input) -> Path:
        metadata = test_input.metadata if hasattr(test_input, 'metadata') else {}
        append_filename = metadata.get("append_filename", f"mal-fuzz.{object_type.lower()}")

        self.restore_baseline()

        target = self._pp_dir / append_filename
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw_bytes)

        self._regenerate_mft_and_deploy()

        if object_type.upper() == "CER":
            sync_with_ca_notify = metadata.get("sync_notification_with_ca", True)
            if sync_with_ca_notify:
                self._sync_notification_from_ca_notify(raw_bytes)

        return self._pp_dir

    @staticmethod
    def _get_rrdp_ast(test_input) -> dict | None:
        if not isinstance(test_input, TestInput):
            return None
        ast_dict = test_input.metadata.get("ast")
        if not ast_dict or not isinstance(ast_dict, dict):
            return None
        from src.rpkiwi.input.rrdp_ast import is_rrdp_semantic_ast
        if is_rrdp_semantic_ast(ast_dict):
            return ast_dict
        return None

    @staticmethod
    def _ast_field(ast_dict: dict, label: str, default=None):
        for child in ast_dict.get("c", []):
            if child.get("n") == label:
                return child.get("v", default)
        return default

    def _ensure_snapshot_for_notification(self, session_id: str, serial: int) -> None:
        snapshot_dir = self._rrdp_base / str(session_id)
        if snapshot_dir.exists() and any(snapshot_dir.rglob("snapshot.xml")):
            return
        snapshot_dir.mkdir(parents=True, exist_ok=True)
        snap_path, _, snap_hash = write_snapshot(
            self.config, session_id=str(session_id), serial=int(serial),
        )

    def _clear_source_dir_objects(self) -> None:
        if self._source_dir.exists():
            for f in self._source_dir.iterdir():
                if f.is_file() and not f.name.endswith(('.key', '.cer')):
                    if f.name != f"{self.config.ca_name}.cer":
                        f.unlink(missing_ok=True)

    def _write_baseline_objects_except(self, skip_ext: str) -> None:
        for name, data in self._baseline_source.items():
            if name.endswith('.key') or name == f"{self.config.ca_name}.cer":
                continue
            if name.endswith(f".{skip_ext}"):
                continue
            if name.endswith('-ee.cer'):
                continue
            if self.exclude_asa and name.endswith('.asa'):
                continue
            self._write_source_file(name, data)

    def _write_baseline_crl(self) -> None:
        ca_name = self.config.ca_name
        crl_name = f"{ca_name}.crl"
        if crl_name in self._baseline_source:
            self._write_source_file(crl_name, self._baseline_source[crl_name])
        else:
            crl_data = generate_crl(self.config)
            self._write_source_file(crl_name, crl_data)

    def _regenerate_mft_and_deploy(self) -> None:
        self.config.deploy_ca_files()

        file_list = []
        pp = self._pp_dir
        if pp.exists():
            for f in sorted(pp.iterdir()):
                if not f.is_file():
                    continue
                if f.name == f"{self.config.ca_name}.cer":
                    continue
                if f.name.endswith(('.roa', '.asa', '.crl', '.cer')):
                    if self.exclude_asa and f.name.endswith('.asa'):
                        f.unlink(missing_ok=True)
                        continue
                    file_list.append((f.name, compute_sha256(f.read_bytes())))

        mft_data, _ = generate_manifest(self.config, file_list)
        mft_name = f"{self.config.ca_name}.mft"
        self._write_source_file(mft_name, mft_data)

        mft_pub = pp / mft_name
        mft_pub.write_bytes(mft_data)

        self._deploy_and_rrdp()

    def _deploy_and_rrdp(self) -> None:
        import re, time
        self._clear_rrdp_session_dirs()
        notif_path = Path(self.config.ca_rrdp_notification_path)
        old_session = None
        old_serial = 0
        if notif_path.exists():
            notif_text = notif_path.read_text(encoding="utf-8")
            m_session = re.search(r'session_id="([^"]+)"', notif_text)
            m_serial = re.search(r'serial="(\d+)"', notif_text)
            if m_session:
                old_session = m_session.group(1)
            if m_serial:
                old_serial = int(m_serial.group(1))
        serial = max(old_serial + 1, int(time.time()))
        snapshot_path, session_id, snapshot_hash = write_snapshot(self.config, session_id=old_session, serial=serial)
        write_notification(self.config, session_id, serial, snapshot_hash)

    def _sync_notification_from_ca_notify(self, cert_bytes: bytes) -> None:
        import re
        from urllib.parse import urlparse

        text = cert_bytes.decode('latin1', errors='ignore')
        match = re.search(
            r'https?://[A-Za-z0-9._~:/?#\-]+?/notification\.xml',
            text,
        )
        if match is None:
            return
        notify_url = match.group(0)

        parsed = urlparse(notify_url)
        if not parsed.hostname:
            return
        target_notif = (
            Path(self.config.build_dir)
            / "publication"
            / parsed.hostname
            / parsed.path.lstrip("/")
        )
        self_notif = Path(self.config.ca_rrdp_notification_path)
        if (
            not target_notif.exists()
            or target_notif.resolve() == self_notif.resolve()
            or not self_notif.exists()
        ):
            return

        target_text = target_notif.read_text(encoding="utf-8")
        snap = re.search(r'<snapshot\s+uri="([^"]+)"\s+hash="([^"]+)"', target_text)
        if snap is None:
            return
        target_uri, target_hash = snap.group(1), snap.group(2)
        current = self_notif.read_text(encoding="utf-8")
        current = re.sub(
            r'<snapshot\s[^>]*/>',
            f'<snapshot uri="{target_uri}" hash="{target_hash}"/>',
            current,
            count=1,
        )
        serial_m = re.search(r'serial="(\d+)"', current)
        if serial_m:
            current = re.sub(
                r'serial="\d+"',
                f'serial="{int(serial_m.group(1)) + 1}"',
                current,
                count=1,
            )
        self_notif.write_text(current, encoding="utf-8")

    def _bump_victim_rrdp(self) -> None:
        import re
        v_config = RPKIConfig(base_domain="victim-pp.com", ca_name="victim-ca",
                              build_dir=self.config.build_dir)
        notif_path = Path(v_config.ca_rrdp_notification_path)
        old_notif = notif_path.read_text(encoding="utf-8") if notif_path.exists() else ""
        m = re.search(r'session_id="([^"]+)"', old_notif)
        old_session = m.group(1) if m else None

        pp = Path(v_config.ca_publish_dir)
        src = Path(v_config.ca_source_dir)
        rrdp = Path(v_config.ca_publication_dir) / v_config.ca_local_rrdp_base_path

        v_config.deploy_ca_files()

        file_list = []
        if pp.exists():
            for f in sorted(pp.iterdir()):
                if not f.is_file() or f.name == f"{v_config.ca_name}.cer":
                    continue
                if f.name.endswith(('.roa', '.asa', '.crl', '.cer', '.mft')):
                    file_list.append((f.name, compute_sha256(f.read_bytes())))

        mft_data, _ = generate_manifest(v_config, file_list)
        mft_name = f"{v_config.ca_name}.mft"
        (src / mft_name).write_bytes(mft_data)
        (pp / mft_name).write_bytes(mft_data)

        if rrdp.exists():
            for entry in rrdp.iterdir():
                try:
                    if entry.is_dir():
                        shutil.rmtree(entry, ignore_errors=True)
                    elif entry.name != "notification.xml":
                        entry.unlink(missing_ok=True)
                except OSError:
                    pass

        serial = int(time.time())
        snapshot_path, session_id, snapshot_hash = write_snapshot(
            v_config, session_id=old_session, serial=serial,
        )
        write_notification(v_config, session_id, serial, snapshot_hash)

    def _rewrite_notification_with_current_victim(self, notification_bytes: bytes) -> bytes:
        import re
        v_config = RPKIConfig(base_domain="victim-pp.com", ca_name="victim-ca",
                              build_dir=self.config.build_dir)
        v_notif = Path(v_config.ca_rrdp_notification_path).read_text(encoding="utf-8")
        m = re.search(r'<snapshot\s+uri="([^"]+)"\s+hash="([^"]+)"', v_notif)
        if m is None:
            return notification_bytes
        victim_uri, victim_hash = m.group(1), m.group(2)
        text = notification_bytes.decode("utf-8")
        text = re.sub(r'<snapshot\s[^>]*/>', f'<snapshot uri="{victim_uri}" hash="{victim_hash}"/>', text, count=1)
        serial_m = re.search(r'serial="(\d+)"', text)
        if serial_m:
            text = re.sub(r'serial="\d+"', f'serial="{int(serial_m.group(1)) + 1}"', text, count=1)
        return text.encode("utf-8")

from __future__ import annotations

import hashlib
import ipaddress
import os
import shutil
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
LAB_BUILD = REPO_ROOT / "build"

def encode_ip_prefix_to_bitstring(prefix_str: str) -> bytes:
    network = ipaddress.ip_network(prefix_str, strict=False)
    prefix_bytes = network.network_address.packed
    prefix_len = network.prefixlen
    num_bytes = (prefix_len + 7) // 8
    unused_bits = (num_bytes * 8) - prefix_len
    ip_bytes = prefix_bytes[:num_bytes]
    return bytes([unused_bits]) + ip_bytes

def format_prefix_for_filename(prefix: str) -> str:
    ip, masklen = prefix.split('/')
    ip_parts = ip.split('.')
    return f"{'-'.join(ip_parts)}-{masklen}"

def compute_file_hash(file_path: str) -> bytes:
    with open(file_path, 'rb') as f:
        return hashlib.sha256(f.read()).digest()

class RPKIConfig:
    def __init__(
        self,
        *,
        base_domain: str = "attacker-pp.com",
        build_dir: str | None = None,
        ta_name: str = "ta",
        ca_name: str = "attacker-ca",
    ):
        self.base_domain = base_domain
        self.build_dir = build_dir or str(LAB_BUILD)
        self.ta_name = ta_name
        self.ca_name = ca_name

    @property
    def identity_dir(self) -> str:
        return os.path.join(self.build_dir, "identity")

    @property
    def publication_dir(self) -> str:
        return os.path.join(self.build_dir, "publication")

    @property
    def tls_dir(self) -> str:
        return os.path.join(self.build_dir, "tls")

    @property
    def ta_publication_dir(self) -> str:
        return os.path.join(self.publication_dir, "myta.com")

    @property
    def ca_publication_dir(self) -> str:
        return os.path.join(self.publication_dir, self.ca_base_domain)

    @property
    def ca_base_domain(self) -> str:
        return getattr(self, '_ca_base_domain', self.base_domain)

    @property
    def ca_repo_base_path(self) -> str:
        return getattr(self, '_ca_repo_base_path', f'repo/{self.ca_name}')

    @property
    def ca_rrdp_base_path(self) -> str:
        return getattr(self, '_ca_rrdp_base_path', f'rrdp/{self.ca_name}')

    @property
    def ca_local_repo_path(self) -> str:
        return getattr(self, '_ca_local_repo_path', self.ca_repo_base_path)

    @property
    def ca_local_rrdp_base_path(self) -> str:
        return getattr(self, '_ca_local_rrdp_base_path', self.ca_rrdp_base_path)

    @property
    def ca_cert_publish_rel_path(self) -> str:
        return getattr(self, '_ca_cert_publish_rel_path', f'ta/{self.ca_name}.cer')

    @property
    def ta_rrdp_base_path(self) -> str:
        return getattr(self, '_ta_rrdp_base_path', 'rrdp')

    @property
    def tal_path(self) -> str:
        return os.path.join(self.identity_dir, self.ta_name, 'myta.tal')

    @property
    def ta_sia_manifest_uri(self) -> str:
        return f'rsync://{self.base_domain}/ta/ta.mft'

    @property
    def ta_sia_repo_uri(self) -> str:
        return f'rsync://{self.base_domain}/ta/'

    @property
    def ta_sia_notify_uri(self) -> str:
        return f'https://{self.base_domain}/{self.ta_rrdp_base_path}/notification.xml'

    @property
    def ta_cert_uri(self) -> str:
        return f'rsync://{self.base_domain}/ta/ta.cer'

    @property
    def ta_source_dir(self) -> str:
        return os.path.join(self.identity_dir, self.ta_name)

    @property
    def ta_source_cert_path(self) -> str:
        return os.path.join(self.ta_source_dir, 'ta.cer')

    @property
    def ta_source_key_path(self) -> str:
        return os.path.join(self.ta_source_dir, 'ta.key')

    @property
    def ta_source_crl_path(self) -> str:
        return os.path.join(self.ta_source_dir, 'ta.crl')

    @property
    def ta_source_mft_path(self) -> str:
        return os.path.join(self.ta_source_dir, 'ta.mft')

    @property
    def ta_publish_dir(self) -> str:
        return os.path.join(self.ta_publication_dir, 'ta')

    @property
    def ta_publish_cert_path(self) -> str:
        return os.path.join(self.ta_publish_dir, 'ta.cer')

    @property
    def ta_publish_crl_path(self) -> str:
        return os.path.join(self.ta_publish_dir, 'ta.crl')

    @property
    def ta_publish_mft_path(self) -> str:
        return os.path.join(self.ta_publish_dir, 'ta.mft')

    @property
    def ca_source_dir(self) -> str:
        return os.path.join(self.identity_dir, 'ca', self.ca_name)

    @property
    def ca_source_cert_path(self) -> str:
        return os.path.join(self.ca_source_dir, f'{self.ca_name}.cer')

    @property
    def ca_source_key_path(self) -> str:
        return os.path.join(self.ca_source_dir, f'{self.ca_name}.key')

    @property
    def ca_source_crl_path(self) -> str:
        return os.path.join(self.ca_source_dir, f'{self.ca_name}.crl')

    @property
    def ca_source_mft_path(self) -> str:
        return os.path.join(self.ca_source_dir, f'{self.ca_name}.mft')

    @property
    def ca_publish_dir(self) -> str:
        return os.path.join(self.ca_publication_dir, self.ca_local_repo_path)

    @property
    def ca_publish_cert_path(self) -> str:
        return os.path.join(self.ta_publication_dir, self.ca_cert_publish_rel_path)

    @property
    def ca_publish_crl_path(self) -> str:
        return os.path.join(self.ca_publish_dir, f'{self.ca_name}.crl')

    @property
    def ca_publish_mft_path(self) -> str:
        return os.path.join(self.ca_publish_dir, f'{self.ca_name}.mft')

    @property
    def ca_rrdp_notification_path(self) -> str:
        return os.path.join(
            self.ca_publication_dir,
            self.ca_local_rrdp_base_path,
            'notification.xml',
        )

    @property
    def ca_sia_manifest_uri(self) -> str:
        return f'rsync://{self.ca_base_domain}/{self.ca_repo_base_path}/{self.ca_name}.mft'

    @property
    def ca_sia_repo_uri(self) -> str:
        return f'rsync://{self.ca_base_domain}/{self.ca_repo_base_path}/'

    @property
    def ca_sia_notify_uri(self) -> str:
        override = getattr(self, '_ca_sia_notify_override', None)
        if override is not None:
            return override
        return f'https://{self.ca_base_domain}/{self.ca_rrdp_base_path}/notification.xml'

    @property
    def ca_cert_uri(self) -> str:
        return f'rsync://myta.com/ta/{self.ca_name}.cer'

    @property
    def ca_crl_uri(self) -> str:
        return f'rsync://{self.ca_base_domain}/{self.ca_repo_base_path}/{self.ca_name}.crl'

    def roa_source_path(self, prefix: str, asn: int) -> str:
        prefix_str = format_prefix_for_filename(prefix)
        return os.path.join(self.ca_source_dir, f'{prefix_str}-AS{asn}.roa')

    def roa_publish_path(self, prefix: str, asn: int) -> str:
        prefix_str = format_prefix_for_filename(prefix)
        return os.path.join(self.ca_publish_dir, f'{prefix_str}-AS{asn}.roa')

    def rsync_uri(self, path: str) -> str:
        path = path.lstrip('./').lstrip('/')
        return f'rsync://{self.base_domain}/{path}'

    def https_uri(self, path: str) -> str:
        path = path.lstrip('./').lstrip('/')
        return f'https://{self.base_domain}/{path}'

    @property
    def ta_rrdp_notification_path(self) -> str:
        return os.path.join(self.ta_publication_dir, self.ta_rrdp_base_path, 'notification.xml')

    def rrdp_snapshot_path(self, session_id: str, serial: int, hash_short: str) -> str:
        return os.path.join(
            self.ta_publication_dir,
            self.ta_rrdp_base_path,
            session_id,
            str(serial),
            hash_short,
            'snapshot.xml',
        )

    def ca_rrdp_snapshot_path(self, session_id: str, serial: int, hash_short: str) -> str:
        return os.path.join(
            self.ca_publication_dir,
            self.ca_local_rrdp_base_path,
            session_id,
            str(serial),
            hash_short,
            'snapshot.xml',
        )

    def deploy_ca_files(self) -> List[str]:
        deployed = []
        os.makedirs(os.path.dirname(self.ca_publish_cert_path), exist_ok=True)
        os.makedirs(self.ca_publish_dir, exist_ok=True)

        if os.path.exists(self.ca_source_cert_path):
            shutil.copy2(self.ca_source_cert_path, self.ca_publish_cert_path)
            deployed.append(self.ca_publish_cert_path)

        for filename in os.listdir(self.ca_source_dir):
            if filename.endswith('.key') or filename == f'{self.ca_name}.cer':
                continue
            if filename.endswith('-ee.cer'):
                continue

            src = os.path.join(self.ca_source_dir, filename)
            dst = os.path.join(self.ca_publish_dir, filename)

            if os.path.isfile(src):
                shutil.copy2(src, dst)
                deployed.append(dst)

        return deployed

def attacker_config() -> RPKIConfig:
    return RPKIConfig(base_domain="attacker-pp.com", ca_name="attacker-ca")

def victim_config() -> RPKIConfig:
    return RPKIConfig(base_domain="victim-pp.com", ca_name="victim-ca")

_global_config: Optional[RPKIConfig] = None

def get_config() -> RPKIConfig:
    global _global_config
    if _global_config is None:
        _global_config = attacker_config()
    return _global_config

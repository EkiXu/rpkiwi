from __future__ import annotations

import base64
import hashlib
import os
import time
import uuid
from pathlib import Path
from typing import Tuple

from src.rpkiwi.config import RPKIConfig

def build_snapshot_xml(
    config: RPKIConfig,
    session_id: str | None = None,
    serial: int | None = None,
) -> Tuple[str, str, int, str]:
    if session_id is None:
        session_id = str(uuid.uuid4())
    if serial is None:
        serial = int(time.time())

    ca_pub_dir = config.ca_publish_dir
    files = []

    if os.path.exists(ca_pub_dir):
        for filename in os.listdir(ca_pub_dir):
            filepath = os.path.join(ca_pub_dir, filename)
            if not os.path.isfile(filepath):
                continue
            if filename in ('notification.xml', 'snapshot.xml'):
                continue
            if filename.endswith(('.crl', '.mft', '.roa', '.asa', '.cer')):
                if filename == f"{config.ca_name}.cer":
                    continue
                uri = f"rsync://{config.ca_base_domain}/{config.ca_repo_base_path}/{filename}"
                files.append((uri, filepath))

    files.sort(key=lambda x: x[0])

    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<snapshot version="1" session_id="{session_id}" serial="{serial}" xmlns="http://www.ripe.net/rpki/rrdp">',
    ]
    for uri, filepath in files:
        with open(filepath, 'rb') as f:
            content = f.read()
        content_b64 = base64.b64encode(content).decode('ascii')
        xml_parts.append(f'  <publish uri="{uri}">{content_b64}</publish>')
    xml_parts.append('</snapshot>')
    xml_content = '\n'.join(xml_parts)

    snapshot_hash = hashlib.sha256(xml_content.encode()).hexdigest()
    return xml_content, session_id, serial, snapshot_hash

def write_snapshot(config: RPKIConfig, session_id: str | None = None, serial: int | None = None) -> Tuple[str, str, str]:
    xml_content, session_id, serial, snapshot_hash = build_snapshot_xml(config, session_id, serial)
    snapshot_hash_short = snapshot_hash[:16]
    snapshot_path = config.ca_rrdp_snapshot_path(session_id, serial, snapshot_hash_short)
    os.makedirs(os.path.dirname(snapshot_path), exist_ok=True)
    with open(snapshot_path, 'w') as f:
        f.write(xml_content)
    return snapshot_path, session_id, snapshot_hash

def build_delta_xml(
    config: RPKIConfig,
    session_id: str,
    serial: int,
    publishes: list[tuple[str, bytes]] | None = None,
    withdraws: list[tuple[str, str]] | None = None,
) -> tuple[str, str]:
    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<delta version="1" session_id="{session_id}" serial="{serial}" '
        f'xmlns="http://www.ripe.net/rpki/rrdp">',
    ]
    for uri, content in (publishes or []):
        b64 = base64.b64encode(content).decode("ascii")
        xml_parts.append(f'  <publish uri="{uri}">{b64}</publish>')
    for uri, hash_hex in (withdraws or []):
        xml_parts.append(f'  <withdraw uri="{uri}" hash="{hash_hex}"/>')
    xml_parts.append("</delta>")
    xml_content = "\n".join(xml_parts)
    delta_hash = hashlib.sha256(xml_content.encode()).hexdigest()
    return xml_content, delta_hash

def write_delta(
    config: RPKIConfig,
    session_id: str,
    serial: int,
    publishes: list[tuple[str, bytes]] | None = None,
    withdraws: list[tuple[str, str]] | None = None,
) -> tuple[str, str]:
    xml_content, delta_hash = build_delta_xml(config, session_id, serial, publishes, withdraws)
    delta_hash_short = delta_hash[:16]
    delta_dir = os.path.join(
        config.ca_publication_dir, config.ca_local_rrdp_base_path,
        session_id, str(serial), delta_hash_short,
    )
    os.makedirs(delta_dir, exist_ok=True)
    delta_path = os.path.join(delta_dir, "delta.xml")
    with open(delta_path, "w") as f:
        f.write(xml_content)
    return delta_path, delta_hash

def write_notification(
    config: RPKIConfig,
    session_id: str,
    serial: int,
    snapshot_hash: str,
    deltas: list[tuple[int, str]] | None = None,
) -> str:
    snapshot_hash_short = snapshot_hash[:16]
    snapshot_uri = (
        f"https://{config.ca_base_domain}/{config.ca_rrdp_base_path}/"
        f"{session_id}/{serial}/{snapshot_hash_short}/snapshot.xml"
    )
    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<notification version="1" session_id="{session_id}" serial="{serial}" '
        f'xmlns="http://www.ripe.net/rpki/rrdp">',
        f'  <snapshot uri="{snapshot_uri}" hash="{snapshot_hash}"/>',
    ]
    for d_serial, d_hash in (deltas or []):
        d_hash_short = d_hash[:16]
        d_uri = (
            f"https://{config.ca_base_domain}/{config.ca_rrdp_base_path}/"
            f"{session_id}/{d_serial}/{d_hash_short}/delta.xml"
        )
        xml_parts.append(f'  <delta serial="{d_serial}" uri="{d_uri}" hash="{d_hash}"/>')
    xml_parts.append("</notification>")
    xml_content = "\n".join(xml_parts)
    notification_path = config.ca_rrdp_notification_path
    os.makedirs(os.path.dirname(notification_path), exist_ok=True)
    with open(notification_path, "w") as f:
        f.write(xml_content)
    return notification_path

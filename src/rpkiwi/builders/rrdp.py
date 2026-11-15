import os
import time
import uuid
import hashlib
from typing import Tuple

from src.rpkiwi.config import RPKIConfig

def update_ta_rrdp_notification(
    config: RPKIConfig,
    session_id: str,
    serial: int,
    snapshot_hash: str,
    deltas: list[tuple[int, str]] | None = None,
    verbose: bool = True,
) -> str:
    snapshot_hash_short = snapshot_hash[:16]
    snapshot_uri = (
        f"https://{config.base_domain}/{config.ta_rrdp_base_path}/"
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
            f"https://{config.base_domain}/{config.ta_rrdp_base_path}/"
            f"{session_id}/{d_serial}/{d_hash_short}/delta.xml"
        )
        xml_parts.append(f'  <delta serial="{d_serial}" uri="{d_uri}" hash="{d_hash}"/>')
    xml_parts.append("</notification>")
    xml_content = "\n".join(xml_parts)

    notification_path = config.ta_rrdp_notification_path
    notification_dir = os.path.dirname(notification_path)
    os.makedirs(notification_dir, exist_ok=True)

    with open(notification_path, 'w') as f:
        f.write(xml_content)

    if verbose:
        print(f"  TA Notification saved: {notification_path}")
        print(f"  TA Snapshot URI: {snapshot_uri}")

    return notification_path

def update_ta_rrdp_snapshot(config: RPKIConfig, session_id: str = None, serial: int = None, verbose: bool = True) -> Tuple[str, str, str]:
    import base64

    if session_id is None:
        session_id = str(uuid.uuid4())
    if serial is None:
        serial = int(time.time())

    if verbose:
        print(f"  TA RRDP Session: {session_id}")
        print(f"  TA RRDP Serial: {serial}")

    ta_pub_dir = config.ta_publish_dir
    files = []

    if verbose:
        print(f"  TA Publish Directory: {ta_pub_dir}")

    if os.path.exists(ta_pub_dir):
        for dirpath, _dirnames, filenames in os.walk(ta_pub_dir):
            for filename in filenames:
                if filename in ['notification.xml', 'snapshot.xml']:
                    continue
                if not filename.endswith(('.cer', '.crl', '.mft', '.roa', '.asa')):
                    continue

                filepath = os.path.join(dirpath, filename)
                rel = os.path.relpath(filepath, ta_pub_dir)
                uri = f"rsync://{config.base_domain}/ta/{rel}"
                files.append((uri, filepath))

    files.sort(key=lambda x: x[0])

    if verbose:
        print(f"  TA Discovered {len(files)} objects")
        for uri, _ in files:
            print(f"    - {os.path.basename(uri)}")

    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<snapshot version="1" session_id="{session_id}" serial="{serial}" xmlns="http://www.ripe.net/rpki/rrdp">'
    ]

    for uri, filepath in files:
        with open(filepath, 'rb') as f:
            content = f.read()
        content_b64 = base64.b64encode(content).decode('ascii')
        xml_parts.append(f'  <publish uri="{uri}">{content_b64}</publish>')

    xml_parts.append('</snapshot>')
    xml_content = '\n'.join(xml_parts)

    snapshot_hash = hashlib.sha256(xml_content.encode()).hexdigest()
    snapshot_hash_short = snapshot_hash[:16]

    snapshot_path = config.rrdp_snapshot_path(session_id, serial, snapshot_hash_short)
    snapshot_dir = os.path.dirname(snapshot_path)
    os.makedirs(snapshot_dir, exist_ok=True)

    with open(snapshot_path, 'w') as f:
        f.write(xml_content)

    if verbose:
        print(f"  TA Snapshot saved: {snapshot_path}")

    return snapshot_path, session_id, snapshot_hash

def write_ta_rrdp_delta(
    config: RPKIConfig,
    session_id: str,
    serial: int,
    publishes: list[tuple[str, bytes]] | None = None,
    withdraws: list[tuple[str, str]] | None = None,
    verbose: bool = True,
) -> tuple[str, str]:
    from src.rpkiwi.input.xmlme.rrdp import build_delta_xml
    xml_content, delta_hash = build_delta_xml(config, session_id, serial, publishes, withdraws)
    delta_hash_short = delta_hash[:16]
    delta_dir = os.path.join(
        config.ta_publication_dir, config.ta_rrdp_base_path,
        session_id, str(serial), delta_hash_short,
    )
    os.makedirs(delta_dir, exist_ok=True)
    delta_path = os.path.join(delta_dir, "delta.xml")
    with open(delta_path, 'w') as f:
        f.write(xml_content)
    if verbose:
        print(f"  TA Delta saved: {delta_path}")
    return delta_path, delta_hash

def update_rrdp_notification(config: RPKIConfig, session_id: str, serial: int, snapshot_hash: str, verbose: bool = True) -> str:
    snapshot_hash_short = snapshot_hash[:16]
    snapshot_uri = f"https://{config.ca_base_domain}/{config.ca_rrdp_base_path}/{session_id}/{serial}/{snapshot_hash_short}/snapshot.xml"

    xml_content = f'''<?xml version="1.0" encoding="UTF-8"?>
<notification version="1" session_id="{session_id}" serial="{serial}" xmlns="http://www.ripe.net/rpki/rrdp">
  <snapshot uri="{snapshot_uri}" hash="{snapshot_hash}"/>
</notification>'''

    notification_path = config.ca_rrdp_notification_path
    notification_dir = os.path.dirname(notification_path)
    os.makedirs(notification_dir, exist_ok=True)

    with open(notification_path, 'w') as f:
        f.write(xml_content)

    if verbose:
        print(f"  Notification saved: {notification_path}")
        print(f"  Snapshot URI: {snapshot_uri}")

    return notification_path

def update_rrdp_snapshot(config: RPKIConfig, session_id: str = None, serial: int = None, verbose: bool = True) -> Tuple[str, str, str]:
    import base64

    if session_id is None:
        session_id = str(uuid.uuid4())
    if serial is None:
        serial = int(time.time())

    if verbose:
        print(f"  RRDP Session: {session_id}")
        print(f"  RRDP Serial: {serial}")

    ca_pub_dir = config.ca_publish_dir
    files = []

    if verbose:
        print(f"  CA Publish Directory: {ca_pub_dir}")

    if os.path.exists(ca_pub_dir):
        for filename in os.listdir(ca_pub_dir):
            filepath = os.path.join(ca_pub_dir, filename)
            if not os.path.isfile(filepath):
                continue

            if filename in ['notification.xml', 'snapshot.xml']:
                continue

            if filename.endswith(('.crl', '.mft', '.roa', '.asa', '.cer')):
                if filename == f"{config.ca_name}.cer":
                    continue
                uri = f"rsync://{config.ca_base_domain}/{config.ca_repo_base_path}/{filename}"
                files.append((uri, filepath))

    files.sort(key=lambda x: x[0])

    if verbose:
        print(f"  Discovered {len(files)} objects")
        for uri, _ in files:
            print(f"    - {os.path.basename(uri)}")

    xml_parts = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        f'<snapshot version="1" session_id="{session_id}" serial="{serial}" xmlns="http://www.ripe.net/rpki/rrdp">'
    ]

    for uri, filepath in files:
        with open(filepath, 'rb') as f:
            content = f.read()
        content_b64 = base64.b64encode(content).decode('ascii')
        xml_parts.append(f'  <publish uri="{uri}">{content_b64}</publish>')

    xml_parts.append('</snapshot>')
    xml_content = '\n'.join(xml_parts)

    snapshot_hash = hashlib.sha256(xml_content.encode()).hexdigest()
    snapshot_hash_short = snapshot_hash[:16]

    snapshot_path = config.ca_rrdp_snapshot_path(session_id, serial, snapshot_hash_short)
    snapshot_dir = os.path.dirname(snapshot_path)
    os.makedirs(snapshot_dir, exist_ok=True)

    with open(snapshot_path, 'w') as f:
        f.write(xml_content)

    if verbose:
        print(f"  Snapshot saved: {snapshot_path}")

    return snapshot_path, session_id, snapshot_hash

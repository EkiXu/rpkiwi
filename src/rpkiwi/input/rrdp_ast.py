from __future__ import annotations

import base64
import xml.etree.ElementTree as ET
from pathlib import PurePosixPath

from src.rpkiwi.input.ast_node import ASTNode

RRDP_NS = "http://www.ripe.net/rpki/rrdp"
_CLARK = f"{{{RRDP_NS}}}"

_EXT_TO_OTYPE: dict[str, str] = {
    ".roa": "ROA",
    ".mft": "MFT",
    ".crl": "CRL",
    ".asa": "ASPA",
    ".cer": "CER",
}

_OTYPE_TO_EXT: dict[str, str] = {v: k for k, v in _EXT_TO_OTYPE.items()}

def _infer_content_type(uri: str) -> str:
    suffix = PurePosixPath(uri).suffix.lower()
    return _EXT_TO_OTYPE.get(suffix, "unknown")

def _parse_publish_content(b64_text: str, uri: str, config=None) -> tuple[ASTNode, str]:
    content_type = _infer_content_type(uri)
    try:
        raw = base64.b64decode(b64_text)
    except Exception:
        return ASTNode("content", value=b64_text), content_type

    if content_type in ("ROA", "MFT", "ASPA", "CRL", "CER"):
        try:
            return ASTNode.from_der(raw, content_type), content_type
        except Exception:
            pass

    return ASTNode("content", value=raw), content_type

def _serialize_publish_content(content_node: ASTNode, content_type: str, config=None) -> str:
    if content_node.is_leaf and isinstance(content_node.value, str):
        return content_node.value

    if content_node.is_leaf and isinstance(content_node.value, (bytes, bytearray)):
        return base64.b64encode(content_node.value).decode("ascii")

    if content_node.label in ("ContentInfo", "CertificateRevocationList", "CACertificate"):
        from src.rpkiwi.input.ast_node import serialize
        der_bytes = serialize(content_node, config, can_resign=False)
        return base64.b64encode(der_bytes).decode("ascii")

    if content_node.is_leaf and content_node.value is None:
        return ""

    from src.rpkiwi.input.ast_node import serialize
    try:
        der_bytes = serialize(content_node, config, can_resign=False)
        return base64.b64encode(der_bytes).decode("ascii")
    except Exception:
        return ""

def parse_rrdp_to_ast(data: bytes, object_type: str, config=None) -> ASTNode:
    otype = object_type.upper()
    root = ET.fromstring(data)
    if otype == "SNAPSHOT":
        return _parse_snapshot(root, config)
    elif otype == "NOTIFICATION":
        return _parse_notification(root)
    elif otype == "DELTA":
        return _parse_delta(root, config)
    raise ValueError(f"unknown RRDP type: {object_type!r}")

def _parse_snapshot(root: ET.Element, config=None) -> ASTNode:
    version = int(root.get("version", "1"))
    session_id = root.get("session_id", "")
    serial = int(root.get("serial", "0"))

    publish_nodes: list[ASTNode] = []
    for pub in root.findall(f"{_CLARK}publish"):
        uri = pub.get("uri", "")
        b64_text = (pub.text or "").strip()
        content_ast, content_type = _parse_publish_content(b64_text, uri, config)

        entry = ASTNode("PublishEntry", children=[
            ASTNode("uri", value=uri),
            ASTNode("content_type", value=content_type),
            content_ast,
        ])
        publish_nodes.append(entry)

    return ASTNode("RRDPSnapshot", children=[
        ASTNode("version", value=version),
        ASTNode("session_id", value=session_id),
        ASTNode("serial", value=serial),
        ASTNode("publishes", children=publish_nodes),
    ])

def _parse_notification(root: ET.Element) -> ASTNode:
    version = int(root.get("version", "1"))
    session_id = root.get("session_id", "")
    serial = int(root.get("serial", "0"))

    snapshot_ref_children: list[ASTNode] = []
    snap_elem = root.find(f"{_CLARK}snapshot")
    if snap_elem is not None:
        snapshot_ref_children = [
            ASTNode("uri", value=snap_elem.get("uri", "")),
            ASTNode("hash", value=snap_elem.get("hash", "")),
        ]

    delta_nodes: list[ASTNode] = []
    for delta_elem in root.findall(f"{_CLARK}delta"):
        delta_nodes.append(ASTNode("DeltaRef", children=[
            ASTNode("serial", value=int(delta_elem.get("serial", "0"))),
            ASTNode("uri", value=delta_elem.get("uri", "")),
            ASTNode("hash", value=delta_elem.get("hash", "")),
        ]))

    return ASTNode("RRDPNotification", children=[
        ASTNode("version", value=version),
        ASTNode("session_id", value=session_id),
        ASTNode("serial", value=serial),
        ASTNode("snapshot_ref", children=snapshot_ref_children),
        ASTNode("delta_refs", children=delta_nodes),
    ])

def _parse_delta(root: ET.Element, config=None) -> ASTNode:
    version = int(root.get("version", "1"))
    session_id = root.get("session_id", "")
    serial = int(root.get("serial", "0"))

    publish_nodes: list[ASTNode] = []
    for pub in root.findall(f"{_CLARK}publish"):
        uri = pub.get("uri", "")
        replace_hash = pub.get("hash")
        b64_text = (pub.text or "").strip()
        content_ast, content_type = _parse_publish_content(b64_text, uri, config)

        children = [
            ASTNode("uri", value=uri),
            ASTNode("content_type", value=content_type),
        ]
        if replace_hash is not None:
            children.append(ASTNode("replace_hash", value=replace_hash))
        children.append(content_ast)
        publish_nodes.append(ASTNode("PublishEntry", children=children))

    withdraw_nodes: list[ASTNode] = []
    for wd in root.findall(f"{_CLARK}withdraw"):
        withdraw_nodes.append(ASTNode("WithdrawEntry", children=[
            ASTNode("uri", value=wd.get("uri", "")),
            ASTNode("hash", value=wd.get("hash", "")),
        ]))

    return ASTNode("RRDPDelta", children=[
        ASTNode("version", value=version),
        ASTNode("session_id", value=session_id),
        ASTNode("serial", value=serial),
        ASTNode("publishes", children=publish_nodes),
        ASTNode("withdraws", children=withdraw_nodes),
    ])

def serialize_rrdp_from_ast(ast: ASTNode, object_type: str, config=None) -> bytes:
    otype = object_type.upper()
    if otype == "SNAPSHOT":
        return _serialize_snapshot(ast, config)
    elif otype == "NOTIFICATION":
        return _serialize_notification(ast)
    elif otype == "DELTA":
        return _serialize_delta(ast, config)
    raise ValueError(f"unknown RRDP type: {object_type!r}")

def _get_child_value(node: ASTNode, label: str, default=None):
    child = node.child(label)
    if child is None:
        return default
    return child.value

def _serialize_snapshot(ast: ASTNode, config=None) -> bytes:
    version = _get_child_value(ast, "version", 1)
    session_id = _get_child_value(ast, "session_id", "")
    serial = _get_child_value(ast, "serial", 0)

    ET.register_namespace("", RRDP_NS)
    root = ET.Element(f"{_CLARK}snapshot")
    root.set("version", str(version))
    root.set("session_id", str(session_id))
    root.set("serial", str(serial))

    publishes = ast.child("publishes")
    if publishes:
        for entry in publishes.children:
            uri = _get_child_value(entry, "uri", "")
            content_type = _get_child_value(entry, "content_type", "unknown")
            content_node = _find_content_node(entry)

            pub = ET.SubElement(root, f"{_CLARK}publish")
            pub.set("uri", str(uri))
            if content_node is not None:
                pub.text = _serialize_publish_content(content_node, content_type, config)

    return _et_to_bytes(root)

def _serialize_notification(ast: ASTNode) -> bytes:
    version = _get_child_value(ast, "version", 1)
    session_id = _get_child_value(ast, "session_id", "")
    serial = _get_child_value(ast, "serial", 0)

    ET.register_namespace("", RRDP_NS)
    root = ET.Element(f"{_CLARK}notification")
    root.set("version", str(version))
    root.set("session_id", str(session_id))
    root.set("serial", str(serial))

    snapshot_ref = ast.child("snapshot_ref")
    if snapshot_ref and snapshot_ref.children:
        snap = ET.SubElement(root, f"{_CLARK}snapshot")
        snap.set("uri", str(_get_child_value(snapshot_ref, "uri", "")))
        snap.set("hash", str(_get_child_value(snapshot_ref, "hash", "")))

    delta_refs = ast.child("delta_refs")
    if delta_refs:
        for dref in delta_refs.children:
            delta = ET.SubElement(root, f"{_CLARK}delta")
            delta.set("serial", str(_get_child_value(dref, "serial", 0)))
            delta.set("uri", str(_get_child_value(dref, "uri", "")))
            delta.set("hash", str(_get_child_value(dref, "hash", "")))

    return _et_to_bytes(root)

def _serialize_delta(ast: ASTNode, config=None) -> bytes:
    version = _get_child_value(ast, "version", 1)
    session_id = _get_child_value(ast, "session_id", "")
    serial = _get_child_value(ast, "serial", 0)

    ET.register_namespace("", RRDP_NS)
    root = ET.Element(f"{_CLARK}delta")
    root.set("version", str(version))
    root.set("session_id", str(session_id))
    root.set("serial", str(serial))

    publishes = ast.child("publishes")
    if publishes:
        for entry in publishes.children:
            uri = _get_child_value(entry, "uri", "")
            content_type = _get_child_value(entry, "content_type", "unknown")
            replace_hash = _get_child_value(entry, "replace_hash")
            content_node = _find_content_node(entry)

            pub = ET.SubElement(root, f"{_CLARK}publish")
            pub.set("uri", str(uri))
            if replace_hash is not None:
                pub.set("hash", str(replace_hash))
            if content_node is not None:
                pub.text = _serialize_publish_content(content_node, content_type, config)

    withdraws = ast.child("withdraws")
    if withdraws:
        for entry in withdraws.children:
            wd = ET.SubElement(root, f"{_CLARK}withdraw")
            wd.set("uri", str(_get_child_value(entry, "uri", "")))
            wd.set("hash", str(_get_child_value(entry, "hash", "")))

    return _et_to_bytes(root)

def _find_content_node(entry: ASTNode) -> ASTNode | None:
    for c in entry.children:
        if c.label not in ("uri", "content_type", "replace_hash"):
            return c
    return None

def _et_to_bytes(root: ET.Element) -> bytes:
    return ET.tostring(root, encoding="unicode", xml_declaration=True).encode("utf-8")

RRDP_ROOT_LABELS = {"RRDPSnapshot", "RRDPNotification", "RRDPDelta"}

def is_rrdp_semantic_ast(ast_dict: dict) -> bool:
    return ast_dict.get("n") in RRDP_ROOT_LABELS

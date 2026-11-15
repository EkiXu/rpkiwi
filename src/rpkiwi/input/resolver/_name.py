from __future__ import annotations

import time

from cryptography.x509.oid import NameOID

from src.rpkiwi.input.ast_node import ASTNode
from src.rpkiwi.input.resolver.context import ExpandContext
from src.rpkiwi.input.resolver.registry import register

@register("issuer")
def resolve_issuer(_node: ASTNode, ctx: ExpandContext) -> str:
    cn_attrs = ctx.ca_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return cn_attrs[0].value if cn_attrs else "unknown-issuer"

@register("subject")
def resolve_subject(node: ASTNode, ctx: ExpandContext) -> str:
    root = ctx.extras.get("_root")
    if root is None:
        return "RPKI-EE"
    ect = root.find("SignedData/encapContentInfo/eContentType") if hasattr(root, "find") else None
    if ect is None:
        return "RPKI-EE"
    mapping = {
        "routeOriginAttestation": "RPKI-EE-roa",
        "asProviderAttestation": "RPKI-EE-aspa",
        "manifest": "RPKI-EE-manifest",
    }
    return mapping.get(ect.value, f"RPKI-EE-{ect.value}")

@register("serialNumber")
def resolve_serial_number(_node: ASTNode, _ctx: ExpandContext) -> int:
    return int(time.time()) % 1_000_000

@register("contentType")
def resolve_content_type_attr(_node: ASTNode, ctx: ExpandContext) -> str:
    root = ctx.extras.get("_root")
    if root is None or not hasattr(root, "find"):
        return "routeOriginAttestation"
    ect = root.find("SignedData/encapContentInfo/eContentType")
    return ect.value if ect is not None else "routeOriginAttestation"

@register("manifestNumber")
def resolve_manifest_number(_node: ASTNode, _ctx: ExpandContext) -> int:
    return int(time.time())

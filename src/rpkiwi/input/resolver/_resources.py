from __future__ import annotations

from cryptography import x509

from src.rpkiwi.input.ast_node import ASTNode
from src.rpkiwi.input.resolver.context import ExpandContext
from src.rpkiwi.input.resolver.registry import register

@register("aki")
def resolve_aki(_node: ASTNode, ctx: ExpandContext) -> bytes:
    try:
        ski_ext = ctx.ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        return ski_ext.value.digest
    except x509.ExtensionNotFound:
        return b"\x00" * 20

@register("ipResources")
def resolve_ip_resources(_node: ASTNode, _ctx: ExpandContext) -> bytes:
    from src.rpkiwi.input.asnme.model.misc import encode_ip_resources_inherit
    return encode_ip_resources_inherit()

@register("asnResources")
def resolve_asn_resources(_node: ASTNode, _ctx: ExpandContext) -> bytes:
    from src.rpkiwi.input.asnme.model.misc import encode_as_resources_inherit
    return encode_as_resources_inherit()

@register("sia")
def resolve_sia(_node: ASTNode, _ctx: ExpandContext) -> bytes:
    return b""

@register("basicConstraints")
def resolve_basic_constraints(_node: ASTNode, _ctx: ExpandContext) -> bytes:
    return b"\x30\x00"

@register("crls")
def resolve_crls(_node: ASTNode, _ctx: ExpandContext):
    return None

@register("keyUsage")
def resolve_key_usage(_node: ASTNode, _ctx: ExpandContext) -> bytes:
    return b"\x05\x06"

@register("certPolicy")
def resolve_cert_policy(_node: ASTNode, _ctx: ExpandContext) -> bytes:
    return b""

@register("aia")
def resolve_aia(_node: ASTNode, _ctx: ExpandContext) -> bytes:
    return b""

@register("crlDP")
def resolve_crl_dp(_node: ASTNode, _ctx: ExpandContext) -> bytes:
    return b""

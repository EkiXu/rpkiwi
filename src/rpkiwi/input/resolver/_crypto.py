from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.rpkiwi.input.ast_encoder import _SEQ, _SET, _encode_tlv_raw, ast_to_der
from src.rpkiwi.input.ast_node import ASTNode
from src.rpkiwi.input.der_ast import DERNode
from src.rpkiwi.input.resolver.context import ExpandContext
from src.rpkiwi.input.resolver.registry import register

def _encode_econtent_body(root: ASTNode) -> bytes:
    ec = root.find("SignedData/encapContentInfo/eContent")
    if ec is None:
        raise ValueError("eContent not present in AST")
    if ec.children:
        inner = b"".join(ast_to_der(c) for c in ec.children)
        return _encode_tlv_raw(_SEQ, inner)
    if isinstance(ec.value, (bytes, bytearray)):
        return bytes(ec.value)
    raise ValueError("eContent has no children and no bytes value")

@register("messageDigest", deps=("eContent",))
def resolve_message_digest(_node: ASTNode, ctx: ExpandContext) -> bytes:
    root = ctx.extras.get("_root")
    if root is None:
        raise ValueError("messageDigest resolver: no _root in ExpandContext")
    body = _encode_econtent_body(root)
    return hashlib.sha256(body).digest()

@register("subjectPublicKeyInfo")
def resolve_spki(_node: ASTNode, ctx: ExpandContext) -> bytes:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    ctx.extras["_ee_privkey"] = priv
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def _ski_from_spki(spki_der: bytes) -> bytes:
    spki = DERNode.parse(spki_der)
    bit_string = spki.children[1]
    pub_bytes = bit_string.content[1:]
    return hashlib.sha1(pub_bytes).digest()

def _find_spki_leaf(root: ASTNode) -> ASTNode | None:
    if root.label == "ContentInfo":
        return root.find("SignedData/certificates/EECertificate/subjectPublicKeyInfo")
    if root.label == "CACertificate":
        return root.find("tbsCertificate/subjectPublicKeyInfo")
    return None

@register("ski", deps=("subjectPublicKeyInfo",))
def resolve_ski(_node: ASTNode, ctx: ExpandContext) -> bytes:
    root = ctx.extras.get("_root")
    if root is None:
        raise ValueError("ski resolver: no _root in ExpandContext")
    spki_node = _find_spki_leaf(root)
    if spki_node is None:
        raise ValueError("ski resolver: SPKI not found in AST")
    if not isinstance(spki_node.value, (bytes, bytearray)):
        raise ValueError("ski resolver: SPKI value is not bytes")
    return _ski_from_spki(bytes(spki_node.value))

@register("sid", deps=("ski",))
def resolve_sid(_node: ASTNode, ctx: ExpandContext) -> bytes:
    root = ctx.extras.get("_root")
    if root is None:
        raise ValueError("sid resolver: no _root in ExpandContext")
    ski_node = root.find("SignedData/certificates/EECertificate/extensions/ski")
    if ski_node is None or not isinstance(ski_node.value, (bytes, bytearray)):
        raise ValueError("sid resolver: EE ski not found or not bytes")
    return bytes(ski_node.value)

def _encode_signed_attrs_for_signing(sa_node: ASTNode) -> bytes:
    from src.rpkiwi.input.cms_encoder import _encode_attribute
    attr_ders = [_encode_attribute(a) for a in sa_node.children]
    attr_ders.sort()
    return _encode_tlv_raw(_SET, b"".join(attr_ders))

@register("signature", deps=("signedAttrs",))
def resolve_signature(_node: ASTNode, ctx: ExpandContext) -> bytes:
    priv = ctx.extras.get("_ee_privkey")
    if priv is None:
        raise ValueError(
            "signature resolver: no EE private key in context; for parse+mutate "
            "flows override the signature leaf directly via MutationContext.set()"
        )
    root = ctx.extras.get("_root")
    if root is None:
        raise ValueError("signature resolver: no _root in ExpandContext")
    sa_node = root.find("SignedData/signerInfos/SignerInfo/signedAttrs")
    if sa_node is None:
        raise ValueError("signature resolver: signedAttrs not found")
    signing_input = _encode_signed_attrs_for_signing(sa_node)
    return priv.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

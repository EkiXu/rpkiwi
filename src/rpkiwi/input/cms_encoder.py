from __future__ import annotations

from src.rpkiwi.input.asnme.model.der.encoder import DEREncoder
from src.rpkiwi.input.ast_encoder import _encode_tlv_raw, ast_to_der
from src.rpkiwi.input.ast_node import ASTNode

OID_SIGNED_DATA    = bytes.fromhex("2a864886f70d010702")
OID_ROA            = bytes.fromhex("2a864886f70d0109100118")
OID_MANIFEST       = bytes.fromhex("2a864886f70d010910011a")
OID_ASPA           = bytes.fromhex("2a864886f70d0109100131")
OID_SHA256         = bytes.fromhex("608648016503040201")
OID_SHA256_RSA     = bytes.fromhex("2a864886f70d01010b")
OID_CONTENT_TYPE   = bytes.fromhex("2a864886f70d010903")
OID_SIGNING_TIME   = bytes.fromhex("2a864886f70d010905")
OID_MESSAGE_DIGEST = bytes.fromhex("2a864886f70d010904")

_OID_NAME_TO_BYTES: dict[str, bytes] = {
    "signedData":              OID_SIGNED_DATA,
    "routeOriginAttestation":  OID_ROA,
    "manifest":                OID_MANIFEST,
    "asProviderAttestation":   OID_ASPA,
    "sha256":                  OID_SHA256,
    "sha256WithRSAEncryption": OID_SHA256_RSA,
    "contentType":             OID_CONTENT_TYPE,
    "signingTime":             OID_SIGNING_TIME,
    "messageDigest":           OID_MESSAGE_DIGEST,
}

def _oid_bytes_for(name: str) -> bytes:
    b = _OID_NAME_TO_BYTES.get(name)
    if b is None:
        raise ValueError(f"unknown OID name: {name!r}")
    return b

_TAG_INT    = 0x02
_TAG_OCTET  = 0x04
_TAG_NULL   = 0x05
_TAG_OID    = 0x06
_TAG_UTC    = 0x17
_TAG_GEN    = 0x18
_TAG_SEQ    = 0x30
_TAG_SET    = 0x31
_TAG_CTX0_P = 0x80
_TAG_CTX0_C = 0xA0
_TAG_CTX1_C = 0xA1
_TAG_CTX3_C = 0xA3

def _enc_int(n: int) -> bytes:
    return DEREncoder.encode_integer(n)

def _enc_oid(oid: bytes) -> bytes:
    return _encode_tlv_raw(_TAG_OID, oid)

def _enc_null() -> bytes:
    return b"\x05\x00"

def _enc_octet(data: bytes) -> bytes:
    return _encode_tlv_raw(_TAG_OCTET, data)

def _enc_utc(s: str) -> bytes:
    return _encode_tlv_raw(_TAG_UTC, s.encode("ascii"))

def _enc_gen(s: str) -> bytes:
    return _encode_tlv_raw(_TAG_GEN, s.encode("ascii"))

def _enc_algid_null(oid: bytes) -> bytes:
    return _encode_tlv_raw(_TAG_SEQ, _enc_oid(oid) + _enc_null())

def encode_content_info(ast: ASTNode) -> bytes:
    if ast.label != "ContentInfo":
        raise ValueError(f"expected ContentInfo, got {ast.label!r}")

    ct = ast.child("contentType")
    sd = ast.child("SignedData")
    if ct is None or sd is None:
        raise ValueError("ContentInfo requires contentType and SignedData children")

    ct_bytes = _oid_bytes_for(ct.value)
    sd_der   = encode_signed_data(sd)

    inner  = _enc_oid(ct_bytes)
    inner += _encode_tlv_raw(_TAG_CTX0_C, sd_der)
    return _encode_tlv_raw(_TAG_SEQ, inner)

def encode_signed_data(ast: ASTNode) -> bytes:
    if ast.label != "SignedData":
        raise ValueError(f"expected SignedData, got {ast.label!r}")

    parts: list[bytes] = []
    for child in ast.children:
        lbl = child.label
        if lbl == "version":
            parts.append(_enc_int(int(child.value)))
        elif lbl == "digestAlgorithms":
            parts.append(_encode_digest_algorithms(child))
        elif lbl == "encapContentInfo":
            parts.append(encode_encap_content_info(child))
        elif lbl == "certificates":
            parts.append(_encode_certificates(child))
        elif lbl == "crls":
            if child.children:
                crls = b"".join(ast_to_der(c) for c in child.children)
                parts.append(_encode_tlv_raw(_TAG_CTX1_C, crls))
            elif child.value not in (None, "auto"):
                parts.append(_encode_tlv_raw(_TAG_CTX1_C, bytes(child.value)))
        elif lbl == "signerInfos":
            parts.append(_encode_signer_infos(child))
        else:
            raise ValueError(f"unknown SignedData child: {lbl!r}")

    return _encode_tlv_raw(_TAG_SEQ, b"".join(parts))

def encode_encap_content_info(ast: ASTNode) -> bytes:
    ect = ast.child("eContentType")
    ec  = ast.child("eContent")
    if ect is None:
        raise ValueError("encapContentInfo requires eContentType")

    parts = [_enc_oid(_oid_bytes_for(ect.value))]

    if ec is not None and ec.children:
        body_inner = b"".join(ast_to_der(c) for c in ec.children)
        body = _encode_tlv_raw(_TAG_SEQ, body_inner)
        octet = _enc_octet(body)
        parts.append(_encode_tlv_raw(_TAG_CTX0_C, octet))
    elif ec is not None and isinstance(ec.value, (bytes, bytearray)):
        parts.append(_encode_tlv_raw(_TAG_CTX0_C, _enc_octet(bytes(ec.value))))

    return _encode_tlv_raw(_TAG_SEQ, b"".join(parts))

def _encode_digest_algorithms(ast: ASTNode) -> bytes:
    alg_ders: list[bytes] = []
    alg_node = ast.child("algorithm")
    if alg_node is not None and not alg_node.children:
        alg_ders.append(_enc_algid_null(_oid_bytes_for(alg_node.value)))
    else:
        for c in ast.children:
            if c.label == "AlgorithmIdentifier" or c.label == "algorithm":
                oid_node = c.child("algorithm") if c.children else c
                oid_name = oid_node.value
                alg_ders.append(_enc_algid_null(_oid_bytes_for(oid_name)))

    alg_ders.sort()
    return _encode_tlv_raw(_TAG_SET, b"".join(alg_ders))

def _encode_certificates(ast: ASTNode) -> bytes:
    cert_ders = [ast_to_der(c) for c in ast.children]
    cert_ders.sort()
    return _encode_tlv_raw(_TAG_CTX0_C, b"".join(cert_ders))

def _encode_signer_infos(ast: ASTNode) -> bytes:
    si_ders = [encode_signer_info(c) for c in ast.children]
    si_ders.sort()
    return _encode_tlv_raw(_TAG_SET, b"".join(si_ders))

def encode_signer_info(ast: ASTNode) -> bytes:
    if ast.label != "SignerInfo":
        raise ValueError(f"expected SignerInfo, got {ast.label!r}")

    parts: list[bytes] = []
    for child in ast.children:
        lbl = child.label
        if lbl == "version":
            parts.append(_enc_int(int(child.value)))
        elif lbl == "sid":
            if not isinstance(child.value, (bytes, bytearray)):
                raise ValueError(f"sid must be bytes, got {type(child.value).__name__}")
            parts.append(_encode_tlv_raw(_TAG_CTX0_P, bytes(child.value)))
        elif lbl == "digestAlgorithm":
            parts.append(_enc_algid_null(_oid_bytes_for(child.value)))
        elif lbl == "signedAttrs":
            parts.append(_encode_signed_attrs(child))
        elif lbl == "signatureAlgorithm":
            parts.append(_enc_algid_null(_oid_bytes_for(child.value)))
        elif lbl == "signature":
            if not isinstance(child.value, (bytes, bytearray)):
                raise ValueError(f"signature must be bytes, got {type(child.value).__name__}")
            parts.append(_enc_octet(bytes(child.value)))
        else:
            raise ValueError(f"unknown SignerInfo child: {lbl!r}")

    return _encode_tlv_raw(_TAG_SEQ, b"".join(parts))

def _encode_signed_attrs(ast: ASTNode) -> bytes:
    attr_ders: list[bytes] = []
    for attr in ast.children:
        attr_ders.append(_encode_attribute(attr))
    attr_ders.sort()
    return _encode_tlv_raw(_TAG_CTX0_C, b"".join(attr_ders))

def _encode_attribute(attr: ASTNode) -> bytes:
    lbl = attr.label

    if lbl == "contentType":
        oid_bytes = _oid_bytes_for(attr.value)
        val_der   = _enc_oid(oid_bytes)
        type_oid  = OID_CONTENT_TYPE
    elif lbl == "signingTime":
        s = attr.value
        if not isinstance(s, str):
            raise ValueError(f"signingTime must be str, got {type(s).__name__}")
        if len(s) == 13:
            val_der = _enc_utc(s)
        elif len(s) == 15:
            val_der = _enc_gen(s)
        else:
            raise ValueError(f"signingTime string {s!r} has unexpected length {len(s)}")
        type_oid = OID_SIGNING_TIME
    elif lbl == "messageDigest":
        if not isinstance(attr.value, (bytes, bytearray)):
            raise ValueError(f"messageDigest must be bytes, got {type(attr.value).__name__}")
        val_der  = _enc_octet(bytes(attr.value))
        type_oid = OID_MESSAGE_DIGEST
    else:
        raise ValueError(f"unsupported signed attribute: {lbl!r}")

    values_set = _encode_tlv_raw(_TAG_SET, val_der)
    inner      = _enc_oid(type_oid) + values_set
    return _encode_tlv_raw(_TAG_SEQ, inner)

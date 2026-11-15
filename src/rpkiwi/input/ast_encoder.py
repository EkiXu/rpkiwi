from __future__ import annotations

import base64
from typing import Any

from src.rpkiwi.input.asnme.model.der.encoder import DEREncoder

_SEQ = 0x30
_SET = 0x31
_INT = 0x02
_OID = 0x06
_OCT = 0x04
_BIT = 0x03
_UTC = 0x17
_GEN = 0x18
_BOOL = 0x01
_NULL = 0x05
_UTF8 = 0x0C
_PRNT = 0x13
_IA5 = 0x16
_CTX0 = 0xA0
_CTX3 = 0xA3

LABEL_TAG: dict[str, int] = {
    "ContentInfo":        _SEQ,
    "contentType":        _OID,
    "SignedData":         _SEQ,
    "version":            _INT,
    "digestAlgorithms":   _SET,
    "algorithm":          _OID,
    "encapContentInfo":   _SEQ,
    "eContentType":       _OID,
    "eContent":           _CTX0,
    "certificates":       _CTX0,
    "crls":               0xA1,
    "signerInfos":        _SET,
    "SignerInfo":          _SEQ,
    "sid":                0x80,
    "digestAlgorithm":    _SEQ,
    "signedAttrs":        0xA0,
    "signatureAlgorithm": _SEQ,
    "signature":          _OCT,

    "signingTime":        _UTC,
    "messageDigest":      _OCT,

    "asID":               _INT,
    "ipAddrBlocks":       _SEQ,
    "ROAIPAddressFamily": _SEQ,
    "addressFamily":      _OCT,
    "addresses":          _SEQ,
    "ROAIPAddress":       _SEQ,
    "address":            _BIT,
    "maxLength":          _INT,

    "customerASID":       _INT,
    "providers":          _SEQ,
    "ProviderAS":         _SEQ,
    "providerASID":       _INT,
    "afiLimit":           _OCT,

    "manifestNumber":     _INT,
    "thisUpdate":         _GEN,
    "nextUpdate":         _GEN,
    "fileHashAlgorithm":  _OID,
    "fileList":           _SEQ,
    "fileEntry":          _SEQ,
    "filename":           _IA5,
    "hash":               _BIT,

    "EECertificate":      _SEQ,
    "serialNumber":       _INT,
    "issuer":             _SEQ,
    "validity":           _SEQ,
    "notBefore":          _UTC,
    "notAfter":           _UTC,
    "subject":            _SEQ,
    "subjectPublicKeyInfo": _SEQ,
    "extensions":         _CTX3,

    "ski":                _SEQ,
    "aki":                _SEQ,
    "ipResources":        _SEQ,
    "asnResources":       _SEQ,
    "sia":                _SEQ,
    "basicConstraints":   _SEQ,
    "crlDP":              _SEQ,
    "keyUsage":           _SEQ,
    "certPolicy":         _SEQ,
    "aia":                _SEQ,

    "CertificateRevocationList": _SEQ,
    "tbsCertList":        _SEQ,
    "revokedCertificates": _SEQ,
    "revokedCertificate": _SEQ,
    "revocationDate":     _UTC,
    "signatureValue":     _BIT,
    "crlNumber":          _INT,

    "CACertificate":      _SEQ,
    "tbsCertificate":     _SEQ,
}

CONSTRUCTED_TAGS = {_SEQ, _SET, _CTX0, 0xA1, _CTX3, 0xA0}

_OID_BYTES: dict[str, bytes] = {
    "signedData":                bytes.fromhex("2a864886f70d010702"),
    "routeOriginAttestation":    bytes.fromhex("2a864886f70d0109100118"),
    "manifest":                  bytes.fromhex("2a864886f70d010910011a"),
    "asProviderAttestation":     bytes.fromhex("2a864886f70d0109100131"),
    "sha256":                    bytes.fromhex("608648016503040201"),
    "sha256WithRSAEncryption":   bytes.fromhex("2a864886f70d01010b"),
    "contentType":               bytes.fromhex("2a864886f70d010903"),
    "signingTime":               bytes.fromhex("2a864886f70d010905"),
    "messageDigest":             bytes.fromhex("2a864886f70d010904"),
    "subjectKeyIdentifier":      bytes.fromhex("551d0e"),
    "authorityKeyIdentifier":    bytes.fromhex("551d23"),
    "ipAddrBlocks":              bytes.fromhex("2b06010505070107"),
    "autonomousSysIds":          bytes.fromhex("2b06010505070108"),
    "subjectInfoAccess":         bytes.fromhex("2b06010505070101"),
    "basicConstraints":          bytes.fromhex("551d13"),
    "keyUsage":                  bytes.fromhex("551d0f"),
    "certificatePolicies":       bytes.fromhex("551d20"),
    "crlDistributionPoints":     bytes.fromhex("551d1f"),
    "commonName":                bytes.fromhex("550403"),
}

def _encode_tlv_raw(tag: int, content: bytes) -> bytes:
    tag_byte = tag.to_bytes(1, "big") if tag < 256 else tag.to_bytes(2, "big")
    length = len(content)
    if length < 128:
        length_bytes = bytes([length])
    else:
        lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
        length_bytes = bytes([0x80 | len(lb)]) + lb
    return tag_byte + length_bytes + content

FULL_TLV_LABELS = frozenset({
    "EECertificate",
    "CACertificate",
})

def ast_to_der(node) -> bytes:
    if node.value == "auto":
        raise ValueError(f"unexpanded auto at '{node.label}': run expand() first")

    if node.label in FULL_TLV_LABELS and node.is_leaf and isinstance(node.value, (bytes, bytearray)):
        return bytes(node.value)

    if node.is_leaf:
        return _encode_leaf(node)

    tag = node.der_tag if node.der_tag is not None else LABEL_TAG.get(node.label, _SEQ)
    inner = b"".join(ast_to_der(c) for c in node.children)
    return _encode_tlv_raw(tag, inner)

_AFI_NAME_TO_BYTES: dict[str, bytes] = {
    "ipv4": b"\x00\x01",
    "ipv6": b"\x00\x02",
}

def _reverse_symbolic_leaf(label: str, val) -> bytes | None:
    if label in ("addressFamily", "afiLimit") and isinstance(val, str):
        b = _AFI_NAME_TO_BYTES.get(val)
        if b is not None:
            return b
        try:
            return bytes.fromhex(val)
        except ValueError:
            return None
    return None

def _encode_leaf(node) -> bytes:
    tag = node.der_tag if node.der_tag is not None else LABEL_TAG.get(node.label, _OCT)
    val = node.value

    if val is None:
        return _encode_tlv_raw(tag, b"") if node.der_tag is not None else b""

    if node.label == "version" and isinstance(val, bytes):
        return _encode_tlv_raw(_CTX0, val)

    reversed_bytes = _reverse_symbolic_leaf(node.label, val)
    if reversed_bytes is not None:
        return _encode_tlv_raw(tag, reversed_bytes)

    if tag == _INT:
        if isinstance(val, int):
            return DEREncoder.encode_integer(val)
        if isinstance(val, bytes):
            return _encode_tlv_raw(_INT, val)
        return DEREncoder.encode_integer(int(val))

    if tag == _OID:
        if isinstance(val, str):
            oid_bytes = _OID_BYTES.get(val)
            if oid_bytes:
                return _encode_tlv_raw(_OID, oid_bytes)
            return _encode_tlv_raw(_OID, val.encode())
        if isinstance(val, bytes):
            return _encode_tlv_raw(_OID, val)
        return _encode_tlv_raw(_OID, str(val).encode())

    if tag == _BIT:
        if isinstance(val, bytes):
            return _encode_tlv_raw(_BIT, val)
        if isinstance(val, str):
            if node.label == "hash":
                raw = bytes.fromhex(val)
                return _encode_tlv_raw(_BIT, b"\x00" + raw)
            return _encode_ip_prefix_bitstring(val)
        return _encode_tlv_raw(_BIT, b'\x00')

    if tag == _OCT:
        if isinstance(val, bytes):
            return _encode_tlv_raw(_OCT, val)
        if isinstance(val, str):
            return _encode_tlv_raw(_OCT, val.encode())
        return _encode_tlv_raw(_OCT, bytes(val))

    if tag in (_UTC, _GEN):
        if isinstance(val, str):
            return _encode_tlv_raw(tag, val.encode("ascii"))
        if isinstance(val, bytes):
            return _encode_tlv_raw(tag, val)
        return _encode_tlv_raw(tag, str(val).encode("ascii"))

    if tag == _IA5:
        if isinstance(val, bytes):
            return _encode_tlv_raw(_IA5, val)
        s = val if isinstance(val, str) else str(val)
        return _encode_tlv_raw(_IA5, s.encode("ascii"))

    if tag == _PRNT:
        if isinstance(val, bytes):
            return _encode_tlv_raw(_PRNT, val)
        s = val if isinstance(val, str) else str(val)
        return _encode_tlv_raw(_PRNT, s.encode("ascii"))

    if tag == _BOOL:
        if isinstance(val, bytes):
            return _encode_tlv_raw(_BOOL, val)
        return _encode_tlv_raw(_BOOL, b'\xff' if val else b'\x00')

    if tag == _NULL:
        return _encode_tlv_raw(_NULL, b'')

    if isinstance(val, bytes):
        return _encode_tlv_raw(tag, val)
    if isinstance(val, str):
        return _encode_tlv_raw(tag, val.encode())
    if isinstance(val, int):
        return DEREncoder.encode_integer(val)
    return _encode_tlv_raw(tag, b'')

def _encode_ip_prefix_bitstring(prefix: str) -> bytes:
    import ipaddress
    network = ipaddress.ip_network(prefix, strict=False)
    prefix_len = network.prefixlen
    num_bytes = (prefix_len + 7) // 8
    unused_bits = (num_bytes * 8) - prefix_len
    ip_bytes = network.network_address.packed[:num_bytes]
    return _encode_tlv_raw(_BIT, bytes([unused_bits]) + ip_bytes)

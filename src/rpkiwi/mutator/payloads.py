from __future__ import annotations

import base64
import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from src.rpkiwi.input.asnme.model.der.length import encode_length

RRDP_NS = {"rrdp": "http://www.ripe.net/rpki/rrdp"}
ET.register_namespace("", "http://www.ripe.net/rpki/rrdp")

@dataclass(slots=True)
class TLV:
    offset: int
    tag: int
    header_len: int
    length: int

    @property
    def content_start(self) -> int:
        return self.offset + self.header_len

    @property
    def content_end(self) -> int:
        return self.content_start + self.length

    @property
    def end(self) -> int:
        return self.content_end

def parse_tlv(data: bytes, offset: int = 0) -> TLV:
    tag = data[offset]
    first_len = data[offset + 1]
    if first_len & 0x80:
        len_bytes = first_len & 0x7F
        length = int.from_bytes(data[offset + 2:offset + 2 + len_bytes], "big")
        header_len = 2 + len_bytes
    else:
        length = first_len
        header_len = 2
    return TLV(offset=offset, tag=tag, header_len=header_len, length=length)

def child_tlvs(data: bytes, parent: TLV) -> list[TLV]:
    children: list[TLV] = []
    cursor = parent.content_start
    while cursor < parent.content_end:
        child = parse_tlv(data, cursor)
        children.append(child)
        cursor = child.end
    return children

def encode_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + encode_length(len(content)) + content

def encode_der_integer(value: int) -> bytes:
    if value == 0:
        content = b"\x00"
    else:
        content = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if content[0] & 0x80:
            content = b"\x00" + content
    return encode_tlv(0x02, content)

def _cms_views(cms_der: bytes) -> tuple[TLV, list[TLV], TLV, list[TLV]]:
    outer = parse_tlv(cms_der)
    outer_children = child_tlvs(cms_der, outer)
    signed_data_wrapper = outer_children[1]
    signed_data = parse_tlv(cms_der, signed_data_wrapper.content_start)
    signed_data_children = child_tlvs(cms_der, signed_data)
    return outer, outer_children, signed_data, signed_data_children

def _rebuild_with_replaced_child(
    container: TLV, children: list[TLV], index: int, replacement: bytes, source: bytes
) -> bytes:
    parts: list[bytes] = []
    cursor = container.content_start
    for idx, child in enumerate(children):
        if idx == index:
            if cursor < child.offset:
                parts.append(source[cursor:child.offset])
            parts.append(replacement)
            cursor = child.end
        else:
            if cursor < child.end:
                parts.append(source[cursor:child.end])
                cursor = child.end
    if cursor < container.content_end:
        parts.append(source[cursor:container.content_end])
    return encode_tlv(container.tag, b"".join(parts))

def cms_replace_econtent(cms_der: bytes, new_econtent: bytes) -> bytes:
    outer, outer_children, signed_data, signed_data_children = _cms_views(cms_der)
    encap = signed_data_children[2]
    encap_children = child_tlvs(cms_der, encap)
    tagged_content = encap_children[1]
    new_octet = encode_tlv(0x04, new_econtent)
    new_tagged = encode_tlv(tagged_content.tag, new_octet)
    new_encap = _rebuild_with_replaced_child(encap, encap_children, 1, new_tagged, cms_der)
    new_signed_data = _rebuild_with_replaced_child(signed_data, signed_data_children, 2, new_encap, cms_der)
    new_wrapper = encode_tlv(outer_children[1].tag, new_signed_data)
    return _rebuild_with_replaced_child(outer, outer_children, 1, new_wrapper, cms_der)

def cms_extract_econtent(cms_der: bytes) -> bytes:
    _, _, _, signed_data_children = _cms_views(cms_der)
    encap = signed_data_children[2]
    encap_children = child_tlvs(cms_der, encap)
    tagged_content = encap_children[1]
    octet = parse_tlv(cms_der, tagged_content.content_start)
    return cms_der[octet.content_start:octet.content_end]

def cms_extract_first_certificate(cms_der: bytes) -> bytes:
    _, _, _, signed_data_children = _cms_views(cms_der)
    certs = signed_data_children[3]
    return cms_der[certs.content_start:certs.content_end]

def cms_replace_first_certificate(cms_der: bytes, new_cert_der: bytes) -> bytes:
    outer, outer_children, signed_data, signed_data_children = _cms_views(cms_der)
    certs = signed_data_children[3]
    new_certs = encode_tlv(certs.tag, new_cert_der)
    new_signed_data = _rebuild_with_replaced_child(signed_data, signed_data_children, 3, new_certs, cms_der)
    new_wrapper = encode_tlv(outer_children[1].tag, new_signed_data)
    return _rebuild_with_replaced_child(outer, outer_children, 1, new_wrapper, cms_der)

def cms_empty_signer_infos(cms_der: bytes) -> bytes:
    outer, outer_children, signed_data, signed_data_children = _cms_views(cms_der)
    new_signer_infos = b"\x31\x00"
    new_signed_data = _rebuild_with_replaced_child(
        signed_data, signed_data_children, len(signed_data_children) - 1, new_signer_infos, cms_der,
    )
    new_wrapper = encode_tlv(outer_children[1].tag, new_signed_data)
    return _rebuild_with_replaced_child(outer, outer_children, 1, new_wrapper, cms_der)

def cms_empty_signed_attrs(cms_der: bytes) -> bytes:
    outer, outer_children, signed_data, signed_data_children = _cms_views(cms_der)
    signer_infos = signed_data_children[-1]
    signer_infos_children = child_tlvs(cms_der, signer_infos)
    first_signer = signer_infos_children[0]
    signer_children = child_tlvs(cms_der, first_signer)
    sa_index = None
    for i, child in enumerate(signer_children):
        if child.tag == 0xA0:
            sa_index = i
            break
    if sa_index is None:
        raise ValueError("signedAttrs (tag 0xA0) not found in SignerInfo")
    new_signed_attrs = b"\xA0\x00"
    new_signer = _rebuild_with_replaced_child(first_signer, signer_children, sa_index, new_signed_attrs, cms_der)
    new_signer_infos = _rebuild_with_replaced_child(signer_infos, signer_infos_children, 0, new_signer, cms_der)
    new_signed_data = _rebuild_with_replaced_child(
        signed_data, signed_data_children, len(signed_data_children) - 1, new_signer_infos, cms_der,
    )
    new_wrapper = encode_tlv(outer_children[1].tag, new_signed_data)
    return _rebuild_with_replaced_child(outer, outer_children, 1, new_wrapper, cms_der)

def cms_bump_signing_time(cms_der: bytes, delta_seconds: int = 120) -> bytes:
    import datetime
    TAG_UTC_TIME = 0x17
    SIGNING_TIME_OID = bytes.fromhex("06092a864886f70d010905")
    oid_pos = cms_der.find(SIGNING_TIME_OID)
    if oid_pos == -1:
        raise ValueError("signingTime OID not found in CMS")
    offset = oid_pos + len(SIGNING_TIME_OID)
    target = None
    while offset < len(cms_der) - 2:
        if cms_der[offset] == TAG_UTC_TIME:
            length = cms_der[offset + 1]
            if 11 <= length <= 15:
                raw = cms_der[offset + 2: offset + 2 + length]
                try:
                    text = raw.decode("ascii")
                    if text.endswith("Z") and len(text) in (13, 15):
                        target = (offset, length)
                        break
                except (UnicodeDecodeError, ValueError):
                    pass
        offset += 1
    if target is None:
        raise ValueError("no UTCTime found after signingTime OID")
    off, length = target
    raw_text = cms_der[off + 2: off + 2 + length].decode("ascii")
    fmt = "%y%m%d%H%M%SZ" if len(raw_text) == 13 else "%Y%m%d%H%M%SZ"
    dt = datetime.datetime.strptime(raw_text, fmt)
    dt += datetime.timedelta(seconds=delta_seconds)
    new_text = dt.strftime("%y%m%d%H%M%SZ").encode("ascii")
    return cms_der[:off + 2] + new_text + cms_der[off + 2 + length:]

def _find_extension_index(cert_der: bytes, exts_inner: TLV, oid_der: bytes) -> tuple[int, list[TLV]]:
    children = child_tlvs(cert_der, exts_inner)
    for index, ext in enumerate(children):
        raw = cert_der[ext.offset:ext.end]
        if oid_der in raw:
            return index, children
    raise ValueError("extension not found")

def patch_cert_ip_resources_prefix_len(cert_der: bytes, *, prefix_bytes: int) -> bytes:
    cert = parse_tlv(cert_der)
    cert_children = child_tlvs(cert_der, cert)
    tbs = cert_children[0]
    tbs_children = child_tlvs(cert_der, tbs)
    exts_wrapper = tbs_children[-1]
    exts_inner = parse_tlv(cert_der, exts_wrapper.content_start)
    oid_ip_resources = bytes.fromhex("06082b06010505070107")
    ext_index, exts_children = _find_extension_index(cert_der, exts_inner, oid_ip_resources)

    bit_string_content = b"\x00" + (b"\x00" * prefix_bytes)
    bit_string = encode_tlv(0x03, bit_string_content)
    address_set = encode_tlv(0x30, bit_string)
    ip_resources = encode_tlv(0x30, encode_tlv(0x30, encode_tlv(0x04, b"\x00\x01") + address_set))
    replacement_ext = encode_tlv(
        0x30, oid_ip_resources + encode_tlv(0x01, b"\xff") + encode_tlv(0x04, ip_resources),
    )

    new_exts_inner = _rebuild_with_replaced_child(exts_inner, exts_children, ext_index, replacement_ext, cert_der)
    new_exts_wrapper = encode_tlv(exts_wrapper.tag, new_exts_inner)
    new_tbs = _rebuild_with_replaced_child(tbs, tbs_children, len(tbs_children) - 1, new_exts_wrapper, cert_der)
    return _rebuild_with_replaced_child(cert, cert_children, 0, new_tbs, cert_der)

def patch_cert_ip_resources_malformed(cert_der: bytes) -> bytes:
    cert = parse_tlv(cert_der)
    cert_children = child_tlvs(cert_der, cert)
    tbs = cert_children[0]
    tbs_children = child_tlvs(cert_der, tbs)
    exts_wrapper = tbs_children[-1]
    exts_inner = parse_tlv(cert_der, exts_wrapper.content_start)
    oid_ip_resources = bytes.fromhex("06082b06010505070107")
    ext_index, exts_children = _find_extension_index(cert_der, exts_inner, oid_ip_resources)

    malformed_ip_resources = encode_tlv(
        0x30, encode_tlv(0x30, encode_tlv(0x02, b"\x01") + encode_tlv(0x05, b"")),
    )
    replacement_ext = encode_tlv(
        0x30, oid_ip_resources + encode_tlv(0x01, b"\xff") + encode_tlv(0x04, malformed_ip_resources),
    )

    new_exts_inner = _rebuild_with_replaced_child(exts_inner, exts_children, ext_index, replacement_ext, cert_der)
    new_exts_wrapper = encode_tlv(exts_wrapper.tag, new_exts_inner)
    new_tbs = _rebuild_with_replaced_child(tbs, tbs_children, len(tbs_children) - 1, new_exts_wrapper, cert_der)
    return _rebuild_with_replaced_child(cert, cert_children, 0, new_tbs, cert_der)

def patch_cert_ip_resources_inherit(cert_der: bytes) -> bytes:
    cert = parse_tlv(cert_der)
    cert_children = child_tlvs(cert_der, cert)
    tbs = cert_children[0]
    tbs_children = child_tlvs(cert_der, tbs)
    exts_wrapper = tbs_children[-1]
    exts_inner = parse_tlv(cert_der, exts_wrapper.content_start)
    oid_ip_resources = bytes.fromhex("06082b06010505070107")
    ext_index, exts_children = _find_extension_index(cert_der, exts_inner, oid_ip_resources)

    inherit_resources = encode_tlv(0x30, encode_tlv(0x30, encode_tlv(0x04, b"\x00\x01") + b"\x05\x00"))
    replacement_ext = encode_tlv(
        0x30, oid_ip_resources + encode_tlv(0x01, b"\xff") + encode_tlv(0x04, inherit_resources),
    )

    new_exts_inner = _rebuild_with_replaced_child(exts_inner, exts_children, ext_index, replacement_ext, cert_der)
    new_exts_wrapper = encode_tlv(exts_wrapper.tag, new_exts_inner)
    new_tbs = _rebuild_with_replaced_child(tbs, tbs_children, len(tbs_children) - 1, new_exts_wrapper, cert_der)
    return _rebuild_with_replaced_child(cert, cert_children, 0, new_tbs, cert_der)

def extract_cert_ski(cert_der: bytes) -> bytes:
    cert = parse_tlv(cert_der)
    cert_children = child_tlvs(cert_der, cert)
    tbs = cert_children[0]
    tbs_children = child_tlvs(cert_der, tbs)
    exts_wrapper = tbs_children[-1]
    exts_inner = parse_tlv(cert_der, exts_wrapper.content_start)
    oid_ski = bytes.fromhex("0603551d0e")
    ext_index, exts_children = _find_extension_index(cert_der, exts_inner, oid_ski)
    ext_tlv = exts_children[ext_index]
    ext_children = child_tlvs(cert_der, ext_tlv)
    octet_wrapper = ext_children[-1]
    inner = parse_tlv(cert_der, octet_wrapper.content_start)
    return cert_der[inner.content_start:inner.content_end]

def patch_cert_ski(cert_der: bytes, new_ski: bytes) -> bytes:
    cert = parse_tlv(cert_der)
    cert_children = child_tlvs(cert_der, cert)
    tbs = cert_children[0]
    tbs_children = child_tlvs(cert_der, tbs)
    exts_wrapper = tbs_children[-1]
    exts_inner = parse_tlv(cert_der, exts_wrapper.content_start)
    oid_ski = bytes.fromhex("0603551d0e")
    ext_index, exts_children = _find_extension_index(cert_der, exts_inner, oid_ski)

    ski_value = encode_tlv(0x04, new_ski)
    replacement_ext = encode_tlv(0x30, oid_ski + encode_tlv(0x04, ski_value))

    new_exts_inner = _rebuild_with_replaced_child(exts_inner, exts_children, ext_index, replacement_ext, cert_der)
    new_exts_wrapper = encode_tlv(exts_wrapper.tag, new_exts_inner)
    new_tbs = _rebuild_with_replaced_child(tbs, tbs_children, len(tbs_children) - 1, new_exts_wrapper, cert_der)
    return _rebuild_with_replaced_child(cert, cert_children, 0, new_tbs, cert_der)

def patch_cert_ip_resources_override(cert_der: bytes, prefix_str: str) -> bytes:
    import ipaddress
    from src.rpkiwi.input.utils.ip_tools import encode_ip_prefix_to_bitstring

    cert = parse_tlv(cert_der)
    cert_children = child_tlvs(cert_der, cert)
    tbs = cert_children[0]
    tbs_children = child_tlvs(cert_der, tbs)
    exts_wrapper = tbs_children[-1]
    exts_inner = parse_tlv(cert_der, exts_wrapper.content_start)
    oid_ip_resources = bytes.fromhex("06082b06010505070107")
    ext_index, exts_children = _find_extension_index(cert_der, exts_inner, oid_ip_resources)

    network = ipaddress.ip_network(prefix_str, strict=False)
    afi = b"\x00\x01" if network.version == 4 else b"\x00\x02"

    bs_content = encode_ip_prefix_to_bitstring(prefix_str)
    bit_string = encode_tlv(0x03, bs_content)
    address_set = encode_tlv(0x30, bit_string)
    ip_resources = encode_tlv(0x30, encode_tlv(0x30, encode_tlv(0x04, afi) + address_set))
    replacement_ext = encode_tlv(
        0x30, oid_ip_resources + encode_tlv(0x01, b"\xff") + encode_tlv(0x04, ip_resources),
    )

    new_exts_inner = _rebuild_with_replaced_child(exts_inner, exts_children, ext_index, replacement_ext, cert_der)
    new_exts_wrapper = encode_tlv(exts_wrapper.tag, new_exts_inner)
    new_tbs = _rebuild_with_replaced_child(tbs, tbs_children, len(tbs_children) - 1, new_exts_wrapper, cert_der)
    return _rebuild_with_replaced_child(cert, cert_children, 0, new_tbs, cert_der)

def patch_cert_aki(cert_der: bytes, new_aki: bytes) -> bytes:
    cert = parse_tlv(cert_der)
    cert_children = child_tlvs(cert_der, cert)
    tbs = cert_children[0]
    tbs_children = child_tlvs(cert_der, tbs)
    exts_wrapper = tbs_children[-1]
    exts_inner = parse_tlv(cert_der, exts_wrapper.content_start)
    oid_aki = bytes.fromhex("0603551d23")
    ext_index, exts_children = _find_extension_index(cert_der, exts_inner, oid_aki)

    aki_value = encode_tlv(0x30, encode_tlv(0x80, new_aki))
    replacement_ext = encode_tlv(0x30, oid_aki + encode_tlv(0x04, aki_value))

    new_exts_inner = _rebuild_with_replaced_child(exts_inner, exts_children, ext_index, replacement_ext, cert_der)
    new_exts_wrapper = encode_tlv(exts_wrapper.tag, new_exts_inner)
    new_tbs = _rebuild_with_replaced_child(tbs, tbs_children, len(tbs_children) - 1, new_exts_wrapper, cert_der)
    return _rebuild_with_replaced_child(cert, cert_children, 0, new_tbs, cert_der)

def patch_cert_basic_constraints(cert_der: bytes, *, ca: bool) -> bytes:
    cert = parse_tlv(cert_der)
    cert_children = child_tlvs(cert_der, cert)
    tbs = cert_children[0]
    tbs_children = child_tlvs(cert_der, tbs)
    exts_wrapper = tbs_children[-1]
    exts_inner = parse_tlv(cert_der, exts_wrapper.content_start)
    exts_children = child_tlvs(cert_der, exts_inner)

    oid_bc = bytes.fromhex("0603551d13")
    if ca:
        bc_value = encode_tlv(0x30, encode_tlv(0x01, b"\xff"))
    else:
        bc_value = b"\x30\x00"
    bc_ext = encode_tlv(
        0x30, oid_bc + encode_tlv(0x01, b"\xff") + encode_tlv(0x04, bc_value),
    )

    old_exts_content = cert_der[exts_inner.content_start:exts_inner.content_end]
    new_exts_inner = encode_tlv(0x30, old_exts_content + bc_ext)
    new_exts_wrapper = encode_tlv(exts_wrapper.tag, new_exts_inner)
    new_tbs = _rebuild_with_replaced_child(tbs, tbs_children, len(tbs_children) - 1, new_exts_wrapper, cert_der)
    return _rebuild_with_replaced_child(cert, cert_children, 0, new_tbs, cert_der)

def rrdp_hash(xml_text: str) -> str:
    return hashlib.sha256(xml_text.encode("utf-8")).hexdigest()

def rrdp_add_publish(snapshot_xml: str, *, uri: str, content: bytes) -> str:
    root = ET.fromstring(snapshot_xml)
    publish = ET.Element("{http://www.ripe.net/rpki/rrdp}publish")
    publish.set("uri", uri)
    publish.text = base64.b64encode(content).decode("ascii")
    root.append(publish)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)

def rrdp_replace_publish_content(snapshot_xml: str, *, uri_suffix: str, content: bytes) -> str:
    root = ET.fromstring(snapshot_xml)
    encoded = base64.b64encode(content).decode("ascii")
    for publish in root.findall("rrdp:publish", RRDP_NS):
        uri = publish.get("uri", "")
        if uri.endswith(uri_suffix):
            publish.text = encoded
            return ET.tostring(root, encoding="unicode", xml_declaration=True)
    raise ValueError(f"publish uri ending with {uri_suffix!r} not found")

def rrdp_set_root_attribute(xml_text: str, *, attribute: str, value: str) -> str:
    root = ET.fromstring(xml_text)
    root.set(attribute, value)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)

def rrdp_replace_numeric_attribute(xml_text: str, *, attribute: str, value: str) -> str:
    pattern = rf'({attribute}=\")([^\"]+)(\")'
    updated, count = re.subn(pattern, rf"\g<1>{value}\g<3>", xml_text, count=1)
    if count != 1:
        raise ValueError(f"attribute {attribute!r} not found")
    return updated

def rrdp_delta_withdraw(*, session_id: str, serial: int, uri: str, hash_value: str) -> str:
    root = ET.Element("{http://www.ripe.net/rpki/rrdp}delta")
    root.set("version", "1")
    root.set("session_id", session_id)
    root.set("serial", str(serial))
    withdraw = ET.SubElement(root, "{http://www.ripe.net/rpki/rrdp}withdraw")
    withdraw.set("uri", uri)
    withdraw.set("hash", hash_value)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)

def rrdp_notification_add_delta(notification_xml: str, *, serial: int, uri: str, hash_value: str) -> str:
    root = ET.fromstring(notification_xml)
    root.set("serial", str(serial))
    delta = ET.Element("{http://www.ripe.net/rpki/rrdp}delta")
    delta.set("serial", str(serial))
    delta.set("uri", uri)
    delta.set("hash", hash_value)
    root.append(delta)
    return ET.tostring(root, encoding="unicode", xml_declaration=True)

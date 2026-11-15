from __future__ import annotations

import base64
import copy
from dataclasses import dataclass, field
from typing import Any

@dataclass
class ASTNode:
    label: str
    value: Any = None
    children: list[ASTNode] = field(default_factory=list)
    signed: bool = False
    der_tag: int | None = None

    @property
    def is_leaf(self) -> bool:
        return not self.children

    def child(self, label: str) -> ASTNode | None:
        for c in self.children:
            if c.label == label:
                return c
        return None

    def find(self, path: str) -> ASTNode | None:
        matches = self.find_all(path)
        return matches[0] if matches else None

    def find_all(self, path: str) -> list[ASTNode]:
        nodes = [self]
        for part in path.split("/"):
            nodes = [child for node in nodes for child in node.children if child.label == part]
        return nodes

    def clone(self) -> ASTNode:
        return copy.deepcopy(self)

    def has_auto(self) -> bool:
        if self.is_leaf:
            return self.value == "auto"
        return any(c.has_auto() for c in self.children)

    def iter_auto_paths(self, prefix: str = "") -> list[str]:
        here = f"{prefix}/{self.label}" if prefix else self.label
        if self.is_leaf:
            return [here] if self.value == "auto" else []
        out: list[str] = []
        for c in self.children:
            out.extend(c.iter_auto_paths(here))
        return out

    def assert_concrete(self) -> None:
        auto_paths = self.iter_auto_paths()
        if auto_paths:
            preview = ", ".join(auto_paths[:5])
            more = f" (+{len(auto_paths) - 5} more)" if len(auto_paths) > 5 else ""
            raise ValueError(f"AST contains unresolved auto: {preview}{more}")

    def to_dict(self) -> dict:
        d: dict[str, Any] = {"n": self.label}
        if self.signed:
            d["signed"] = True
        if self.der_tag is not None:
            d["der_tag"] = self.der_tag
        if self.children:
            d["c"] = [c.to_dict() for c in self.children]
        elif self.value is not None:
            if isinstance(self.value, bytes):
                d["type"] = "bytes"
                d["v"] = base64.b64encode(self.value).decode()
            elif isinstance(self.value, int):
                d["type"] = "int"
                d["v"] = self.value
            elif self.value == "auto":
                d["type"] = "auto"
            else:
                d["type"] = "str"
                d["v"] = self.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> ASTNode:
        label = d["n"]
        signed = d.get("signed", False)
        der_tag = d.get("der_tag")
        if "c" in d:
            children = [cls.from_dict(c) for c in d["c"]]
            return cls(label=label, children=children, signed=signed, der_tag=der_tag)
        vtype = d.get("type")
        if vtype == "auto":
            return cls(label=label, value="auto", signed=signed, der_tag=der_tag)
        if vtype == "bytes":
            return cls(label=label, value=base64.b64decode(d["v"]), signed=signed, der_tag=der_tag)
        value = d.get("v")
        return cls(label=label, value=value, signed=signed, der_tag=der_tag)

    def __repr__(self) -> str:
        if self.children:
            return f"ASTNode({self.label!r}, [{len(self.children)} children])"
        return f"ASTNode({self.label!r}, {self.value!r})"

    @classmethod
    def from_der(cls, data: bytes, object_type: str) -> "ASTNode":
        from src.rpkiwi.input.der_ast import DERNode

        ot = object_type.upper()
        root = DERNode.parse(data)
        if ot == "CRL":
            return _parse_crl(root)
        if ot == "CER":
            certificate = _parse_ee_cert_structured(root)
            certificate.label = "CACertificate"
            return certificate

        return _parse_cms(root, data, object_type)

_OID_NAMES: dict[bytes, str] = {
    bytes.fromhex("2a864886f70d010702"): "signedData",
    bytes.fromhex("2a864886f70d0109100118"): "routeOriginAttestation",
    bytes.fromhex("2a864886f70d010910011a"): "manifest",
    bytes.fromhex("2a864886f70d0109100131"): "asProviderAttestation",
    bytes.fromhex("608648016503040201"): "sha256",
    bytes.fromhex("2a864886f70d01010b"): "sha256WithRSAEncryption",
    bytes.fromhex("2a864886f70d010901"): "emailAddress",
    bytes.fromhex("550403"): "commonName",
    bytes.fromhex("2a864886f70d010903"): "contentType",
    bytes.fromhex("2a864886f70d010905"): "signingTime",
    bytes.fromhex("2a864886f70d010904"): "messageDigest",
    bytes.fromhex("551d0e"): "subjectKeyIdentifier",
    bytes.fromhex("551d23"): "authorityKeyIdentifier",
    bytes.fromhex("551d0f"): "keyUsage",
    bytes.fromhex("551d20"): "certificatePolicies",
    bytes.fromhex("2b0601050507010b"): "subjectInfoAccess",
    bytes.fromhex("551d1f"): "crlDistributionPoints",
    bytes.fromhex("2b06010505070101"): "authorityInfoAccess",
    bytes.fromhex("2b06010505070107"): "ipAddrBlocks",
    bytes.fromhex("2b06010505070108"): "autonomousSysIds",
    bytes.fromhex("551d13"): "basicConstraints",
    bytes.fromhex("551d14"): "crlNumber",
    bytes.fromhex("2a864886f70d010101"): "rsaEncryption",
}

def _oid_name(content: bytes) -> str:
    return _OID_NAMES.get(content, content.hex())

def _decode_integer(content: bytes) -> int:
    if not content:
        return 0
    return int.from_bytes(content, "big", signed=True)

def _decode_ip_prefix(bitstring_bytes: bytes, version: int = 4) -> str:
    import ipaddress
    unused = bitstring_bytes[0]
    addr_bytes = bitstring_bytes[1:]
    prefix_len = len(addr_bytes) * 8 - unused
    width = 4 if version == 4 else 16
    if not 0 <= unused <= 7 or len(addr_bytes) > width or prefix_len < 0:
        raise ValueError("invalid IP prefix BIT STRING")
    padded = addr_bytes + b"\x00" * (width - len(addr_bytes))
    net = ipaddress.ip_address(padded)
    return f"{net}/{prefix_len}"

def _decode_generalizedtime(content: bytes) -> str:
    return content.decode("ascii")

def _decode_utctime(content: bytes) -> str:
    return content.decode("ascii")

def _decode_ia5string(content: bytes) -> str | bytes:
    try:
        return content.decode("ascii")
    except UnicodeDecodeError:
        return content

def _parse_cms(root, data: bytes, object_type: str) -> ASTNode:
    from src.rpkiwi.input.der_ast import DERNode

    content_type_oid = root.children[0]
    content_wrapper = root.children[1]
    signed_data = content_wrapper.children[0]

    sd_children = signed_data.children
    version_node = sd_children[0]
    digest_algs = sd_children[1]
    encap_content_info = sd_children[2]
    certificates_node = sd_children[3]
    signer_infos_set = sd_children[4]

    econtent_type_oid = encap_content_info.children[0]
    econtent_wrapper = encap_content_info.children[1]
    econtent_octet = econtent_wrapper.children[0]

    econtent_type_name = _oid_name(econtent_type_oid.content)

    econtent_bytes = econtent_octet.content
    econtent_children = _parse_econtent(DERNode.parse(econtent_bytes), econtent_type_name, object_type)

    first_alg = digest_algs.children[0]
    alg_oid = first_alg.children[0]

    cert_seq = certificates_node.children[0]
    cert_ast = _parse_ee_cert_structured(cert_seq)
    cert_ast.signed = True

    signer_info_asts = [_parse_signer_info(si) for si in signer_infos_set.children]

    return ASTNode("ContentInfo", children=[
        ASTNode("contentType", value=_oid_name(content_type_oid.content)),
        ASTNode("SignedData", children=[
            ASTNode("version", value=_decode_integer(version_node.content)),
            ASTNode("digestAlgorithms", children=[
                ASTNode("algorithm", value=_oid_name(alg_oid.content)),
            ]),
            ASTNode("encapContentInfo", children=[
                ASTNode("eContentType", value=econtent_type_name),
                ASTNode("eContent", children=econtent_children, signed=True),
            ]),
            ASTNode("certificates", children=[cert_ast], signed=True),
            ASTNode("signerInfos", children=signer_info_asts),
        ]),
    ])

def _parse_econtent(root, econtent_type: str, object_type: str) -> list[ASTNode]:
    ot = object_type.upper()
    if ot == "ROA" or econtent_type == "routeOriginAttestation":
        return _parse_roa_econtent(root)
    elif ot == "ASPA" or econtent_type == "asProviderAttestation":
        return _parse_aspa_econtent(root)
    elif ot in ("MFT", "MANIFEST") or econtent_type == "manifest":
        return _parse_manifest_econtent(root)
    raise ValueError(f"unknown object_type={object_type!r} / eContentType={econtent_type!r}")

def _parse_roa_econtent(root) -> list[ASTNode]:
    asid = root.children[0]
    ip_addr_blocks = root.children[1]

    families: list[ASTNode] = []
    for family_node in ip_addr_blocks.children:
        af_octet = family_node.children[0]
        addrs_seq = family_node.children[1]

        af_bytes = af_octet.content
        af_name = "ipv4" if af_bytes == b"\x00\x01" else "ipv6" if af_bytes == b"\x00\x02" else af_bytes.hex()

        address_nodes: list[ASTNode] = []
        for addr_node in addrs_seq.children:
            children: list[ASTNode] = []
            bitstr = addr_node.children[0]
            children.append(ASTNode("address", value=_decode_ip_prefix(bitstr.content, 6 if af_bytes == b"\x00\x02" else 4)))
            if len(addr_node.children) > 1:
                ml = addr_node.children[1]
                children.append(ASTNode("maxLength", value=_decode_integer(ml.content)))
            address_nodes.append(ASTNode("ROAIPAddress", children=children))

        families.append(ASTNode("ROAIPAddressFamily", children=[
            ASTNode("addressFamily", value=af_name),
            ASTNode("addresses", children=address_nodes),
        ]))

    return [
        ASTNode("asID", value=_decode_integer(asid.content)),
        ASTNode("ipAddrBlocks", children=families),
    ]

def _parse_aspa_econtent(root) -> list[ASTNode]:
    children = root.children
    idx = 0

    version = None
    if children[idx].tag == 0xA0:
        version_inner = children[idx].children[0]
        version = _decode_integer(version_inner.content)
        idx += 1

    customer_asid = _decode_integer(children[idx].content)
    idx += 1

    providers_seq = children[idx]
    provider_nodes: list[ASTNode] = []
    for child in providers_seq.children:
        if child.tag == 0x30:
            pasid = child.children[0]
            p_children: list[ASTNode] = [ASTNode("providerASID", value=_decode_integer(pasid.content))]
            if len(child.children) > 1:
                afi_node = child.children[1]
                afi_bytes = afi_node.content
                afi_name = "ipv4" if afi_bytes == b"\x00\x01" else "ipv6" if afi_bytes == b"\x00\x02" else afi_bytes.hex()
                p_children.append(ASTNode("afiLimit", value=afi_name))
            provider_nodes.append(ASTNode("ProviderAS", children=p_children))
        elif child.tag == 0x02:
            provider_nodes.append(ASTNode("ProviderAS", children=[
                ASTNode("providerASID", value=_decode_integer(child.content)),
            ]))

    result: list[ASTNode] = []
    if version is not None:
        result.append(ASTNode("version", value=version))
    result.append(ASTNode("customerASID", value=customer_asid))
    result.append(ASTNode("providers", children=provider_nodes))
    return result

def _parse_manifest_econtent(root) -> list[ASTNode]:
    children = root.children
    manifest_number = _decode_integer(children[0].content)
    this_update = _decode_generalizedtime(children[1].content)
    next_update = _decode_generalizedtime(children[2].content)

    fha = children[3]
    if fha.tag == 0x06:
        fha_name = _oid_name(fha.content)
    else:
        fha_name = _oid_name(fha.children[0].content)

    file_list_seq = children[4]
    file_entries: list[ASTNode] = []
    for entry in file_list_seq.children:
        filename = _decode_ia5string(entry.children[0].content)
        hash_bits = entry.children[1].content
        hash_hex = hash_bits[1:].hex() if hash_bits else ""
        file_entries.append(ASTNode("fileEntry", children=[
            ASTNode("filename", value=filename),
            ASTNode("hash", value=hash_hex),
        ]))

    return [
        ASTNode("manifestNumber", value=manifest_number),
        ASTNode("thisUpdate", value=this_update),
        ASTNode("nextUpdate", value=next_update),
        ASTNode("fileHashAlgorithm", value=fha_name),
        ASTNode("fileList", children=file_entries),
    ]

def _parse_name(name_seq, label: str) -> ASTNode:
    inner = b"".join(c.serialize() for c in name_seq.children)
    return ASTNode(label, value=inner)

def _parse_ee_cert_structured(cert_seq) -> ASTNode:
    tbs = cert_seq.children[0]
    sig_alg = cert_seq.children[1]
    sig_val = cert_seq.children[2]

    tbs_children: list[ASTNode] = []
    idx = 0
    tbs_items = tbs.children

    if idx < len(tbs_items) and tbs_items[idx].tag == 0xA0:
        version_inner = tbs_items[idx].children[0].serialize()
        tbs_children.append(ASTNode("version", value=version_inner))
        idx += 1

    serial = _decode_integer(tbs_items[idx].content)
    tbs_children.append(ASTNode("serialNumber", value=serial))
    idx += 1

    sig_alg_inner = b"".join(c.serialize() for c in tbs_items[idx].children)
    tbs_children.append(ASTNode("signatureAlgorithm", value=sig_alg_inner))
    idx += 1

    tbs_children.append(_parse_name(tbs_items[idx], "issuer"))
    idx += 1

    validity = tbs_items[idx]
    tbs_children.append(ASTNode("validity", children=[
        ASTNode("notBefore", value=_decode_time(validity.children[0]), der_tag=validity.children[0].tag),
        ASTNode("notAfter", value=_decode_time(validity.children[1]), der_tag=validity.children[1].tag),
    ]))
    idx += 1

    tbs_children.append(_parse_name(tbs_items[idx], "subject"))
    idx += 1

    spki = tbs_items[idx]
    spki_inner = b"".join(c.serialize() for c in spki.children)
    tbs_children.append(ASTNode("subjectPublicKeyInfo", value=spki_inner))
    idx += 1

    for extra in tbs_items[idx:]:
        if extra.tag == 0xA3:
            ext_nodes = _parse_cert_extensions(extra.children[0])
            tbs_children.append(ASTNode("extensions", der_tag=0xA3, children=[
                ASTNode("extSeq", children=ext_nodes, der_tag=0x30)
            ]))
        else:
            tbs_children.append(_raw_der_node(extra, f"optional_{extra.tag:x}"))

    outer_sig_alg_inner = b"".join(c.serialize() for c in sig_alg.children)

    return ASTNode("EECertificate", der_tag=0x30, children=[
        ASTNode("tbsCertificate", children=tbs_children),
        ASTNode("signatureAlgorithm", value=outer_sig_alg_inner),
        ASTNode("signatureValue", value=sig_val.content),
    ])

def _decode_time(node) -> str:
    if node.tag == 0x17:
        return _decode_utctime(node.content)
    elif node.tag == 0x18:
        return _decode_generalizedtime(node.content)
    return node.content.hex()

def _parse_cert_extensions(exts_seq) -> list[ASTNode]:
    _EXT_LABELS = {
        "subjectKeyIdentifier": "ski",
        "authorityKeyIdentifier": "aki",
        "ipAddrBlocks": "ipResources",
        "autonomousSysIds": "asnResources",
        "subjectInfoAccess": "sia",
        "basicConstraints": "basicConstraints",
        "keyUsage": "keyUsage",
        "certificatePolicies": "certPolicy",
        "crlDistributionPoints": "crlDP",
        "authorityInfoAccess": "aia",
    }

    result: list[ASTNode] = []
    for ext in exts_seq.children:
        ext_inner = b"".join(c.serialize() for c in ext.children)
        oid = ext.children[0]
        oid_name = _oid_name(oid.content)
        label = _EXT_LABELS.get(oid_name, oid_name)
        if label == "sia":
            result.append(_parse_sia_extension(ext))
        else:
            result.append(ASTNode(label, value=ext_inner, der_tag=0x30))

    return result


def _raw_der_node(node, label: str) -> ASTNode:
    if node.constructed:
        return ASTNode(label, der_tag=node.tag, children=[
            _raw_der_node(child, f"raw_{child.tag:x}") for child in node.children
        ])
    return ASTNode(label, value=node.content, der_tag=node.tag)


def _parse_sia_extension(extension) -> ASTNode:
    from src.rpkiwi.input.der_ast import DERNode

    labels = {
        bytes.fromhex("2b06010505073005"): "caRepository",
        bytes.fromhex("2b0601050507300a"): "rpkiManifest",
        bytes.fromhex("2b0601050507300d"): "rpkiNotify",
    }
    fields = [ASTNode("extnID" if item.tag == 0x06 else "critical",
                      value=item.content, der_tag=item.tag) for item in extension.children[:-1]]
    descriptions = []
    try:
        value = DERNode.parse(extension.children[-1].content)
    except (ValueError, IndexError):
        return ASTNode("sia", value=b"".join(c.serialize() for c in extension.children), der_tag=0x30)
    for description in value.children:
        if len(description.children) != 2 or description.children[0].tag != 0x06:
            descriptions.append(_raw_der_node(description, "malformedAccessDescription"))
            continue
        method, location = description.children
        location_ast = (ASTNode("uri", value=_decode_ia5string(location.content), der_tag=0x86)
                        if location.tag == 0x86 else _raw_der_node(location, "location"))
        descriptions.append(ASTNode(labels.get(method.content, method.content.hex()), der_tag=0x30, children=[
            ASTNode("method", value=method.content, der_tag=0x06),
            location_ast,
        ]))
    fields.append(ASTNode("extnValue", der_tag=0x04, children=[
        ASTNode("accessDescriptions", der_tag=0x30, children=descriptions),
    ]))
    return ASTNode("sia", der_tag=0x30, children=fields)

def _parse_signer_info(si_seq) -> ASTNode:
    children = si_seq.children
    version = _decode_integer(children[0].content)

    sid = children[1]
    sid_value = sid.content

    digest_alg = children[2]
    digest_alg_oid = digest_alg.children[0]

    signed_attrs_ast: list[ASTNode] = []
    sig_alg_name = "sha256WithRSAEncryption"
    sig_bytes = b""

    idx = 3
    if idx < len(children) and children[idx].tag == 0xA0:
        signed_attrs_node = children[idx]
        signed_attrs_ast = _parse_signed_attrs(signed_attrs_node)
        idx += 1

    if idx < len(children) and children[idx].tag == 0x30:
        sig_alg_seq = children[idx]
        sig_alg_name = _oid_name(sig_alg_seq.children[0].content)
        idx += 1

    if idx < len(children) and children[idx].tag == 0x04:
        sig_bytes = children[idx].content

    return ASTNode("SignerInfo", children=[
        ASTNode("version", value=version),
        ASTNode("sid", value=sid_value),
        ASTNode("digestAlgorithm", value=_oid_name(digest_alg_oid.content)),
        ASTNode("signedAttrs", children=signed_attrs_ast, signed=True),
        ASTNode("signatureAlgorithm", value=sig_alg_name),
        ASTNode("signature", value=sig_bytes),
    ])

def _parse_signed_attrs(attrs_node) -> list[ASTNode]:
    result: list[ASTNode] = []
    for attr in attrs_node.children:
        oid = attr.children[0]
        oid_name = _oid_name(oid.content)
        value_set = attr.children[1]
        value_node = value_set.children[0] if value_set.children else None

        if oid_name == "contentType" and value_node:
            result.append(ASTNode("contentType", value=_oid_name(value_node.content)))
        elif oid_name == "signingTime" and value_node:
            result.append(ASTNode("signingTime", value=_decode_time(value_node)))
        elif oid_name == "messageDigest" and value_node:
            result.append(ASTNode("messageDigest", value=value_node.content))
        else:
            result.append(ASTNode(oid_name, value=value_node.content if value_node else None))

    return result

def _parse_crl(root) -> ASTNode:
    tbs, signature_algorithm, signature_value = root.children
    fields, index = [], 0
    if tbs.children[index].tag == 0x02:
        fields.append(ASTNode("version", value=_decode_integer(tbs.children[index].content), der_tag=0x02))
        index += 1
    algorithm = tbs.children[index]
    fields.append(ASTNode("signatureAlgorithm", value=b"".join(c.serialize() for c in algorithm.children), der_tag=0x30))
    index += 1
    fields.append(_parse_name(tbs.children[index], "issuer"))
    index += 1
    fields.append(ASTNode("thisUpdate", value=_decode_time(tbs.children[index]), der_tag=tbs.children[index].tag))
    index += 1
    if index < len(tbs.children) and tbs.children[index].tag in (0x17, 0x18):
        fields.append(ASTNode("nextUpdate", value=_decode_time(tbs.children[index]), der_tag=tbs.children[index].tag))
        index += 1
    if index < len(tbs.children) and tbs.children[index].tag == 0x30:
        entries = []
        for entry in tbs.children[index].children:
            children = [
                ASTNode("serialNumber", value=_decode_integer(entry.children[0].content), der_tag=0x02),
                ASTNode("revocationDate", value=_decode_time(entry.children[1]), der_tag=entry.children[1].tag),
            ]
            if len(entry.children) > 2:
                children.append(ASTNode("entryExtensions", value=b"".join(c.serialize() for c in entry.children[2].children), der_tag=0x30))
            entries.append(ASTNode("revokedCertificate", children=children, der_tag=0x30))
        fields.append(ASTNode("revokedCertificates", children=entries, der_tag=0x30))
        index += 1
    if index < len(tbs.children) and tbs.children[index].tag == 0xA0:
        extensions = _parse_cert_extensions(tbs.children[index].children[0])
        fields.append(ASTNode("extensions", der_tag=0xA0, children=[
            ASTNode("extSeq", children=extensions, der_tag=0x30),
        ]))
    return ASTNode("CertificateRevocationList", der_tag=0x30, children=[
        ASTNode("tbsCertList", children=fields, signed=True, der_tag=0x30),
        ASTNode("signatureAlgorithm", value=b"".join(c.serialize() for c in signature_algorithm.children), der_tag=0x30),
        ASTNode("signatureValue", value=signature_value.content, der_tag=0x03),
    ])


def _parse_crl_extensions(exts_seq) -> list[ASTNode]:
    result: list[ASTNode] = []
    for ext in exts_seq.children:
        oid = ext.children[0]
        oid_name = _oid_name(oid.content)
        octet = ext.children[-1]
        ext_value = octet.content if octet.tag == 0x04 else octet.content

        if oid_name == "crlNumber":
            from src.rpkiwi.input.der_ast import DERNode
            inner = DERNode.parse(ext_value)
            result.append(ASTNode(oid_name, value=_decode_integer(inner.content)))
        elif oid_name == "authorityKeyIdentifier":
            from src.rpkiwi.input.der_ast import DERNode
            inner = DERNode.parse(ext_value)
            if inner.children:
                result.append(ASTNode("aki", value=inner.children[0].content))
            else:
                result.append(ASTNode("aki", value=ext_value))
        else:
            result.append(ASTNode(oid_name, value=ext_value))

    return result

def _build_cms_wrapper(econtent_type: str, econtent_children: list[ASTNode]) -> ASTNode:
    return ASTNode("ContentInfo", children=[
        ASTNode("contentType", value="signedData"),
        ASTNode("SignedData", children=[
            ASTNode("version", value=3),
            ASTNode("digestAlgorithms", children=[
                ASTNode("algorithm", value="sha256"),
            ]),
            ASTNode("encapContentInfo", children=[
                ASTNode("eContentType", value=econtent_type),
                ASTNode("eContent", children=econtent_children),
            ]),
            ASTNode("certificates", children=[
                ASTNode("EECertificate", children=[
                    ASTNode("serialNumber", value="auto"),
                    ASTNode("issuer", value="auto"),
                    ASTNode("validity", children=[
                        ASTNode("notBefore", value="auto"),
                        ASTNode("notAfter", value="auto"),
                    ]),
                    ASTNode("subject", value="auto"),
                    ASTNode("subjectPublicKeyInfo", value="auto"),
                    ASTNode("extensions", children=[
                        ASTNode("ski", value="auto"),
                        ASTNode("aki", value="auto"),
                        ASTNode("ipResources", value="auto"),
                        ASTNode("asnResources", value="auto"),
                        ASTNode("sia", value="auto"),
                        ASTNode("basicConstraints", value="auto"),
                    ]),
                ]),
            ]),
            ASTNode("crls", value="auto"),
            ASTNode("signerInfos", children=[
                ASTNode("SignerInfo", children=[
                    ASTNode("version", value=3),
                    ASTNode("sid", value="auto"),
                    ASTNode("digestAlgorithm", value="sha256"),
                    ASTNode("signedAttrs", children=[
                        ASTNode("contentType", value="auto"),
                        ASTNode("signingTime", value="auto"),
                        ASTNode("messageDigest", value="auto"),
                    ]),
                    ASTNode("signatureAlgorithm", value="sha256WithRSAEncryption"),
                    ASTNode("signature", value="auto"),
                ]),
            ]),
        ]),
    ])

def build_roa_ast(
    prefix: str | list[str] = "3.0.0.0/24",
    asn: int = 1000,
    max_length: int | list[int | None] | None = None,
) -> ASTNode:
    import ipaddress

    if isinstance(prefix, str):
        prefixes = [prefix]
        max_lengths = [max_length]
    else:
        prefixes = prefix
        max_lengths = max_length if isinstance(max_length, list) else [max_length] * len(prefixes)

    v4_entries: list[ASTNode] = []
    v6_entries: list[ASTNode] = []
    for pfx, ml in zip(prefixes, max_lengths):
        net = ipaddress.ip_network(pfx, strict=False)
        if ml is None:
            ml = net.prefixlen
        entry = ASTNode("ROAIPAddress", children=[
            ASTNode("address", value=pfx),
            ASTNode("maxLength", value=ml),
        ])
        if net.version == 4:
            v4_entries.append(entry)
        else:
            v6_entries.append(entry)

    families: list[ASTNode] = []
    if v4_entries:
        families.append(ASTNode("ROAIPAddressFamily", children=[
            ASTNode("addressFamily", value="ipv4"),
            ASTNode("addresses", children=v4_entries),
        ]))
    if v6_entries:
        families.append(ASTNode("ROAIPAddressFamily", children=[
            ASTNode("addressFamily", value="ipv6"),
            ASTNode("addresses", children=v6_entries),
        ]))

    return _build_cms_wrapper("routeOriginAttestation", [
        ASTNode("asID", value=asn),
        ASTNode("ipAddrBlocks", children=families),
    ])

def build_aspa_ast(
    customer_asid: int = 1000,
    providers: tuple[tuple[int, str | None], ...] = ((1001, None), (1002, None)),
) -> ASTNode:
    normalized = []
    for p in providers:
        if isinstance(p, int):
            normalized.append((p, None))
        else:
            normalized.append(p)

    provider_nodes = []
    for asn, afi in normalized:
        children = [ASTNode("providerASID", value=asn)]
        if afi is not None:
            children.append(ASTNode("afiLimit", value=afi))
        provider_nodes.append(ASTNode("ProviderAS", children=children))

    return _build_cms_wrapper("asProviderAttestation", [
        ASTNode("customerASID", value=customer_asid),
        ASTNode("providers", children=provider_nodes),
    ])

def build_crl_ast(
    revoked_serials: list[int] | None = None,
) -> ASTNode:
    revoked = []
    for serial in (revoked_serials or []):
        revoked.append(ASTNode("revokedCertificate", children=[
            ASTNode("serialNumber", value=serial),
            ASTNode("revocationDate", value="auto"),
        ]))

    return ASTNode("CertificateRevocationList", children=[
        ASTNode("tbsCertList", children=[
            ASTNode("version", value=1),
            ASTNode("signature", children=[
                ASTNode("algorithm", value="sha256WithRSAEncryption"),
            ]),
            ASTNode("issuer", value="auto"),
            ASTNode("thisUpdate", value="auto"),
            ASTNode("nextUpdate", value="auto"),
            ASTNode("revokedCertificates", children=revoked),
            ASTNode("extensions", children=[
                ASTNode("crlNumber", value=3),
                ASTNode("aki", value="auto"),
            ]),
        ]),
        ASTNode("signatureAlgorithm", children=[
            ASTNode("algorithm", value="sha256WithRSAEncryption"),
        ]),
        ASTNode("signatureValue", value="auto"),
    ])

def build_manifest_ast(
    file_list: list[tuple[str, str]] | None = None,
) -> ASTNode:
    file_nodes = []
    for name, hash_hex in (file_list or []):
        file_nodes.append(ASTNode("fileEntry", children=[
            ASTNode("filename", value=name),
            ASTNode("hash", value=hash_hex),
        ]))

    return _build_cms_wrapper("manifest", [
        ASTNode("manifestNumber", value="auto"),
        ASTNode("thisUpdate", value="auto"),
        ASTNode("nextUpdate", value="auto"),
        ASTNode("fileHashAlgorithm", value="sha256"),
        ASTNode("fileList", children=file_nodes),
    ])

def build_cer_ast(
    subject: str = "child-ca",
    notify_uri: str = "auto",
    ca_repository: str = "auto",
    manifest_uri: str = "auto",
) -> ASTNode:
    return ASTNode("CACertificate", children=[
        ASTNode("tbsCertificate", children=[
            ASTNode("version", value=2),
            ASTNode("serialNumber", value="auto"),
            ASTNode("signature", children=[
                ASTNode("algorithm", value="sha256WithRSAEncryption"),
            ]),
            ASTNode("issuer", value="auto"),
            ASTNode("validity", children=[
                ASTNode("notBefore", value="auto"),
                ASTNode("notAfter", value="auto"),
            ]),
            ASTNode("subject", value=subject),
            ASTNode("subjectPublicKeyInfo", value="auto"),
            ASTNode("extensions", children=[
                ASTNode("basicConstraints", value="ca_true"),
                ASTNode("ski", value="auto"),
                ASTNode("aki", value="auto"),
                ASTNode("keyUsage", value="auto"),
                ASTNode("certPolicy", value="auto"),
                ASTNode("sia", value=notify_uri),
                ASTNode("crlDP", value="auto"),
                ASTNode("aia", value="auto"),
                ASTNode("ipResources", value="auto"),
                ASTNode("asnResources", value="auto"),
            ]),
        ], signed=True),
        ASTNode("signatureAlgorithm", children=[
            ASTNode("algorithm", value="sha256WithRSAEncryption"),
        ]),
        ASTNode("signatureValue", value="auto"),
    ])

def _cms_ast_is_faithful_ready(ast: ASTNode) -> bool:
    if ast.has_auto():
        return False
    ee = ast.find("SignedData/certificates/EECertificate")
    if ee is None:
        return False
    if ee.children:
        sig_val = ee.find("signatureValue")
        if sig_val is None or not isinstance(sig_val.value, (bytes, bytearray)):
            return False
    else:
        if not isinstance(ee.value, (bytes, bytearray)):
            return False
    signer_infos = ast.find("SignedData/signerInfos")
    if signer_infos is None:
        return False
    if not signer_infos.children:
        return True
    si = ast.find("SignedData/signerInfos/SignerInfo")
    if si is None:
        return False
    sig = si.child("signature")
    if sig is None or not isinstance(sig.value, (bytes, bytearray)):
        return False
    md = ast.find("SignedData/signerInfos/SignerInfo/signedAttrs/messageDigest")
    if md is None or not isinstance(md.value, (bytes, bytearray)):
        return False
    return True

def _re_sign_all(
    ast: ASTNode, config: "RPKIConfig", ee_key_pem: str | None = None,
    *, preserve_cms_digest: bool = False,
    preserve_cms_signature: bool = False, preserve_object_signature: bool = False,
) -> None:
    from src.rpkiwi.input.builders.ca_cert import load_ca_cert_and_key
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
    from src.rpkiwi.input.ast_encoder import ast_to_der
    from src.rpkiwi.input.cms_encoder import _encode_signed_attrs, _encode_tlv_raw
    import hashlib

    _, ca_key = load_ca_cert_and_key(config.ca_source_cert_path, config.ca_source_key_path)
    if ast.label in ("CACertificate", "CertificateRevocationList"):
        tbs = ast.child("tbsCertificate") or ast.child("tbsCertList")
        signature = ast.child("signatureValue")
        if not preserve_object_signature and tbs is not None and signature is not None and ast.der_tag is not None:
            signature.value = b"\x00" + ca_key.sign(ast_to_der(tbs), padding.PKCS1v15(), hashes.SHA256())
        return

    certificate = ast.find("SignedData/certificates/EECertificate")
    if certificate is not None and certificate.children:
        tbs = certificate.child("tbsCertificate")
        signature = certificate.child("signatureValue")
        if tbs is not None and signature is not None:
            signature.value = b"\x00" + ca_key.sign(ast_to_der(tbs), padding.PKCS1v15(), hashes.SHA256())
    if not ee_key_pem:
        return
    ee_key = serialization.load_pem_private_key(ee_key_pem.encode(), password=None)
    content = ast.find("SignedData/encapContentInfo/eContent")
    if content is None:
        return
    body = (_encode_tlv_raw(0x30, b"".join(ast_to_der(c) for c in content.children))
            if content.children else bytes(content.value or b""))
    for signer in ast.find_all("SignedData/signerInfos/SignerInfo"):
        attributes = signer.child("signedAttrs")
        signature = signer.child("signature")
        if attributes is None or signature is None:
            continue
        digest = attributes.child("messageDigest")
        if digest is not None and not preserve_cms_digest:
            digest.value = hashlib.sha256(body).digest()
        # Sign the actual encoded attributes, including deliberate digest faults.
        encoded = _encode_signed_attrs(attributes)
        if not preserve_cms_signature:
            signature.value = ee_key.sign(b"\x31" + encoded[1:], padding.PKCS1v15(), hashes.SHA256())


def serialize(
    ast: ASTNode, config: "RPKIConfig", can_resign: bool = False,
    ee_key_pem: str | None = None, *, preserve_cms_digest: bool = False,
    preserve_cms_signature: bool = False, preserve_object_signature: bool = False,
) -> bytes:
    if ast.label in ("CertificateRevocationList", "CACertificate") and ast.children and ast.der_tag is None:
        raise ValueError("legacy certificate/CRL templates cannot preserve mutations; generate and parse a concrete object first")
    if can_resign:
        _re_sign_all(ast, config, ee_key_pem=ee_key_pem, preserve_cms_digest=preserve_cms_digest,
                     preserve_cms_signature=preserve_cms_signature, preserve_object_signature=preserve_object_signature)

    if ast.label in ("CertificateRevocationList", "CACertificate") and ast.der_tag is not None:
        from src.rpkiwi.input.ast_encoder import ast_to_der
        return ast_to_der(ast)

    if ast.label == "CertificateRevocationList":
        if not ast.children and isinstance(ast.value, (bytes, bytearray)):
            return bytes(ast.value)
        return _serialize_crl(ast, config)

    if ast.label == "CACertificate":
        if not ast.children and isinstance(ast.value, (bytes, bytearray)):
            return bytes(ast.value)
        return _serialize_ca_cert(ast, config)

    if ast.label == "ContentInfo":
        if not _cms_ast_is_faithful_ready(ast):
            auto_paths = ast.iter_auto_paths()
            detail = f"auto at: {auto_paths[:3]}" if auto_paths else (
                "signerInfos incomplete"
            )
            raise ValueError(
                f"serialize requires a faithful-ready ContentInfo AST; {detail}. "
                "Run ast_expand.expand() first, or use generator._wrap_cms for "
                "programmatic construction from auto-heavy templates."
            )
        from src.rpkiwi.input.cms_encoder import encode_content_info
        return encode_content_info(ast)

    raise ValueError(f"serialize does not handle root label {ast.label!r}")

def _generate_crl_with_revocations(config: "RPKIConfig", serials: list[int]) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from datetime import datetime, timedelta, timezone
    from src.rpkiwi.input.builders.ca_cert import load_ca_cert_and_key

    ca_cert, ca_key = load_ca_cert_and_key(config.ca_source_cert_path, config.ca_source_key_path)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.last_update(now)
    builder = builder.next_update(now + timedelta(days=7))
    builder = builder.add_extension(x509.CRLNumber(3), critical=False)
    try:
        ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=ca_ski.value.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )
    except x509.ExtensionNotFound:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    builder = builder.add_extension(aki, critical=False)
    for serial in serials:
        revoked = x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build()
        builder = builder.add_revoked_certificate(revoked)
    crl = builder.sign(ca_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.DER)

def _serialize_crl(ast: ASTNode, config: "RPKIConfig") -> bytes:
    from src.rpkiwi.input.generator import generate_crl
    tbs = ast.child("tbsCertList")
    if tbs:
        revoked_node = tbs.child("revokedCertificates")
        if revoked_node and revoked_node.children:
            serials = []
            for entry in revoked_node.children:
                sn = entry.child("serialNumber")
                if sn and isinstance(sn.value, int):
                    serials.append(sn.value)
            if serials:
                return _generate_crl_with_revocations(config, serials)
    return generate_crl(config)

def _serialize_ca_cert(ast: ASTNode, config: "RPKIConfig") -> bytes:
    from src.rpkiwi.input.builders.ca_cert import load_ca_cert_and_key, generate_child_ca_cert

    tbs = ast.child("tbsCertificate")
    subject_node = tbs.child("subject") if tbs else None
    subject = subject_node.value if subject_node and subject_node.value != "auto" else "child-ca"

    sia_node = tbs.find("extensions/sia") if tbs else None
    notify_uri = None
    if sia_node and sia_node.value not in ("auto", None) and isinstance(sia_node.value, str):
        if sia_node.value.startswith("http"):
            notify_uri = sia_node.value

    ca_cert, ca_key = load_ca_cert_and_key(
        config.ca_source_cert_path, config.ca_source_key_path
    )
    cert_der, _ = generate_child_ca_cert(
        config, ca_cert, ca_key,
        subject=subject,
        notify_uri=notify_uri,
    )
    return cert_der

def print_ast(node: ASTNode, indent: int = 0) -> None:
    prefix = "  " * indent
    tag = " [SIGNED]" if node.signed else ""
    if node.children:
        print(f"{prefix}{node.label}:{tag}")
        for c in node.children:
            print_ast(c, indent + 1)
    elif node.value is not None:
        if isinstance(node.value, bytes):
            v = node.value[:16].hex() + ("..." if len(node.value) > 16 else "")
            print(f"{prefix}{node.label} = <{len(node.value)}B> {v}{tag}")
        else:
            print(f"{prefix}{node.label} = {node.value}{tag}")
    else:
        print(f"{prefix}{node.label}{tag}")

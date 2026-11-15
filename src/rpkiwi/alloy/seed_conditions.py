"""Byte-level checks for the field constraints concretized from a witness.

These checks establish properties of an input, not acceptance by a validator.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from urllib.parse import urlparse

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from rpkiwi.config import RPKIConfig
from rpkiwi.input.ast_node import ASTNode
from rpkiwi.input.ast_encoder import ast_to_der
from rpkiwi.input.der_ast import DERNode


class SeedConditionError(ValueError):
    pass


def json_value(value):
    if isinstance(value, (bytes, bytearray)):
        return {"bytes_b64": base64.b64encode(value).decode()}
    return value


def parse_input(data: bytes, object_type: str) -> ASTNode:
    if object_type in {"SNAPSHOT", "DELTA", "NOTIFICATION"}:
        from rpkiwi.input.rrdp_ast import parse_rrdp_to_ast
        return parse_rrdp_to_ast(data, object_type)
    return ASTNode.from_der(data, object_type)


def cms_parts(data: bytes) -> tuple[bytes, x509.Certificate, list[DERNode]]:
    root = DERNode.parse(data)
    sd = root.children[1].children[0]
    content = sd.children[2].children[1].children[0].content
    certs = sd.child_by_tag(0xA0)
    if certs is None or not certs.children:
        raise SeedConditionError("CMS has no EE certificate")
    cert = x509.load_der_x509_certificate(certs.children[0].serialize())
    signers = sd.children[-1]
    if signers.tag != 0x31:
        raise SeedConditionError("CMS has no signerInfos SET")
    return content, cert, signers.children


def cms_signature_valid(data: bytes) -> bool:
    _, cert, signers = cms_parts(data)
    if len(signers) != 1:
        return False
    signer = signers[0]
    attrs = signer.child_by_tag(0xA0)
    signature = signer.child_by_tag(0x04)
    if attrs is None or signature is None:
        return False
    try:
        cert.public_key().verify(signature.content, b"\x31" + attrs.serialize()[1:], padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def extension_value(node: ASTNode) -> bytes:
    extension = DERNode.parse(ast_to_der(node))
    value = extension.children[-1]
    if value.tag != 0x04:
        raise SeedConditionError("extension has no OCTET STRING value")
    return value.content


def observe_condition(data: bytes, object_type: str, ast: ASTNode, condition: dict, config: RPKIConfig | None = None):
    kind = condition["kind"]
    if kind == "byte_replay":
        return hashlib.sha256(data).hexdigest()
    if kind == "cms_signature_valid":
        return cms_signature_valid(data)
    if kind == "cms_digest_matches":
        content, _, _ = cms_parts(data)
        digests = ast.find_all("SignedData/signerInfos/SignerInfo/signedAttrs/messageDigest")
        return len(digests) == 1 and digests[0].value == hashlib.sha256(content).digest()
    if kind == "object_signature_valid":
        if config is None:
            raise SeedConditionError("public issuer configuration required")
        role = condition.get("issuer", "attacker")
        issuer_config = (config if role == "attacker" else RPKIConfig(
            base_domain="victim-pp.com", ca_name="victim-ca", build_dir=config.build_dir))
        issuer = x509.load_der_x509_certificate(Path(issuer_config.ca_source_cert_path).read_bytes())
        obj = (x509.load_der_x509_crl(data) if object_type == "CRL" else x509.load_der_x509_certificate(data))
        body = obj.tbs_certlist_bytes if object_type == "CRL" else obj.tbs_certificate_bytes
        try:
            issuer.public_key().verify(obj.signature, body, padding.PKCS1v15(), obj.signature_hash_algorithm)
            return True
        except InvalidSignature:
            return False
    path = condition["path"]
    nodes = ast.find_all(path)
    if not nodes:
        raise SeedConditionError(f"final bytes lack {path}")
    if kind == "roa_prefixes":
        return [n.value for n in nodes[0].find_all("ROAIPAddressFamily/addresses/ROAIPAddress/address")]
    if kind == "extension_value":
        return json_value(extension_value(nodes[0]))
    if kind == "uri_host":
        return urlparse(nodes[0].value).hostname
    if kind == "child_count":
        return len(nodes[0].children)
    if kind == "ast_value":
        return json_value(nodes[0].value)
    if kind == "ast_values":
        return [json_value(node.value) for node in nodes]
    raise SeedConditionError(f"unknown seed condition {kind}")


def condition_holds(condition: dict, observed) -> bool:
    expected = condition["expected"]
    if condition.get("match", "equals") == "contains":
        return isinstance(observed, list) and expected in observed
    return observed == expected


def check_postconditions(data: bytes, object_type: str, conditions: list[dict], config: RPKIConfig | None = None) -> list[dict]:
    ast = parse_input(data, object_type)
    observations = []
    for condition in conditions:
        observed = observe_condition(data, object_type, ast, condition, config)
        passed = condition_holds(condition, observed)
        observations.append({"condition": condition, "observed": observed, "passed": passed})
        if not passed:
            raise SeedConditionError(f"postcondition failed: {condition}; observed={observed}")
    return observations


def validate_seed(data: bytes, object_type: str, metadata: dict, config: RPKIConfig | None = None) -> None:
    expected_hash = metadata.get("data_sha256")
    if expected_hash is not None and hashlib.sha256(data).hexdigest() != expected_hash:
        raise SeedConditionError("seed bytes differ from recorded input hash")
    conditions = metadata.get("postconditions", [])
    if conditions:
        check_postconditions(data, object_type, conditions, config)

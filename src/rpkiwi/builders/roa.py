from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timezone
from typing import Callable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from src.rpkiwi.config import RPKIConfig, get_config
from src.rpkiwi.input.asnme.model.asn import ASN1SequenceOf, ASN1SetOf
from src.rpkiwi.input.asnme.model.cms import (
    AlgorithmIdentifier,
    ContentInfo,
    DER_NULL,
    EncapsulatedContentInfo,
    SignerInfo,
    SignedData,
    build_signed_attrs,
)
from src.rpkiwi.builders.ca_cert import load_ca_cert_and_key
from src.rpkiwi.builders.constant import OID_ROA, OID_SHA256, OID_SHA256_RSA, OID_SIGNED_DATA
from src.rpkiwi.builders.ee_cert import generate_ee_cert
from src.rpkiwi.input.schema.roa import ASID, IPAddress, ROAIPAddress, ROAIPAddressFamily, RouteOriginAttestation
from src.rpkiwi.utils import compute_sha256, encode_ip_prefix_to_bitstring, parse_roa_prefixes

def generate_roa_content(prefix: str, asn: int, max_length: Optional[int] = None) -> bytes:
    network = ipaddress.ip_network(prefix, strict=False)
    prefix_len = network.prefixlen
    if max_length is None:
        max_length = prefix_len

    ip_bitstring = encode_ip_prefix_to_bitstring(prefix)
    ip_address = IPAddress(value=ip_bitstring)
    roa_ip_address = ROAIPAddress(address=ip_address, maxLength=max_length)
    afi = b"\x00\x01" if isinstance(network, ipaddress.IPv4Network) else b"\x00\x02"
    ip_family = ROAIPAddressFamily(
        addressFamily=afi,
        addresses=ASN1SequenceOf([roa_ip_address]),
    )
    roa = RouteOriginAttestation(
        asID=ASID(value=asn),
        ipAddrBlocks=ASN1SequenceOf([ip_family]),
    )
    return roa.der_encode()

def generate_multi_roa_content(entries: list[tuple[str, int]], asn: int) -> bytes:
    families: dict[bytes, list[ROAIPAddress]] = {}
    for prefix, max_length in entries:
        network = ipaddress.ip_network(prefix, strict=False)
        afi = b"\x00\x01" if isinstance(network, ipaddress.IPv4Network) else b"\x00\x02"
        families.setdefault(afi, []).append(
            ROAIPAddress(
                address=IPAddress(value=encode_ip_prefix_to_bitstring(prefix)),
                maxLength=max_length,
            )
        )
    blocks = [
        ROAIPAddressFamily(addressFamily=afi, addresses=ASN1SequenceOf(addresses))
        for afi, addresses in families.items()
    ]
    return RouteOriginAttestation(
        asID=ASID(value=asn),
        ipAddrBlocks=ASN1SequenceOf(blocks),
    ).der_encode()

def generate_roa_cms(
    roa_der: bytes,
    ee_cert: x509.Certificate,
    ee_key: rsa.RSAPrivateKey,
    signing_time: Optional[datetime] = None,
    signed_data_version: int = 3,
    unsigned_attrs_der: Optional[bytes] = None,
    signed_attrs_builder: Optional[Callable[[bytes], tuple[bytes, bytes]]] = None,
) -> bytes:
    if signing_time is None:
        signing_time = datetime.now(timezone.utc)

    ski_ext = ee_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    ski_bytes = ski_ext.value.digest

    if signed_attrs_builder:
        signed_attrs_implicit, signed_attrs_for_signing = signed_attrs_builder(roa_der)
    else:
        message_digest = compute_sha256(roa_der)
        signed_attrs_implicit, signed_attrs_for_signing = build_signed_attrs(
            content_type_oid=OID_ROA,
            signing_time=signing_time,
            message_digest=message_digest,
        )

    signature = ee_key.sign(
        signed_attrs_for_signing,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    ee_cert_der = ee_cert.public_bytes(serialization.Encoding.DER)
    certs_content = ee_cert_der
    certs_length = len(certs_content)
    if certs_length < 128:
        certs_encoded = bytes([0xA0, certs_length]) + certs_content
    else:
        length_bytes = certs_length.to_bytes((certs_length.bit_length() + 7) // 8, "big")
        certs_encoded = bytes([0xA0, 0x80 | len(length_bytes)]) + length_bytes + certs_content

    signer_info = SignerInfo(
        version=3,
        sid=ski_bytes,
        digestAlgorithm=AlgorithmIdentifier(algorithm=OID_SHA256, parameters=DER_NULL),
        signedAttrs=signed_attrs_implicit,
        signatureAlgorithm=AlgorithmIdentifier(algorithm=OID_SHA256_RSA, parameters=DER_NULL),
        signature=signature,
        unsignedAttrs=unsigned_attrs_der,
    )

    signed_data = SignedData(
        version=signed_data_version,
        digestAlgorithms=ASN1SetOf([AlgorithmIdentifier(algorithm=OID_SHA256, parameters=DER_NULL)]),
        encapContentInfo=EncapsulatedContentInfo(eContentType=OID_ROA, eContent=roa_der),
        certificates=certs_encoded,
        crls=None,
        signerInfos=ASN1SetOf([signer_info]),
    )
    content_info = ContentInfo(contentType=OID_SIGNED_DATA, content=signed_data)
    return content_info.der_encode()

def sign_roa(
    roa_filename: str,
    roa_der: bytes,
    *,
    verbose: bool = True,
    cms_params: Optional[dict] = None,
    ee_ipv4_override: Optional[list[str]] = None,
    ee_ipv6_override: Optional[list[str]] = None,
    ee_serial: Optional[int] = None,
    ee_cert_policy_oid: Optional[str] = None,
    ee_ip_resources_oid: Optional[str] = None,
    custom_ee_cert_generator: Optional[Callable] = None,
    config: Optional[RPKIConfig] = None,
) -> str:
    config = config or get_config()

    if verbose:
        print("=" * 60)
        print(f"Generating ROA: {roa_filename}")
        print("=" * 60)
        print("\n1. Loading CA certificate and key...")
        print(f"   CA Cert: {config.ca_source_cert_path}")
        print(f"   CA Key: {config.ca_source_key_path}")

    ca_cert, ca_key = load_ca_cert_and_key(config.ca_source_cert_path, config.ca_source_key_path)
    if verbose:
        print(f"   CA Subject: {ca_cert.subject}")
        print("\n2. Parsing ROA content for EE certificate IP resources...")

    try:
        _, ipv4_prefixes, ipv6_prefixes = parse_roa_prefixes(roa_der)
    except Exception as exc:
        if verbose:
            print(f"   WARNING: Failed to parse ROA prefixes ({exc}), using inherit")
        ipv4_prefixes, ipv6_prefixes = [], []

    if ee_ipv4_override is not None:
        ipv4_prefixes = ee_ipv4_override
        if verbose:
            print(f"   EE IPv4 OVERRIDE: {ipv4_prefixes}")
    if ee_ipv6_override is not None:
        ipv6_prefixes = ee_ipv6_override
        if verbose:
            print(f"   EE IPv6 OVERRIDE: {ipv6_prefixes}")

    if verbose:
        if ipv4_prefixes:
            print(f"   IPv4 prefixes: {', '.join(ipv4_prefixes)}")
        if ipv6_prefixes:
            print(f"   IPv6 prefixes: {', '.join(ipv6_prefixes)}")
        print("\n3. Generating EE certificate (explicit IP resources)...")

    if custom_ee_cert_generator:
        ee_cert, ee_key = custom_ee_cert_generator(config, ca_cert, ca_key, roa_filename)
    else:
        ee_cert, ee_key = generate_ee_cert(
            config=config,
            ca_cert=ca_cert,
            ca_key=ca_key,
            roa_filename=roa_filename,
            ipv4_prefixes=ipv4_prefixes or None,
            ipv6_prefixes=ipv6_prefixes or None,
            serial=ee_serial,
            cert_policy_oid=ee_cert_policy_oid,
            ip_resources_oid=ee_ip_resources_oid,
        )

    if verbose:
        ski = ee_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        print(f"   EE SKI: {ski.value.digest.hex()}")

    ee_path = os.path.join(config.ca_source_dir, f"{roa_filename}-ee.cer")
    with open(ee_path, "wb") as handle:
        handle.write(ee_cert.public_bytes(serialization.Encoding.DER))
    if verbose:
        print(f"   Saved: {ee_path}")
        print("\n4. Wrapping in CMS SignedData...")

    roa_cms = generate_roa_cms(roa_der, ee_cert, ee_key, **(cms_params or {}))
    roa_path = os.path.join(config.ca_source_dir, f"{roa_filename}.roa")
    with open(roa_path, "wb") as handle:
        handle.write(roa_cms)

    if verbose:
        print(f"   CMS size: {len(roa_cms)} bytes")
        print(f"   Saved: {roa_path}")
        print("\n" + "=" * 60)
        print("ROA generation complete!")
        print("=" * 60)

    return roa_path

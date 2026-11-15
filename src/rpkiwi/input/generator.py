from __future__ import annotations

import ipaddress
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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
from src.rpkiwi.input.asnme.model.der.encoder import DEREncoder
from src.rpkiwi.input.asnme.model.der.length import encode_tlv
from src.rpkiwi.input.asnme.model.misc import encode_generalized_time, encode_bit_string_with_hash

from src.rpkiwi.config import RPKIConfig
from src.rpkiwi.input.builders import (
    OID_ROA, OID_ASPA, OID_MANIFEST, OID_SHA256, OID_SHA256_RSA, OID_SIGNED_DATA,
)
from src.rpkiwi.input.builders.ca_cert import load_ca_cert_and_key
from src.rpkiwi.input.builders.ee_cert import generate_ee_cert, generate_aspa_ee_cert, generate_manifest_ee_cert
from src.rpkiwi.input.schema.roa import ASID, IPAddress, ROAIPAddress, ROAIPAddressFamily, RouteOriginAttestation
from src.rpkiwi.input.schema.aspa import ASProviderAttestation, ProviderAS
from src.rpkiwi.input.utils import compute_sha256, encode_ip_prefix_to_bitstring, parse_roa_prefixes

def generate_roa_content(prefix: str, asn: int, max_length: Optional[int] = None) -> bytes:
    network = ipaddress.ip_network(prefix, strict=False)
    prefix_len = network.prefixlen
    if max_length is None:
        max_length = prefix_len

    ip_bitstring = encode_ip_prefix_to_bitstring(prefix)
    ip_address = IPAddress(value=ip_bitstring)
    roa_ip_address = ROAIPAddress(address=ip_address, maxLength=max_length)
    afi = b"\x00\x01" if isinstance(network, ipaddress.IPv4Network) else b"\x00\x02"
    ip_family = ROAIPAddressFamily(addressFamily=afi, addresses=ASN1SequenceOf([roa_ip_address]))
    roa = RouteOriginAttestation(asID=ASID(value=asn), ipAddrBlocks=ASN1SequenceOf([ip_family]))
    return roa.der_encode()

def _wrap_cms(
    content_der: bytes,
    ee_cert: x509.Certificate,
    ee_key: rsa.RSAPrivateKey,
    content_type_oid: str,
    signing_time: Optional[datetime] = None,
    _sidecar: dict | None = None,
) -> bytes:
    if signing_time is None:
        signing_time = datetime.now(timezone.utc)

    ski_ext = ee_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    ski_bytes = ski_ext.value.digest
    message_digest = compute_sha256(content_der)
    signed_attrs_implicit, signed_attrs_for_signing = build_signed_attrs(
        content_type_oid=content_type_oid,
        signing_time=signing_time,
        message_digest=message_digest,
    )

    signature = ee_key.sign(signed_attrs_for_signing, padding.PKCS1v15(), hashes.SHA256())
    ee_cert_der = ee_cert.public_bytes(serialization.Encoding.DER)
    certs_length = len(ee_cert_der)
    if certs_length < 128:
        certs_encoded = bytes([0xA0, certs_length]) + ee_cert_der
    else:
        length_bytes = certs_length.to_bytes((certs_length.bit_length() + 7) // 8, "big")
        certs_encoded = bytes([0xA0, 0x80 | len(length_bytes)]) + length_bytes + ee_cert_der

    signer_info = SignerInfo(
        version=3,
        sid=ski_bytes,
        digestAlgorithm=AlgorithmIdentifier(algorithm=OID_SHA256, parameters=DER_NULL),
        signedAttrs=signed_attrs_implicit,
        signatureAlgorithm=AlgorithmIdentifier(algorithm=OID_SHA256_RSA, parameters=DER_NULL),
        signature=signature,
        unsignedAttrs=None,
    )
    signed_data = SignedData(
        version=3,
        digestAlgorithms=ASN1SetOf([AlgorithmIdentifier(algorithm=OID_SHA256, parameters=DER_NULL)]),
        encapContentInfo=EncapsulatedContentInfo(eContentType=content_type_oid, eContent=content_der),
        certificates=certs_encoded,
        crls=None,
        signerInfos=ASN1SetOf([signer_info]),
    )
    if _sidecar is not None:
        _sidecar["_ee_key_pem"] = ee_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

    content_info = ContentInfo(contentType=OID_SIGNED_DATA, content=signed_data)
    return content_info.der_encode()

def generate_roa(config: RPKIConfig, prefix: str = "3.0.0.0/24", asn: int = 1000, roa_filename: str = "fuzz-roa") -> tuple[bytes, str]:
    roa_der = generate_roa_content(prefix, asn)
    ca_cert, ca_key = load_ca_cert_and_key(config.ca_source_cert_path, config.ca_source_key_path)
    try:
        _, ipv4_prefixes, ipv6_prefixes = parse_roa_prefixes(roa_der)
    except Exception:
        ipv4_prefixes, ipv6_prefixes = [], []
    ee_cert, ee_key = generate_ee_cert(
        config=config,
        ca_cert=ca_cert,
        ca_key=ca_key,
        roa_filename=roa_filename,
        ipv4_prefixes=ipv4_prefixes or None,
        ipv6_prefixes=ipv6_prefixes or None,
    )
    sidecar: dict = {}
    data = _wrap_cms(roa_der, ee_cert, ee_key, OID_ROA, _sidecar=sidecar)
    return data, sidecar["_ee_key_pem"]

def generate_aspa_content(customer_asid: int, providers: Iterable[int | tuple[int, str | None]]) -> bytes:
    _AFI_MAP = {"ipv4": b"\x00\x01", "ipv6": b"\x00\x02"}
    provider_objects = []
    for p in providers:
        if isinstance(p, tuple):
            asn, afi = p
        else:
            asn, afi = p, None
        afi_bytes = _AFI_MAP.get(afi) if afi else None
        provider_objects.append(ProviderAS(providerASID=ASID(value=asn), afiLimit=afi_bytes))
    aspa = ASProviderAttestation(
        customerASID=ASID(value=customer_asid),
        providers=ASN1SequenceOf(provider_objects),
    )
    return aspa.der_encode()

def generate_aspa(config: RPKIConfig, customer_asid: int = 1000, providers: tuple[int | tuple[int, str | None], ...] = ((1001, None), (1002, None))) -> tuple[bytes, str]:
    aspa_der = generate_aspa_content(customer_asid, providers)
    ca_cert, ca_key = load_ca_cert_and_key(config.ca_source_cert_path, config.ca_source_key_path)
    ee_cert, ee_key = generate_aspa_ee_cert(
        config=config,
        ca_cert=ca_cert,
        ca_key=ca_key,
        aspa_filename="fuzz-aspa",
        customer_asid=customer_asid,
    )
    sidecar: dict = {}
    data = _wrap_cms(aspa_der, ee_cert, ee_key, OID_ASPA, _sidecar=sidecar)
    return data, sidecar["_ee_key_pem"]

def generate_manifest_content(
    manifest_number: int,
    this_update: datetime,
    next_update: datetime,
    file_list: list[tuple[str, bytes]],
) -> bytes:
    from src.rpkiwi.input.asnme.model.der.tags import SEQUENCE_TAG, IA5_STRING_TAG

    file_entries = []
    for filename, file_hash in file_list:
        file_ia5 = encode_tlv(IA5_STRING_TAG.encode(), filename.encode('ascii'))
        hash_bits = encode_bit_string_with_hash(file_hash)
        file_entry = encode_tlv(SEQUENCE_TAG.encode(), file_ia5 + hash_bits)
        file_entries.append(file_entry)

    file_list_der = encode_tlv(SEQUENCE_TAG.encode(), b''.join(file_entries))
    manifest_num_der = DEREncoder.encode_integer(manifest_number)
    this_update_der = encode_generalized_time(this_update)
    next_update_der = encode_generalized_time(next_update)
    file_hash_alg_der = DEREncoder.encode_object_identifier(OID_SHA256)
    manifest_content = manifest_num_der + this_update_der + next_update_der + file_hash_alg_der + file_list_der
    return encode_tlv(SEQUENCE_TAG.encode(), manifest_content)

def generate_manifest(config: RPKIConfig, file_list: list[tuple[str, bytes]]) -> tuple[bytes, str]:
    ca_cert, ca_key = load_ca_cert_and_key(config.ca_source_cert_path, config.ca_source_key_path)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    manifest_number = int(time.time())
    ee_cert, ee_key = generate_manifest_ee_cert(
        config=config,
        ca_cert=ca_cert,
        ca_key=ca_key,
        serial=manifest_number,
        not_before=now,
        not_after=now + timedelta(days=1),
    )
    manifest_der = generate_manifest_content(
        manifest_number=manifest_number,
        this_update=now,
        next_update=now + timedelta(days=1),
        file_list=file_list,
    )
    sidecar: dict = {}
    data = _wrap_cms(manifest_der, ee_cert, ee_key, OID_MANIFEST, signing_time=now, _sidecar=sidecar)
    return data, sidecar["_ee_key_pem"]

def generate_crl(config: RPKIConfig, *, revoked_serials: Iterable[int] = ()) -> bytes:
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
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build()
        )
    crl = builder.sign(ca_key, hashes.SHA256())
    return crl.public_bytes(serialization.Encoding.DER)

def generate_snapshot(config: RPKIConfig) -> bytes:
    from src.rpkiwi.input.xmlme.rrdp import build_snapshot_xml
    xml_content, _session_id, _serial, _hash = build_snapshot_xml(config)
    return xml_content.encode("utf-8")

def generate_notification(config: RPKIConfig) -> bytes:
    import hashlib
    import uuid
    from src.rpkiwi.input.xmlme.rrdp import build_snapshot_xml
    session_id = str(uuid.uuid4())
    serial = int(time.time())
    xml_content, session_id, _serial, snapshot_hash = build_snapshot_xml(config, session_id, serial)
    snapshot_uri = (
        f"https://{config.ca_base_domain}/{config.ca_rrdp_base_path}/"
        f"{session_id}/{serial}/snapshot.xml"
    )
    notification_xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<notification version="1" session_id="{session_id}" serial="{serial}" '
        f'xmlns="http://www.ripe.net/rpki/rrdp">\n'
        f'  <snapshot uri="{snapshot_uri}" hash="{snapshot_hash}"/>\n'
        f'</notification>'
    )
    return notification_xml.encode("utf-8")

def generate_delta(config: RPKIConfig) -> bytes:
    import base64
    import hashlib
    import uuid
    session_id = str(uuid.uuid4())
    serial = int(time.time())
    roa_data = None
    source_dir = os.path.join(config.ca_source_dir)
    if os.path.exists(source_dir):
        for filename in os.listdir(source_dir):
            if filename.endswith('.roa'):
                with open(os.path.join(source_dir, filename), 'rb') as f:
                    roa_data = f.read()
                roa_uri = f"rsync://{config.ca_base_domain}/{config.ca_repo_base_path}/{filename}"
                break
    if roa_data is None:
        roa_data = generate_roa(config, prefix="3.0.0.0/24", asn=1000)[0]
        roa_uri = f"rsync://{config.ca_base_domain}/{config.ca_repo_base_path}/fuzz.roa"
    roa_b64 = base64.b64encode(roa_data).decode("ascii")
    withdraw_uri = f"rsync://{config.ca_base_domain}/{config.ca_repo_base_path}/withdrawn.roa"
    withdraw_hash = hashlib.sha256(b"dummy").hexdigest()
    delta_xml = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<delta version="1" session_id="{session_id}" serial="{serial}" '
        f'xmlns="http://www.ripe.net/rpki/rrdp">\n'
        f'  <publish uri="{roa_uri}">{roa_b64}</publish>\n'
        f'  <withdraw uri="{withdraw_uri}" hash="{withdraw_hash}"/>\n'
        f'</delta>'
    )
    return delta_xml.encode("utf-8")

def _generate_mft_for_testinput(config: RPKIConfig) -> tuple[bytes, str]:
    from src.rpkiwi.input.utils import compute_sha256 as _sha256
    source_dir = Path(config.ca_source_dir)
    file_list: list[tuple[str, bytes]] = []
    if source_dir.exists():
        for f in sorted(source_dir.iterdir()):
            if not f.is_file():
                continue
            if f.name.endswith(('.key', '-ee.cer')) or f.name == f"{config.ca_name}.cer":
                continue
            if f.name.endswith(('.roa', '.asa', '.crl', '.cer')):
                file_list.append((f.name, _sha256(f.read_bytes())))
    return generate_manifest(config, file_list)

def _generate_cer_for_testinput(config: RPKIConfig) -> bytes:
    from src.rpkiwi.input.builders.ca_cert import generate_child_ca_cert
    ca_cert, ca_key = load_ca_cert_and_key(config.ca_source_cert_path, config.ca_source_key_path)
    data, _ = generate_child_ca_cert(config, ca_cert, ca_key)
    return data

_SEED_GENERATORS: dict[str, object] = {
    "ROA": lambda config: generate_roa(config, prefix="3.0.0.0/24", asn=1000),
    "ASPA": lambda config: generate_aspa(config, customer_asid=1000, providers=((1001, None), (1002, None))),
    "MFT": _generate_mft_for_testinput,
    "CRL": lambda config: (generate_crl(config), None),
    "CER": lambda config: (_generate_cer_for_testinput(config), None),
    "SNAPSHOT": lambda config: (generate_snapshot(config), None),
    "NOTIFICATION": lambda config: (generate_notification(config), None),
    "DELTA": lambda config: (generate_delta(config), None),
}

def generate(object_type: str, config: RPKIConfig) -> "TestInput":
    from src.rpkiwi.input.test_input import TestInput
    from src.rpkiwi.input.ast_node import ASTNode

    otype = object_type.upper()

    if otype in ("SNAPSHOT", "NOTIFICATION", "DELTA"):
        result = _SEED_GENERATORS[otype](config)
        data = result[0] if isinstance(result, tuple) else result
        ti = TestInput.from_bytes(data, otype, source="generator")
        from src.rpkiwi.input.rrdp_ast import parse_rrdp_to_ast
        try:
            ti.metadata["ast"] = parse_rrdp_to_ast(data, otype, config).to_dict()
        except Exception:
            pass
        ti.metadata["can_resign"] = False
        ti.metadata.setdefault("mutate_energy", {})
        return ti

    if otype not in _SEED_GENERATORS:
        raise ValueError(
            f"unknown object type {otype!r}; "
            f"valid: {', '.join(sorted(_SEED_GENERATORS))}"
        )

    result = _SEED_GENERATORS[otype](config)
    if isinstance(result, tuple):
        data, ee_key_pem = result
    else:
        data, ee_key_pem = result, None

    metadata: dict = {"source": "generator"}
    if ee_key_pem:
        metadata["ee_key_pem"] = ee_key_pem
    try:
        ast = ASTNode.from_der(data, otype)
        metadata["ast"] = ast.to_dict()
        metadata["can_resign"] = True
    except Exception:
        pass
    return TestInput(data=data, object_type=otype, format="der", metadata=metadata)

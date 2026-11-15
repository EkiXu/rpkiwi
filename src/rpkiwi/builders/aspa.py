from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterable

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

from src.rpkiwi.config import RPKIConfig, get_config
from src.rpkiwi.builders.ca_cert import load_ca_cert_and_key
from src.rpkiwi.builders.constant import OID_ASPA, OID_SHA256, OID_SHA256_RSA, OID_SIGNED_DATA
from src.rpkiwi.builders.ee_cert import generate_aspa_ee_cert
from src.rpkiwi.input.schema.aspa import ASProviderAttestation
from src.rpkiwi.input.schema.roa import ASID
from src.rpkiwi.utils import compute_sha256

def generate_aspa_content(
    customer_asid: int,
    providers: Iterable[int],
    *,
    with_explicit_version: bool = False,
) -> bytes:
    provider_ids = [ASID(value=asn) for asn in providers]
    kwargs = {
        "customerASID": ASID(value=customer_asid),
        "providers": ASN1SequenceOf(provider_ids),
    }
    if with_explicit_version:
        kwargs["version"] = 1
    aspa = ASProviderAttestation(**kwargs)
    return aspa.der_encode()

def generate_aspa_cms(
    aspa_der: bytes,
    ee_cert: x509.Certificate,
    ee_key: rsa.RSAPrivateKey,
    signing_time: datetime | None = None,
) -> bytes:
    if signing_time is None:
        signing_time = datetime.now(timezone.utc)

    ski_ext = ee_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    ski_bytes = ski_ext.value.digest

    message_digest = compute_sha256(aspa_der)
    signed_attrs_implicit, signed_attrs_for_signing = build_signed_attrs(
        content_type_oid=OID_ASPA,
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
        digestAlgorithm=AlgorithmIdentifier(
            algorithm=OID_SHA256,
            parameters=DER_NULL,
        ),
        signedAttrs=signed_attrs_implicit,
        signatureAlgorithm=AlgorithmIdentifier(
            algorithm=OID_SHA256_RSA,
            parameters=DER_NULL,
        ),
        signature=signature,
        unsignedAttrs=None,
    )

    signed_data = SignedData(
        version=3,
        digestAlgorithms=ASN1SetOf([
            AlgorithmIdentifier(algorithm=OID_SHA256, parameters=DER_NULL)
        ]),
        encapContentInfo=EncapsulatedContentInfo(
            eContentType=OID_ASPA,
            eContent=aspa_der,
        ),
        certificates=certs_encoded,
        crls=None,
        signerInfos=ASN1SetOf([signer_info]),
    )

    content_info = ContentInfo(
        contentType=OID_SIGNED_DATA,
        content=signed_data,
    )
    return content_info.der_encode()

def sign_my_aspa(
    aspa_filename: str,
    aspa_der: bytes,
    customer_asid: int,
    config: RPKIConfig | None = None,
) -> str:
    if config is None:
        config = get_config()

    ca_cert, ca_key = load_ca_cert_and_key(config.ca_source_cert_path, config.ca_source_key_path)
    ee_cert, ee_key = generate_aspa_ee_cert(
        config=config,
        ca_cert=ca_cert,
        ca_key=ca_key,
        aspa_filename=aspa_filename,
        customer_asid=customer_asid,
    )

    ee_path = os.path.join(config.ca_source_dir, f"{aspa_filename}-ee.cer")
    with open(ee_path, "wb") as f:
        f.write(ee_cert.public_bytes(serialization.Encoding.DER))

    aspa_cms = generate_aspa_cms(aspa_der, ee_cert, ee_key)
    aspa_path = os.path.join(config.ca_source_dir, f"{aspa_filename}.asa")
    with open(aspa_path, "wb") as f:
        f.write(aspa_cms)
    return aspa_path

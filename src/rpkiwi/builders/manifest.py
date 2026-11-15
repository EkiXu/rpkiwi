import os
from typing import List
from datetime import datetime, timedelta, timezone
from typing import Tuple
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

from src.rpkiwi.input.asnme.model.cms import ContentInfo, SignedData, EncapsulatedContentInfo, SignerInfo, AlgorithmIdentifier, Attribute, build_signed_attrs
from src.rpkiwi.input.asnme.model.asn import ASN1SetOf
from src.rpkiwi.input.asnme.model.der.encoder import DEREncoder
from src.rpkiwi.input.asnme.model.der.length import encode_tlv
from src.rpkiwi.input.asnme.model.misc import encode_generalized_time, encode_bit_string_with_hash
from src.rpkiwi.input.asnme.model.cms.algorithm_identifier import DER_NULL

from src.rpkiwi.builders.constant import OID_SHA256, OID_SHA256_RSA, OID_MANIFEST, OID_SIGNED_DATA
from src.rpkiwi.builders.ca_cert import load_ca_cert_and_key
from src.rpkiwi.builders.ee_cert import generate_manifest_ee_cert
from src.rpkiwi.utils import compute_sha256

from src.rpkiwi.config import RPKIConfig

def _crl_utc(value: datetime) -> datetime:
    """cryptography<42 exposes naive last_update/next_update; normalize to UTC."""
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def generate_manifest_content(
    manifest_number: int,
    this_update: datetime,
    next_update: datetime,
    file_list: List[Tuple[str, bytes]]
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

    manifest_content = (
        manifest_num_der +
        this_update_der +
        next_update_der +
        file_hash_alg_der +
        file_list_der
    )

    return encode_tlv(SEQUENCE_TAG.encode(), manifest_content)

def generate_manifest_cms(
    manifest_der: bytes,
    ee_cert: x509.Certificate,
    ee_key: rsa.RSAPrivateKey,
    signing_time: datetime
) -> bytes:
    ski_ext = ee_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    ski_bytes = ski_ext.value.digest

    message_digest = compute_sha256(manifest_der)

    signed_attrs_implicit, signed_attrs_for_signing = build_signed_attrs(
        content_type_oid=OID_MANIFEST,
        signing_time=signing_time,
        message_digest=message_digest
    )

    signature = ee_key.sign(
        signed_attrs_for_signing,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    ee_cert_der = ee_cert.public_bytes(serialization.Encoding.DER)

    certs_content = ee_cert_der
    certs_length = len(certs_content)
    if certs_length < 128:
        certs_encoded = bytes([0xA0, certs_length]) + certs_content
    else:
        length_bytes = certs_length.to_bytes((certs_length.bit_length() + 7) // 8, 'big')
        certs_encoded = bytes([0xA0, 0x80 | len(length_bytes)]) + length_bytes + certs_content

    signer_info = SignerInfo(
        version=3,
        sid=ski_bytes,
        digestAlgorithm=AlgorithmIdentifier(
            algorithm=OID_SHA256,
            parameters=DER_NULL
        ),
        signedAttrs=signed_attrs_implicit,
        signatureAlgorithm=AlgorithmIdentifier(
            algorithm=OID_SHA256_RSA,
            parameters=DER_NULL
        ),
        signature=signature,
        unsignedAttrs=None
    )

    signed_data = SignedData(
        version=3,
        digestAlgorithms=ASN1SetOf([
            AlgorithmIdentifier(algorithm=OID_SHA256, parameters=DER_NULL)
        ]),
        encapContentInfo=EncapsulatedContentInfo(
            eContentType=OID_MANIFEST,
            eContent=manifest_der
        ),
        certificates=certs_encoded,
        crls=None,
        signerInfos=ASN1SetOf([signer_info])
    )

    content_info = ContentInfo(
        contentType=OID_SIGNED_DATA,
        content=signed_data
    )

    return content_info.der_encode()

def update_ca_manifest(config: RPKIConfig, verbose: bool = True, manifest_content_modifier=None, manifest_number: int | None = None) -> str:
    ca_pub_dir = config.ca_publish_dir

    manifest_files = []

    crl_pub_path = config.ca_publish_crl_path
    if os.path.exists(crl_pub_path):
        crl_name = os.path.basename(crl_pub_path)
        file_hash = compute_sha256(open(crl_pub_path, 'rb').read())
        manifest_files.append((crl_name, file_hash))

    if os.path.exists(ca_pub_dir):
        for fname in os.listdir(ca_pub_dir):
            if fname.endswith('.roa') or fname.endswith('.asa') or fname.endswith('.cer'):
                if fname == f"{config.ca_name}.cer":
                    continue
                fpath = os.path.join(ca_pub_dir, fname)
                if os.path.isfile(fpath):
                    file_hash = compute_sha256(open(fpath, 'rb').read())
                    manifest_files.append((fname, file_hash))

    manifest_files.sort(key=lambda x: x[0])

    if verbose:
        print(f"  Manifest will include {len(manifest_files)} files:")
        for fname, fhash in manifest_files:
            print(f"    - {fname}: {fhash.hex()[:16]}...")

    ca_cert, ca_key = load_ca_cert_and_key(config.ca_source_cert_path, config.ca_source_key_path)

    crl_pub_path = config.ca_publish_crl_path
    if os.path.exists(crl_pub_path):
        crl = x509.load_der_x509_crl(open(crl_pub_path, 'rb').read())
        this_update = _crl_utc(getattr(crl, 'last_update_utc', None) or crl.last_update).replace(microsecond=0)
        next_update = _crl_utc(getattr(crl, 'next_update_utc', None) or crl.next_update).replace(microsecond=0)
    else:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        this_update = now
        next_update = now + timedelta(days=1)

    manifest_number = manifest_number or int(time.time())
    ee_cert, ee_key = generate_manifest_ee_cert(
        config=config,
        ca_cert=ca_cert,
        ca_key=ca_key,
        serial=manifest_number,
        not_before=this_update,
        not_after=next_update
    )

    manifest_der = generate_manifest_content(
        manifest_number=manifest_number,
        this_update=this_update,
        next_update=next_update,
        file_list=manifest_files
    )

    if manifest_content_modifier is not None:
        if verbose:
            print(f"  Applying pre-signing manifest content modification...")
        manifest_der = manifest_content_modifier(manifest_der)

    manifest_cms = generate_manifest_cms(
        manifest_der=manifest_der,
        ee_cert=ee_cert,
        ee_key=ee_key,
        signing_time=this_update
    )

    manifest_path = config.ca_source_mft_path
    with open(manifest_path, 'wb') as f:
        f.write(manifest_cms)

    ee_path = manifest_path.replace('.mft', '-ee.cer')
    with open(ee_path, 'wb') as f:
        f.write(ee_cert.public_bytes(serialization.Encoding.DER))

    if verbose:
        print(f"  Manifest saved: {manifest_path}")
        print(f"  Manifest EE cert: {ee_path}")
        print(f"  Manifest number: {manifest_number}")

    return manifest_path

def update_ta_manifest(config: RPKIConfig, verbose: bool = True) -> str:
    ta_pub_dir = config.ta_publish_dir

    manifest_files = []

    crl_path = config.ta_publish_crl_path
    if os.path.exists(crl_path):
        crl_name = os.path.basename(crl_path)
        file_hash = compute_sha256(open(crl_path, 'rb').read())
        manifest_files.append((crl_name, file_hash))

    ta_cert_name = os.path.basename(config.ta_publish_cert_path)
    for fname in sorted(os.listdir(ta_pub_dir)):
        if fname.endswith('.cer') and fname != ta_cert_name:
            fpath = os.path.join(ta_pub_dir, fname)
            if os.path.isfile(fpath):
                file_hash = compute_sha256(open(fpath, 'rb').read())
                manifest_files.append((fname, file_hash))

    manifest_files.sort(key=lambda x: x[0])

    if verbose:
        print(f"  TA Manifest will include {len(manifest_files)} files:")
        for fname, fhash in manifest_files:
            print(f"    - {fname}: {fhash.hex()[:16]}...")

    ta_cert, ta_key = load_ca_cert_and_key(config.ta_source_cert_path, config.ta_source_key_path)

    ta_crl_pub_path = config.ta_publish_crl_path
    if os.path.exists(ta_crl_pub_path):
        crl = x509.load_der_x509_crl(open(ta_crl_pub_path, 'rb').read())
        this_update = _crl_utc(getattr(crl, 'last_update_utc', None) or crl.last_update).replace(microsecond=0)
        next_update = _crl_utc(getattr(crl, 'next_update_utc', None) or crl.next_update).replace(microsecond=0)
    else:
        now = datetime.now(timezone.utc).replace(microsecond=0)
        this_update = now
        next_update = now + timedelta(days=1)

    manifest_number = int(time.time())
    ee_cert, ee_key = generate_manifest_ee_cert(
        config=config,
        ca_cert=ta_cert,
        ca_key=ta_key,
        serial=manifest_number,
        is_ta=True,
        not_before=this_update,
        not_after=next_update
    )

    manifest_der = generate_manifest_content(
        manifest_number=manifest_number,
        this_update=this_update,
        next_update=next_update,
        file_list=manifest_files
    )

    manifest_cms = generate_manifest_cms(
        manifest_der=manifest_der,
        ee_cert=ee_cert,
        ee_key=ee_key,
        signing_time=this_update
    )

    manifest_src_path = config.ta_source_mft_path
    os.makedirs(os.path.dirname(manifest_src_path), exist_ok=True)
    with open(manifest_src_path, 'wb') as f:
        f.write(manifest_cms)

    manifest_pub_path = config.ta_publish_mft_path
    os.makedirs(os.path.dirname(manifest_pub_path), exist_ok=True)
    import shutil
    shutil.copy2(manifest_src_path, manifest_pub_path)

    ee_src_path = manifest_src_path.replace('.mft', '-ee.cer')
    with open(ee_src_path, 'wb') as f:
        f.write(ee_cert.public_bytes(serialization.Encoding.DER))

    if verbose:
        print(f"  TA Manifest saved: {manifest_pub_path}")
        print(f"  TA Manifest EE cert: {ee_src_path}")
        print(f"  TA Manifest number: {manifest_number}")

    return manifest_pub_path

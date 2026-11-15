import os
from datetime import datetime, timedelta, timezone
from typing import Iterable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

from src.rpkiwi.config import RPKIConfig
from src.rpkiwi.builders.ca_cert import load_ca_cert_and_key

def generate_crl(
    cert: x509.Certificate,
    key,
    output_path: str,
    crl_number: int = 3,
    validity_days: int = 7,
    revoked_serials: Iterable[int] | None = None,
    issuer_name: x509.Name | None = None,
    authority_key_identifier: bytes | None = None,
) -> bytes:
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer_name or cert.subject)

    now = datetime.now(timezone.utc).replace(microsecond=0)
    builder = builder.last_update(now)
    builder = builder.next_update(now + timedelta(days=validity_days))

    builder = builder.add_extension(x509.CRLNumber(crl_number), critical=False)

    if authority_key_identifier is not None:
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=authority_key_identifier,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        )
    else:
        try:
            ca_ski = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
            aki = x509.AuthorityKeyIdentifier(
                key_identifier=ca_ski.value.digest,
                authority_cert_issuer=None,
                authority_cert_serial_number=None,
            )
        except x509.ExtensionNotFound:
            aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(cert.public_key())
    builder = builder.add_extension(aki, critical=False)

    for serial in revoked_serials or ():
        revoked = (
            x509.RevokedCertificateBuilder()
            .serial_number(int(serial))
            .revocation_date(now)
            .build()
        )
        builder = builder.add_revoked_certificate(revoked)

    crl = builder.sign(key, hashes.SHA256())
    crl_der = crl.public_bytes(serialization.Encoding.DER)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(crl_der)

    return crl_der

def regenerate_crls(config: RPKIConfig, verbose: bool = True):
    import shutil

    ta_cert, ta_key = load_ca_cert_and_key(config.ta_source_cert_path, config.ta_source_key_path)
    ta_crl_src = config.ta_source_crl_path
    generate_crl(ta_cert, ta_key, ta_crl_src)
    shutil.copy2(ta_crl_src, config.ta_publish_crl_path)
    if verbose:
        print(f"  TA CRL: {ta_crl_src}")

    ca_cert, ca_key = load_ca_cert_and_key(config.ca_source_cert_path, config.ca_source_key_path)
    ca_crl_src = config.ca_source_crl_path
    generate_crl(ca_cert, ca_key, ca_crl_src)
    shutil.copy2(ca_crl_src, config.ca_publish_crl_path)
    if verbose:
        print(f"  CA CRL: {ca_crl_src}")

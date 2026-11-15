from typing import Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from src.rpkiwi.config import RPKIConfig
from src.rpkiwi.input.builders import (
    OID_RPKI_POLICY, OID_AD_CA_ISSUERS, OID_IP_RESOURCES, OID_AS_RESOURCES,
)

def load_ca_cert_and_key(ca_source_cert_path: str, ca_source_key_path: str) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    with open(ca_source_cert_path, 'rb') as f:
        ca_cert = x509.load_der_x509_certificate(f.read())

    with open(ca_source_key_path, 'rb') as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    return ca_cert, ca_key

def generate_child_ca_cert(
    config: RPKIConfig,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    *,
    subject: str = "child-ca",
    notify_uri: str | None = None,
    ca_repository: str | None = None,
    manifest_uri: str | None = None,
    validity_days: int = 30,
) -> Tuple[bytes, rsa.RSAPrivateKey]:
    from datetime import datetime, timedelta, timezone
    from src.rpkiwi.input.asnme.model.misc import (
        encode_ip_resources_inherit, encode_as_resources_inherit,
    )
    import time

    if notify_uri is None:
        notify_uri = config.ca_sia_notify_uri
    if ca_repository is None:
        ca_repository = config.ca_sia_repo_uri
    if manifest_uri is None:
        manifest_uri = f"rsync://{config.ca_base_domain}/{config.ca_repo_base_path}/{subject}.mft"

    child_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    serial = int(time.time()) % 1000000

    parent_ski = ca_cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier
    ).value.digest

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    )
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(child_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(now)
    builder = builder.not_valid_after(now + timedelta(days=validity_days))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )
    builder = builder.add_extension(
        x509.SubjectKeyIdentifier.from_public_key(child_key.public_key()),
        critical=False,
    )
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier(
            key_identifier=parent_ski,
            authority_cert_issuer=None,
            authority_cert_serial_number=None,
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=False, key_encipherment=False,
            content_commitment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True,
            encipher_only=False, decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(
                policy_identifier=ObjectIdentifier(OID_RPKI_POLICY),
                policy_qualifiers=None,
            )
        ]),
        critical=True,
    )

    OID_AD_CA_REPO = "1.3.6.1.5.5.7.48.5"
    OID_AD_RPKI_MANIFEST = "1.3.6.1.5.5.7.48.10"
    OID_AD_RPKI_NOTIFY = "1.3.6.1.5.5.7.48.13"

    sia_descriptions = [
        x509.AccessDescription(
            access_method=ObjectIdentifier(OID_AD_CA_REPO),
            access_location=x509.UniformResourceIdentifier(ca_repository),
        ),
        x509.AccessDescription(
            access_method=ObjectIdentifier(OID_AD_RPKI_MANIFEST),
            access_location=x509.UniformResourceIdentifier(manifest_uri),
        ),
        x509.AccessDescription(
            access_method=ObjectIdentifier(OID_AD_RPKI_NOTIFY),
            access_location=x509.UniformResourceIdentifier(notify_uri),
        ),
    ]
    builder = builder.add_extension(
        x509.SubjectInformationAccess(sia_descriptions), critical=False,
    )
    builder = builder.add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(config.ca_crl_uri)],
                relative_name=None, reasons=None, crl_issuer=None,
            )
        ]),
        critical=False,
    )
    builder = builder.add_extension(
        x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=ObjectIdentifier(OID_AD_CA_ISSUERS),
                access_location=x509.UniformResourceIdentifier(config.ca_cert_uri),
            )
        ]),
        critical=False,
    )
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            oid=ObjectIdentifier(OID_IP_RESOURCES),
            value=encode_ip_resources_inherit(),
        ),
        critical=True,
    )
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            oid=ObjectIdentifier(OID_AS_RESOURCES),
            value=encode_as_resources_inherit(),
        ),
        critical=True,
    )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER), child_key

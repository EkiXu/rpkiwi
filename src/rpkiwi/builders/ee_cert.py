from datetime import datetime, timedelta, timezone
from typing import Tuple, Optional, List
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier

from src.rpkiwi.input.asnme.model.misc import encode_ip_resources_inherit, encode_as_resources_inherit, encode_ip_resources_explicit, encode_as_resources_explicit

from src.rpkiwi.config import RPKIConfig
from src.rpkiwi.builders.constant import OID_RPKI_POLICY, OID_AD_SIGNED_OBJECT, OID_AD_CA_ISSUERS, OID_IP_RESOURCES, OID_AS_RESOURCES

def generate_manifest_ee_cert(
    config: RPKIConfig,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    serial: int = None,
    validity_days: int = 7,
    is_ta: bool = False,
    not_before: datetime = None,
    not_after: datetime = None
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    ee_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    if serial is None:
        serial = int(time.time()) % 1000000

    if not_before is None:
        not_before = datetime.now(timezone.utc)
    if not_after is None:
        not_after = not_before + timedelta(days=validity_days)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "RPKI-EE-manifest")
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(ee_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    ski = x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    try:
        ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=ca_ski.value.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        )
    except x509.ExtensionNotFound:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    builder = builder.add_extension(aki, critical=False)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    builder = builder.add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(
                policy_identifier=ObjectIdentifier(OID_RPKI_POLICY),
                policy_qualifiers=None
            )
        ]),
        critical=True
    )

    if is_ta:
        manifest_uri = config.ta_sia_manifest_uri
    else:
        manifest_uri = config.ca_sia_manifest_uri

    builder = builder.add_extension(
        x509.SubjectInformationAccess([
            x509.AccessDescription(
                access_method=ObjectIdentifier(OID_AD_SIGNED_OBJECT),
                access_location=x509.UniformResourceIdentifier(manifest_uri)
            )
        ]),
        critical=False
    )

    if is_ta:
        crl_uri = f"rsync://{config.base_domain}/ta/ta.crl"
    else:
        crl_uri = config.ca_crl_uri
    builder = builder.add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_uri)],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            )
        ]),
        critical=False
    )

    if is_ta:
        issuer_cert_uri = config.ta_cert_uri
    else:
        issuer_cert_uri = config.ca_cert_uri
    builder = builder.add_extension(
        x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=ObjectIdentifier(OID_AD_CA_ISSUERS),
                access_location=x509.UniformResourceIdentifier(issuer_cert_uri)
            )
        ]),
        critical=False
    )

    ip_resources_ext = encode_ip_resources_inherit()
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            oid=ObjectIdentifier(OID_IP_RESOURCES),
            value=ip_resources_ext
        ),
        critical=True
    )

    as_resources_ext = encode_as_resources_inherit()
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            oid=ObjectIdentifier(OID_AS_RESOURCES),
            value=as_resources_ext
        ),
        critical=True
    )

    ee_cert = builder.sign(ca_key, hashes.SHA256())

    return ee_cert, ee_key

def generate_ee_cert(
    config: RPKIConfig,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    roa_filename: str,
    serial: int = None,
    validity_days: int = 7,
    ipv4_prefixes: Optional[List[str]] = None,
    ipv6_prefixes: Optional[List[str]] = None,
    cert_policy_oid: Optional[str] = None,
    ip_resources_oid: Optional[str] = None,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    ee_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    if serial is None:
        serial = int(time.time()) % 1000000

    now = datetime.now(timezone.utc)
    not_before = now
    not_after = now + timedelta(days=validity_days)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "RPKI-EE-roa")
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(ee_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    ski = x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    try:
        ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=ca_ski.value.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        )
    except x509.ExtensionNotFound:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    builder = builder.add_extension(aki, critical=False)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    policy_oid = cert_policy_oid or OID_RPKI_POLICY
    builder = builder.add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(
                policy_identifier=ObjectIdentifier(policy_oid),
                policy_qualifiers=None
            )
        ]),
        critical=True
    )

    roa_uri = f"rsync://{config.ca_base_domain}/{config.ca_repo_base_path}/{roa_filename}.roa"

    builder = builder.add_extension(
        x509.SubjectInformationAccess([
            x509.AccessDescription(
                access_method=ObjectIdentifier(OID_AD_SIGNED_OBJECT),
                access_location=x509.UniformResourceIdentifier(roa_uri)
            )
        ]),
        critical=False
    )

    crl_uri = config.ca_crl_uri
    builder = builder.add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_uri)],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            )
        ]),
        critical=False
    )

    builder = builder.add_extension(
        x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=ObjectIdentifier(OID_AD_CA_ISSUERS),
                access_location=x509.UniformResourceIdentifier(config.ca_cert_uri)
            )
        ]),
        critical=False
    )

    ip_ext_oid = ip_resources_oid or OID_IP_RESOURCES
    if ipv4_prefixes is not None or ipv6_prefixes is not None:
        ip_resources_ext = encode_ip_resources_explicit(ipv4_prefixes, ipv6_prefixes)
    else:
        ip_resources_ext = encode_ip_resources_inherit()
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            oid=ObjectIdentifier(ip_ext_oid),
            value=ip_resources_ext
        ),
        critical=True
    )

    ee_cert = builder.sign(ca_key, hashes.SHA256())

    return ee_cert, ee_key

def generate_aspa_ee_cert(
    config: RPKIConfig,
    ca_cert: x509.Certificate,
    ca_key: rsa.RSAPrivateKey,
    aspa_filename: str,
    customer_asid: int,
    serial: int = None,
    validity_days: int = 7,
) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
    ee_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    if serial is None:
        serial = int(time.time()) % 1000000

    now = datetime.now(timezone.utc)
    not_before = now
    not_after = now + timedelta(days=validity_days)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "RPKI-EE-aspa")
    ])

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(ee_key.public_key())
    builder = builder.serial_number(serial)
    builder = builder.not_valid_before(not_before)
    builder = builder.not_valid_after(not_after)

    ski = x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key())
    builder = builder.add_extension(ski, critical=False)

    try:
        ca_ski = ca_cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        aki = x509.AuthorityKeyIdentifier(
            key_identifier=ca_ski.value.digest,
            authority_cert_issuer=None,
            authority_cert_serial_number=None
        )
    except x509.ExtensionNotFound:
        aki = x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key())
    builder = builder.add_extension(aki, critical=False)

    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True
    )

    builder = builder.add_extension(
        x509.CertificatePolicies([
            x509.PolicyInformation(
                policy_identifier=ObjectIdentifier(OID_RPKI_POLICY),
                policy_qualifiers=None
            )
        ]),
        critical=True
    )

    aspa_uri = f"rsync://{config.ca_base_domain}/{config.ca_repo_base_path}/{aspa_filename}.asa"

    builder = builder.add_extension(
        x509.SubjectInformationAccess([
            x509.AccessDescription(
                access_method=ObjectIdentifier(OID_AD_SIGNED_OBJECT),
                access_location=x509.UniformResourceIdentifier(aspa_uri)
            )
        ]),
        critical=False
    )

    crl_uri = config.ca_crl_uri
    builder = builder.add_extension(
        x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(crl_uri)],
                relative_name=None,
                reasons=None,
                crl_issuer=None
            )
        ]),
        critical=False
    )

    builder = builder.add_extension(
        x509.AuthorityInformationAccess([
            x509.AccessDescription(
                access_method=ObjectIdentifier(OID_AD_CA_ISSUERS),
                access_location=x509.UniformResourceIdentifier(config.ca_cert_uri)
            )
        ]),
        critical=False
    )

    as_resources_ext = encode_as_resources_explicit(customer_asid)
    builder = builder.add_extension(
        x509.UnrecognizedExtension(
            oid=ObjectIdentifier(OID_AS_RESOURCES),
            value=as_resources_ext
        ),
        critical=True
    )

    ee_cert = builder.sign(ca_key, hashes.SHA256())

    return ee_cert, ee_key

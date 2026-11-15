from typing import Tuple
from datetime import datetime

OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

from ..asn import ASN1SetOf
from ..misc import encode_utc_time
from ..der.encoder import DEREncoder

from .attribute import Attribute

def build_signed_attrs(content_type_oid: str, signing_time: datetime, message_digest: bytes) -> Tuple[bytes, bytes]:
    content_type_attr = Attribute(
        attrType=OID_CONTENT_TYPE,
        attrValues=ASN1SetOf([DEREncoder.encode_object_identifier(content_type_oid)])
    )

    signing_time_value = encode_utc_time(signing_time)
    signing_time_attr = Attribute(
        attrType=OID_SIGNING_TIME,
        attrValues=ASN1SetOf([signing_time_value])
    )

    message_digest_attr = Attribute(
        attrType=OID_MESSAGE_DIGEST,
        attrValues=ASN1SetOf([DEREncoder.encode_octet_string(message_digest)])
    )

    attrs_list = ASN1SetOf([content_type_attr, signing_time_attr, message_digest_attr])
    attrs_der = attrs_list.der_encode()

    attrs_implicit = bytes([0xA0]) + attrs_der[1:]

    attrs_for_signing = attrs_der

    return attrs_implicit, attrs_for_signing

def encode_signed_attrs_for_signing(signed_attrs_der: bytes) -> bytes:
    return bytes([0x31]) + signed_attrs_der[1:]

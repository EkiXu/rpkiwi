from typing import Optional, List, TypeAlias
from ..asn import (
    ASN1Object,
    ASN1Field,
    ASN1Type,
    ASN1Tag,
    ASN1SetOf,
    ASN1SequenceOf,
    ASN1OctetString,
)

class ContentInfo(ASN1Object):

    _asn1_def = 'SEQUENCE'

    contentType = ASN1Field(ASN1Type.OBJECT_IDENTIFIER)
    content = ASN1Field(ASN1Type.ANY, tag=ASN1Tag(number=0, explicit=True))

class EncapsulatedContentInfo(ASN1Object):

    _asn1_def = 'SEQUENCE'

    eContentType = ASN1Field(ASN1Type.OBJECT_IDENTIFIER)
    eContent = ASN1Field(ASN1Type.OCTET_STRING, optional=True, tag=ASN1Tag(number=0, explicit=True))

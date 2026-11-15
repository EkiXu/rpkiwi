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

SignerInfos: TypeAlias = ASN1SetOf['SignerInfo']

class SignerInfo(ASN1Object):

    _asn1_def = 'SEQUENCE'

    version = ASN1Field(ASN1Type.INTEGER)
    sid = ASN1Field(ASN1Type.OCTET_STRING, tag=ASN1Tag(number=0, implicit=True))
    digestAlgorithm = ASN1Field('AlgorithmIdentifier')
    signedAttrs = ASN1Field(ASN1Type.ANY, optional=True)
    signatureAlgorithm = ASN1Field('AlgorithmIdentifier')
    signature = ASN1Field(ASN1Type.OCTET_STRING)
    unsignedAttrs = ASN1Field(ASN1Type.ANY, optional=True)

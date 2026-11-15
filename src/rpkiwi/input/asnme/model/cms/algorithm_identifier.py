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

DigestAlgorithmIdentifiers: TypeAlias = ASN1SetOf['AlgorithmIdentifier']

DER_NULL = b'\x05\x00'

class AlgorithmIdentifier(ASN1Object):

    _asn1_def = 'SEQUENCE'

    algorithm = ASN1Field(ASN1Type.OBJECT_IDENTIFIER)
    parameters = ASN1Field(ASN1Type.ANY, optional=True)

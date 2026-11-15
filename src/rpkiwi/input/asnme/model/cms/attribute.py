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

class Attribute(ASN1Object):

    _asn1_def = 'SEQUENCE'

    attrType = ASN1Field(ASN1Type.OBJECT_IDENTIFIER)
    attrValues = ASN1Field('AttributeValues')

AttributeValues: TypeAlias = ASN1SetOf[ASN1OctetString]
AttributeSet: TypeAlias = ASN1SetOf['Attribute']

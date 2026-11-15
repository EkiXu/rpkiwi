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

class SignedData(ASN1Object):

    _asn1_def = 'SEQUENCE'

    version = ASN1Field(ASN1Type.INTEGER)
    digestAlgorithms = ASN1Field('DigestAlgorithmIdentifiers')
    encapContentInfo = ASN1Field('EncapsulatedContentInfo')
    certificates = ASN1Field(ASN1Type.ANY, optional=True)
    crls = ASN1Field(ASN1Type.ANY, optional=True)
    signerInfos = ASN1Field('SignerInfos')

CertificateSet: TypeAlias = ASN1SequenceOf[ASN1OctetString]

RevocationInfoChoices: TypeAlias = ASN1SetOf[ASN1OctetString]

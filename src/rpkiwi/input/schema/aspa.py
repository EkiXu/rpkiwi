from src.rpkiwi.input.asnme.model.asn import (
    ASN1Object,
    ASN1Field,
    ASN1Type,
    ASN1Tag,
)
from src.rpkiwi.input.schema.roa import ASID

class ProviderAS(ASN1Object):
    _asn1_def = 'SEQUENCE'

    providerASID = ASN1Field('ASID')
    afiLimit = ASN1Field(ASN1Type.OCTET_STRING, tag=ASN1Tag(number=0, implicit=True), optional=True)

class ASProviderAttestation(ASN1Object):
    _asn1_def = 'SEQUENCE'

    version = ASN1Field(ASN1Type.INTEGER, tag=ASN1Tag(number=0, explicit=True), optional=True)
    customerASID = ASN1Field('ASID')
    providers = ASN1Field(ASN1Type.SEQUENCE_OF)

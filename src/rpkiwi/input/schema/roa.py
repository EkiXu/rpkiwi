from typing import Optional, List, TypeAlias
from src.rpkiwi.input.asnme.model.asn import (
    ASN1Object,
    ASN1Field,
    ASN1Type,
    ASN1Tag,
    ASN1SetOf,
    ASN1SequenceOf,
)

class RouteOriginAttestation(ASN1Object):
    _asn1_def = 'SEQUENCE'

    version = ASN1Field(ASN1Type.INTEGER, tag=ASN1Tag(number=0, explicit=True), optional=True, default=0)
    asID = ASN1Field('ASID')
    ipAddrBlocks = ASN1Field(ASN1Type.SEQUENCE_OF)

class ASID(ASN1Object):
    _asn1_def = 'INTEGER'

    def __init__(self, value: int = 0):
        super().__init__()
        self._value = value

    def der_encode(self) -> bytes:
        from src.rpkiwi.input.asnme.model.der.encoder import DEREncoder
        return DEREncoder.encode_integer(self._value)

class ROAIPAddressFamily(ASN1Object):
    _asn1_def = 'SEQUENCE'

    addressFamily = ASN1Field(ASN1Type.OCTET_STRING)
    addresses = ASN1Field(ASN1Type.SEQUENCE_OF)

class ROAIPAddress(ASN1Object):
    _asn1_def = 'SEQUENCE'

    address = ASN1Field('IPAddress')
    maxLength = ASN1Field(ASN1Type.INTEGER, optional=True)

class IPAddress(ASN1Object):
    _asn1_def = 'BIT_STRING'

    def __init__(self, value: bytes = b'\x00'):
        super().__init__()
        self._value = value

    def der_encode(self) -> bytes:
        from src.rpkiwi.input.asnme.model.der.encoder import DEREncoder
        if len(self._value) >= 1:
            unused_bits = self._value[0]
            ip_bytes = self._value[1:]
            return DEREncoder.encode_bit_string(ip_bytes, unused_bits=unused_bits)
        else:
            return DEREncoder.encode_bit_string(b'', unused_bits=0)

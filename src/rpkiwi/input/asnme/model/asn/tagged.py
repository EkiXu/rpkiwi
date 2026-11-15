from ..der import Tag, context_tag, application_tag, DEREncoder, encode_tlv
from .types import ASN1Type

class ASN1TaggedImplicit(ASN1Type):

    def __init__(
        self,
        tag_number: int,
        value: ASN1Type,
        tag_class: type = None
    ):
        if not isinstance(value, ASN1Type):
            raise TypeError("Value must be an ASN1Type")

        self.tag_number = tag_number
        self.value = value
        self.tag_class = tag_class

        encoded_value = value.der_encode()
        is_constructed = bool(encoded_value[0] & 0x20)

        if tag_class is None:
            self._tag = context_tag(tag_number, is_constructed)
        else:
            self._tag = Tag(tag_class, is_constructed, tag_number)

        super().__init__(self._tag)

    def der_encode(self) -> bytes:
        encoded_value = self.value.der_encode()

        offset = 0

        if encoded_value[offset] & 0x1F == 0x1F:
            offset += 1
            while offset < len(encoded_value) and encoded_value[offset] & 0x80:
                offset += 1
            offset += 1
        else:
            offset += 1

        length_byte = encoded_value[offset]
        offset += 1
        if length_byte & 0x80:
            num_octets = length_byte & 0x7F
            offset += num_octets

        content = encoded_value[offset:]

        return encode_tlv(self._tag.encode(), content)

    def __repr__(self) -> str:
        return f"ASN1TaggedImplicit([{self.tag_number}], {self.value!r})"

class ASN1TaggedExplicit(ASN1Type):

    def __init__(
        self,
        tag_number: int,
        value: ASN1Type,
        tag_class: type = None
    ):
        if not isinstance(value, ASN1Type):
            raise TypeError("Value must be an ASN1Type")

        self.tag_number = tag_number
        self.value = value
        self.tag_class = tag_class

        if tag_class is None:
            self._tag = context_tag(tag_number, constructed=True)
        else:
            self._tag = Tag(tag_class, True, tag_number)

        super().__init__(self._tag)

    def der_encode(self) -> bytes:
        content = self.value.der_encode()
        return encode_tlv(self._tag.encode(), content)

    def __repr__(self) -> str:
        return f"ASN1TaggedExplicit([{self.tag_number}], {self.value!r})"

def implicit(tag_number: int, value: ASN1Type) -> ASN1TaggedImplicit:
    return ASN1TaggedImplicit(tag_number, value)

def explicit(tag_number: int, value: ASN1Type) -> ASN1TaggedExplicit:
    return ASN1TaggedExplicit(tag_number, value)

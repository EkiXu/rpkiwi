from enum import IntEnum
from typing import NamedTuple

class TagClass(IntEnum):
    UNIVERSAL = 0x00
    APPLICATION = 0x40
    CONTEXT = 0x80
    PRIVATE = 0xC0

class TagForm(IntEnum):
    PRIMITIVE = 0x00
    CONSTRUCTED = 0x20

class UniversalTag(IntEnum):
    BOOLEAN = 0x01
    INTEGER = 0x02
    BIT_STRING = 0x03
    OCTET_STRING = 0x04
    NULL = 0x05
    OBJECT_IDENTIFIER = 0x06
    OBJECT_DESCRIPTOR = 0x07
    EXTERNAL = 0x08
    REAL = 0x09
    ENUMERATED = 0x0A
    EMBEDDED_PDV = 0x0B
    UTF8_STRING = 0x0C
    RELATIVE_OID = 0x0D
    SEQUENCE = 0x10
    SET = 0x11
    NUMERIC_STRING = 0x12
    PRINTABLE_STRING = 0x13
    T61_STRING = 0x14
    VIDEOTEX_STRING = 0x15
    IA5_STRING = 0x16
    UTC_TIME = 0x17
    GENERALIZED_TIME = 0x18
    GRAPHIC_STRING = 0x19
    VISIBLE_STRING = 0x1A
    GENERAL_STRING = 0x1B
    UNIVERSAL_STRING = 0x1C
    CHARACTER_STRING = 0x1D
    BMP_STRING = 0x1E

class Tag(NamedTuple):
    tag_class: TagClass
    constructed: bool
    number: int

    def encode(self) -> bytes:
        form = TagForm.CONSTRUCTED if self.constructed else TagForm.PRIMITIVE

        if self.number < 31:
            return bytes([self.tag_class | form | self.number])

        first_byte = self.tag_class | form | 0x1F

        number_bytes = []
        n = self.number

        while n > 0:
            number_bytes.insert(0, n & 0x7F)
            n >>= 7

        for i in range(len(number_bytes) - 1):
            number_bytes[i] |= 0x80

        return bytes([first_byte] + number_bytes)

    @classmethod
    def decode(cls, data: bytes, offset: int = 0) -> tuple['Tag', int]:
        if offset >= len(data):
            raise ValueError("Unexpected end of data while decoding tag")

        first_byte = data[offset]
        offset += 1

        tag_class = TagClass(first_byte & 0xC0)
        constructed = bool(first_byte & TagForm.CONSTRUCTED)
        number = first_byte & 0x1F

        if number == 0x1F:
            number = 0
            while offset < len(data):
                byte = data[offset]
                offset += 1
                number = (number << 7) | (byte & 0x7F)
                if not (byte & 0x80):
                    break
            else:
                raise ValueError("Unexpected end of data in long-form tag")

        return cls(tag_class, constructed, number), offset

BOOLEAN_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.BOOLEAN)
INTEGER_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.INTEGER)
BIT_STRING_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.BIT_STRING)
OCTET_STRING_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.OCTET_STRING)
NULL_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.NULL)
OID_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.OBJECT_IDENTIFIER)
SEQUENCE_TAG = Tag(TagClass.UNIVERSAL, True, UniversalTag.SEQUENCE)
SET_TAG = Tag(TagClass.UNIVERSAL, True, UniversalTag.SET)
PRINTABLE_STRING_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.PRINTABLE_STRING)
UTF8_STRING_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.UTF8_STRING)
IA5_STRING_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.IA5_STRING)
UTC_TIME_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.UTC_TIME)
GENERALIZED_TIME_TAG = Tag(TagClass.UNIVERSAL, False, UniversalTag.GENERALIZED_TIME)

def context_tag(number: int, constructed: bool = True) -> Tag:
    return Tag(TagClass.CONTEXT, constructed, number)

def application_tag(number: int, constructed: bool = True) -> Tag:
    return Tag(TagClass.APPLICATION, constructed, number)

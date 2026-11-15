from typing import Protocol, runtime_checkable
from .tags import Tag
from .length import encode_length, encode_tlv

@runtime_checkable
class DEREncodable(Protocol):
    def der_encode(self) -> bytes:
        ...

class DEREncoder:

    @staticmethod
    def encode_boolean(value: bool, tag: Tag | None = None) -> bytes:
        from .tags import BOOLEAN_TAG
        tag_bytes = (tag or BOOLEAN_TAG).encode()
        content = b'\xff' if value else b'\x00'
        return encode_tlv(tag_bytes, content)

    @staticmethod
    def encode_integer(value: int, tag: Tag | None = None) -> bytes:
        from .tags import INTEGER_TAG
        tag_bytes = (tag or INTEGER_TAG).encode()

        if value == 0:
            return encode_tlv(tag_bytes, b'\x00')

        if value < 0:
            bit_length = value.bit_length() + 1
            byte_length = (bit_length + 7) // 8
            content = value.to_bytes(byte_length, 'big', signed=True)
        else:
            byte_length = (value.bit_length() + 7) // 8
            content = value.to_bytes(byte_length, 'big')
            if content[0] & 0x80:
                content = b'\x00' + content

        return encode_tlv(tag_bytes, content)

    @staticmethod
    def encode_octet_string(value: bytes, tag: Tag | None = None) -> bytes:
        from .tags import OCTET_STRING_TAG
        tag_bytes = (tag or OCTET_STRING_TAG).encode()
        return encode_tlv(tag_bytes, value)

    @staticmethod
    def encode_bit_string(
        value: bytes,
        unused_bits: int = 0,
        tag: Tag | None = None
    ) -> bytes:
        from .tags import BIT_STRING_TAG

        if not 0 <= unused_bits <= 7:
            raise ValueError(f"unused_bits must be 0-7, got {unused_bits}")

        if unused_bits > 0 and len(value) == 0:
            raise ValueError("Cannot have unused bits with empty bit string")

        if unused_bits > 0 and value:
            mask = (1 << unused_bits) - 1
            if value[-1] & mask != 0:
                raise ValueError("Unused bits must be zero in DER")

        tag_bytes = (tag or BIT_STRING_TAG).encode()
        content = bytes([unused_bits]) + value
        return encode_tlv(tag_bytes, content)

    @staticmethod
    def encode_null(tag: Tag | None = None) -> bytes:
        from .tags import NULL_TAG
        tag_bytes = (tag or NULL_TAG).encode()
        return tag_bytes + b'\x00'

    @staticmethod
    def encode_object_identifier(oid: str | tuple[int, ...], tag: Tag | None = None) -> bytes:
        from .tags import OID_TAG

        if isinstance(oid, str):
            try:
                oid_tuple = tuple(int(x) for x in oid.split('.'))
            except ValueError:
                raise ValueError(f"Invalid OID string: {oid}")
        else:
            oid_tuple = oid

        if len(oid_tuple) < 2:
            raise ValueError("OID must have at least 2 components")

        if not (0 <= oid_tuple[0] <= 2):
            raise ValueError(f"First OID component must be 0-2, got {oid_tuple[0]}")

        if oid_tuple[0] < 2 and oid_tuple[1] >= 40:
            raise ValueError(f"Second component must be < 40 when first is < 2")

        content = bytearray()
        first_value = 40 * oid_tuple[0] + oid_tuple[1]
        content.extend(DEREncoder._encode_oid_component(first_value))

        for component in oid_tuple[2:]:
            content.extend(DEREncoder._encode_oid_component(component))

        tag_bytes = (tag or OID_TAG).encode()
        return encode_tlv(tag_bytes, bytes(content))

    @staticmethod
    def _encode_oid_component(value: int) -> bytes:
        if value == 0:
            return b'\x00'

        encoded = bytearray()
        while value > 0:
            encoded.insert(0, value & 0x7F)
            value >>= 7

        for i in range(len(encoded) - 1):
            encoded[i] |= 0x80

        return bytes(encoded)

    @staticmethod
    def encode_sequence(elements: list[bytes], tag: Tag | None = None) -> bytes:
        from .tags import SEQUENCE_TAG
        tag_bytes = (tag or SEQUENCE_TAG).encode()
        content = b''.join(elements)
        return encode_tlv(tag_bytes, content)

    @staticmethod
    def encode_set(elements: list[bytes], tag: Tag | None = None) -> bytes:
        from .tags import SET_TAG
        sorted_elements = sorted(elements)
        tag_bytes = (tag or SET_TAG).encode()
        content = b''.join(sorted_elements)
        return encode_tlv(tag_bytes, content)

    @staticmethod
    def encode_utf8_string(value: str, tag: Tag | None = None) -> bytes:
        from .tags import UTF8_STRING_TAG
        tag_bytes = (tag or UTF8_STRING_TAG).encode()
        content = value.encode('utf-8')
        return encode_tlv(tag_bytes, content)

    @staticmethod
    def encode_printable_string(value: str, tag: Tag | None = None) -> bytes:
        from .tags import PRINTABLE_STRING_TAG

        valid_chars = set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
            "0123456789 '()+,-./:=?"
        )

        for char in value:
            if char not in valid_chars:
                raise ValueError(
                    f"Invalid character in PrintableString: {repr(char)}"
                )

        tag_bytes = (tag or PRINTABLE_STRING_TAG).encode()
        content = value.encode('ascii')
        return encode_tlv(tag_bytes, content)

    @staticmethod
    def encode_ia5_string(value: str, tag: Tag | None = None) -> bytes:
        from .tags import IA5_STRING_TAG

        try:
            content = value.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError("IA5String must contain only ASCII characters")

        tag_bytes = (tag or IA5_STRING_TAG).encode()
        return encode_tlv(tag_bytes, content)

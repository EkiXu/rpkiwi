from abc import ABC, abstractmethod
from typing import Any
from ..der import DEREncoder, DEREncodable, Tag

class ASN1Type(ABC):

    def __init__(self, tag: Tag | None = None):
        self._tag = tag

    @abstractmethod
    def der_encode(self) -> bytes:
        pass

    def __bytes__(self) -> bytes:
        return self.der_encode()

class ASN1Boolean(ASN1Type):

    def __init__(self, value: bool, tag: Tag | None = None):
        super().__init__(tag)
        self.value = bool(value)

    def der_encode(self) -> bytes:
        return DEREncoder.encode_boolean(self.value, self._tag)

    def __repr__(self) -> str:
        return f"ASN1Boolean({self.value})"

    def __bool__(self) -> bool:
        return self.value

class ASN1Integer(ASN1Type):

    def __init__(self, value: int, tag: Tag | None = None):
        super().__init__(tag)
        self.value = int(value)

    def der_encode(self) -> bytes:
        return DEREncoder.encode_integer(self.value, self._tag)

    def __repr__(self) -> str:
        return f"ASN1Integer({self.value})"

    def __int__(self) -> int:
        return self.value

class ASN1OctetString(ASN1Type):

    def __init__(self, value: bytes, tag: Tag | None = None):
        super().__init__(tag)
        if not isinstance(value, bytes):
            raise TypeError("ASN1OctetString value must be bytes")
        self.value = value

    def der_encode(self) -> bytes:
        return DEREncoder.encode_octet_string(self.value, self._tag)

    def __repr__(self) -> str:
        return f"ASN1OctetString({self.value!r})"

    def __len__(self) -> int:
        return len(self.value)

class ASN1BitString(ASN1Type):

    def __init__(self, value: bytes, unused_bits: int = 0, tag: Tag | None = None):
        super().__init__(tag)
        if not isinstance(value, bytes):
            raise TypeError("ASN1BitString value must be bytes")
        if not 0 <= unused_bits <= 7:
            raise ValueError("unused_bits must be 0-7")
        if unused_bits > 0 and len(value) == 0:
            raise ValueError("Cannot have unused bits with empty bit string")

        self.value = value
        self.unused_bits = unused_bits

    def der_encode(self) -> bytes:
        return DEREncoder.encode_bit_string(self.value, self.unused_bits, self._tag)

    def __repr__(self) -> str:
        return f"ASN1BitString({self.value!r}, unused_bits={self.unused_bits})"

class ASN1Null(ASN1Type):

    def __init__(self, tag: Tag | None = None):
        super().__init__(tag)

    def der_encode(self) -> bytes:
        return DEREncoder.encode_null(self._tag)

    def __repr__(self) -> str:
        return "ASN1Null()"

    def __bool__(self) -> bool:
        return False

class ASN1ObjectIdentifier(ASN1Type):

    def __init__(self, oid: str | tuple[int, ...], tag: Tag | None = None):
        super().__init__(tag)

        if isinstance(oid, str):
            try:
                self.components = tuple(int(x) for x in oid.split('.'))
            except ValueError:
                raise ValueError(f"Invalid OID string: {oid}")
        else:
            self.components = tuple(oid)

        if len(self.components) < 2:
            raise ValueError("OID must have at least 2 components")

    def der_encode(self) -> bytes:
        return DEREncoder.encode_object_identifier(self.components, self._tag)

    def __repr__(self) -> str:
        return f"ASN1ObjectIdentifier('{self}')"

    def __str__(self) -> str:
        return '.'.join(str(x) for x in self.components)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, ASN1ObjectIdentifier):
            return self.components == other.components
        if isinstance(other, str):
            return str(self) == other
        if isinstance(other, tuple):
            return self.components == other
        return False

    def __hash__(self) -> int:
        return hash(self.components)

class ASN1UTF8String(ASN1Type):

    def __init__(self, value: str, tag: Tag | None = None):
        super().__init__(tag)
        if not isinstance(value, str):
            raise TypeError("ASN1UTF8String value must be str")
        self.value = value

    def der_encode(self) -> bytes:
        return DEREncoder.encode_utf8_string(self.value, self._tag)

    def __repr__(self) -> str:
        return f"ASN1UTF8String({self.value!r})"

    def __str__(self) -> str:
        return self.value

class ASN1PrintableString(ASN1Type):

    def __init__(self, value: str, tag: Tag | None = None):
        super().__init__(tag)
        if not isinstance(value, str):
            raise TypeError("ASN1PrintableString value must be str")
        self.value = value

    def der_encode(self) -> bytes:
        return DEREncoder.encode_printable_string(self.value, self._tag)

    def __repr__(self) -> str:
        return f"ASN1PrintableString({self.value!r})"

    def __str__(self) -> str:
        return self.value

class ASN1IA5String(ASN1Type):

    def __init__(self, value: str, tag: Tag | None = None):
        super().__init__(tag)
        if not isinstance(value, str):
            raise TypeError("ASN1IA5String value must be str")
        self.value = value

    def der_encode(self) -> bytes:
        return DEREncoder.encode_ia5_string(self.value, self._tag)

    def __repr__(self) -> str:
        return f"ASN1IA5String({self.value!r})"

    def __str__(self) -> str:
        return self.value

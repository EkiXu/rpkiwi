from typing import Any, Sequence as PySequence
from ..der import DEREncoder, Tag
from .types import ASN1Type

class ASN1Choice(ASN1Type):

    def __init__(self, value: ASN1Type):
        super().__init__(None)
        if not isinstance(value, ASN1Type):
            raise TypeError("CHOICE value must be an ASN1Type")
        self.value = value

    def der_encode(self) -> bytes:
        return self.value.der_encode()

    def __repr__(self) -> str:
        return f"ASN1Choice({self.value!r})"

class ASN1Optional:

    def __init__(self, value: ASN1Type | None):
        self.value = value

    def is_present(self) -> bool:
        return self.value is not None

    def get(self) -> ASN1Type:
        if self.value is None:
            raise ValueError("Optional field is not present")
        return self.value

    def der_encode(self) -> bytes:
        if self.value is None:
            return b''
        return self.value.der_encode()

    def __repr__(self) -> str:
        if self.value is None:
            return "ASN1Optional(absent)"
        return f"ASN1Optional({self.value!r})"

    def __bool__(self) -> bool:
        return self.is_present()

from typing import TypeVar, Generic, List, Iterator, Union
from .objects import ASN1Object
from .types import ASN1Type

T = TypeVar('T', bound=Union[ASN1Object, ASN1Type])

class ASN1SetOf(Generic[T], ASN1Object):

    _asn1_def = 'SET OF'

    def __init__(self, items: List[T] = None):
        super().__init__()
        self.items = items if items is not None else []

    def __repr__(self) -> str:
        return f"ASN1Set({self.items!r})"

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Iterator[T]:
        return iter(self.items)

    def __getitem__(self, index: int) -> T:
        return self.items[index]

    def append(self, item: T):
        self.items.append(item)

    def extend(self, items: List[T]):
        self.items.extend(items)

    def der_encode(self) -> bytes:
        from ..der.encoder import DEREncoder

        encoded_items = []
        for item in self.items:
            if isinstance(item, (ASN1Object, ASN1Type)):
                encoded_items.append(item.der_encode())
            elif isinstance(item, bytes):
                encoded_items.append(item)
            else:
                raise TypeError(
                    f"SET OF element must be ASN1Object, ASN1Type or bytes, got {type(item).__name__}"
                )

        encoded_items.sort()

        return DEREncoder.encode_set(encoded_items)

class ASN1SequenceOf(Generic[T], ASN1Object):

    _asn1_def = 'SEQUENCE OF'

    def __init__(self, items: List[T] = None):
        super().__init__()
        self.items = items if items is not None else []

    def __repr__(self) -> str:
        return f"ASN1SequenceOf({self.items!r})"

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Iterator[T]:
        return iter(self.items)

    def __getitem__(self, index: int) -> T:
        return self.items[index]

    def append(self, item: T):
        self.items.append(item)

    def extend(self, items: List[T]):
        self.items.extend(items)

    def der_encode(self) -> bytes:
        from ..der.encoder import DEREncoder

        encoded_items = []
        for item in self.items:
            if isinstance(item, (ASN1Object, ASN1Type)):
                encoded_items.append(item.der_encode())
            elif isinstance(item, bytes):
                encoded_items.append(item)
            else:
                raise TypeError(
                    f"SEQUENCE OF element must be ASN1Object, ASN1Type or bytes, got {type(item).__name__}"
                )

        return DEREncoder.encode_sequence(encoded_items)

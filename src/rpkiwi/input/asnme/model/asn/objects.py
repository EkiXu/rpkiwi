from typing import Any, Optional, Union, List, Dict, Type as PyType
from enum import Enum
from dataclasses import dataclass

class ASN1Type(Enum):
    INTEGER = "INTEGER"
    BOOLEAN = "BOOLEAN"
    OCTET_STRING = "OCTET STRING"
    BIT_STRING = "BIT STRING"
    NULL = "NULL"
    OBJECT_IDENTIFIER = "OBJECT IDENTIFIER"
    UTF8String = "UTF8String"
    PrintableString = "PrintableString"
    IA5String = "IA5String"
    SEQUENCE = "SEQUENCE"
    SET = "SET"
    SEQUENCE_OF = "SEQUENCE OF"
    SET_OF = "SET OF"
    CHOICE = "CHOICE"
    ANY = "ANY"

@dataclass
class ASN1Tag:
    number: int
    implicit: bool = False
    explicit: bool = False

class ASN1Field:

    def __init__(
        self,
        asn1_type: Union[ASN1Type, str, PyType],
        optional: bool = False,
        tag: Optional[ASN1Tag] = None,
        default: Any = None,
        element_type: Optional[Union[ASN1Type, str, PyType]] = None
    ):
        self.asn1_type = asn1_type
        self.optional = optional
        self.tag = tag
        self.default = default
        self.element_type = element_type
        self.name = None

    def __set_name__(self, owner, name):
        self.name = name

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return obj._values.get(self.name, self.default)

    def __set__(self, obj, value):
        obj._values[self.name] = value

class ASN1ObjectMeta(type):

    def __new__(mcs, name, bases, namespace, **kwargs):
        fields = {}
        for key, value in list(namespace.items()):
            if isinstance(value, ASN1Field):
                fields[key] = value

        namespace['_asn1_fields'] = fields

        return super().__new__(mcs, name, bases, namespace)

class ASN1Object(metaclass=ASN1ObjectMeta):

    _asn1_def: str = "SEQUENCE"
    _asn1_fields: Dict[str, ASN1Field] = {}

    def __init__(self, **kwargs):
        self._values = {}

        for key, value in kwargs.items():
            if key in self._asn1_fields:
                setattr(self, key, value)
            else:
                raise TypeError(f"Unknown field: {key}")

        for field_name, field_def in self._asn1_fields.items():
            if not field_def.optional and field_name not in kwargs:
                if field_def.default is None:
                    raise TypeError(f"Missing required field: {field_name}")

    def der_encode(self) -> bytes:
        from ..der.encoder import DEREncoder
        from ..der.tags import Tag, TagClass, context_tag
        from ..der.length import encode_tlv

        asn1_def = self._asn1_def.upper()

        if asn1_def == "SEQUENCE":
            return self._encode_sequence()
        elif asn1_def == "SET":
            return self._encode_set()
        elif asn1_def == "CHOICE":
            return self._encode_choice()
        elif asn1_def.startswith("SEQUENCE OF"):
            return self._encode_sequence_of()
        elif asn1_def.startswith("SET OF"):
            return self._encode_set_of()
        else:
            raise ValueError(f"Unknown ASN.1 definition: {asn1_def}")

    def _encode_sequence(self) -> bytes:
        from ..der.encoder import DEREncoder

        encoded_fields = []

        for field_name, field_def in self._asn1_fields.items():
            value = getattr(self, field_name)

            if value is None and field_def.optional:
                continue

            if field_def.default is not None and field_def.optional:
                if value == field_def.default:
                    continue

            encoded = self._encode_field(field_def, value)

            if field_def.tag:
                encoded = self._apply_tag(encoded, field_def.tag)

            encoded_fields.append(encoded)

        return DEREncoder.encode_sequence(encoded_fields)

    def _encode_set(self) -> bytes:
        from ..der.encoder import DEREncoder

        encoded_fields = []

        for field_name, field_def in self._asn1_fields.items():
            value = getattr(self, field_name)

            if value is None and field_def.optional:
                continue

            encoded = self._encode_field(field_def, value)

            if field_def.tag:
                encoded = self._apply_tag(encoded, field_def.tag)

            encoded_fields.append(encoded)

        return DEREncoder.encode_set(encoded_fields)

    def _encode_choice(self) -> bytes:
        set_fields = [(name, getattr(self, name))
                      for name in self._asn1_fields.keys()
                      if getattr(self, name) is not None]

        if len(set_fields) != 1:
            raise ValueError(f"CHOICE must have exactly one field set, got {len(set_fields)}")

        field_name, value = set_fields[0]
        field_def = self._asn1_fields[field_name]

        encoded = self._encode_field(field_def, value)

        if field_def.tag:
            encoded = self._apply_tag(encoded, field_def.tag)

        return encoded

    def _encode_sequence_of(self) -> bytes:
        from ..der.encoder import DEREncoder

        if len(self._asn1_fields) != 1:
            raise ValueError("SEQUENCE OF should have exactly one field")

        field_name = list(self._asn1_fields.keys())[0]
        field_def = list(self._asn1_fields.values())[0]
        items = getattr(self, field_name)

        if not isinstance(items, list):
            raise TypeError(f"SEQUENCE OF field must be a list, got {type(items)}")

        encoded_items = []
        for item in items:
            if field_def.element_type:
                if isinstance(field_def.element_type, str):
                    if isinstance(item, ASN1Object):
                        encoded = item.der_encode()
                    elif hasattr(item, 'der_encode'):
                        encoded = item.der_encode()
                    else:
                        raise TypeError(f"Cannot encode item of type {type(item)} for element_type {field_def.element_type}")
                elif isinstance(field_def.element_type, ASN1Type):
                    encoded = self._encode_value(field_def.element_type, item)
                else:
                    if isinstance(item, ASN1Object):
                        encoded = item.der_encode()
                    else:
                        raise TypeError(f"Expected ASN1Object, got {type(item)}")
            elif isinstance(item, ASN1Object):
                encoded = item.der_encode()
            else:
                encoded = item
            encoded_items.append(encoded)

        return DEREncoder.encode_sequence(encoded_items)

    def _encode_set_of(self) -> bytes:
        from ..der.encoder import DEREncoder

        if len(self._asn1_fields) != 1:
            raise ValueError("SET OF should have exactly one field")

        field_name = list(self._asn1_fields.keys())[0]
        field_def = list(self._asn1_fields.values())[0]
        items = getattr(self, field_name)

        if not isinstance(items, list):
            raise TypeError(f"SET OF field must be a list, got {type(items)}")

        encoded_items = []
        for item in items:
            if field_def.element_type:
                if isinstance(field_def.element_type, str):
                    if isinstance(item, ASN1Object):
                        encoded = item.der_encode()
                    elif hasattr(item, 'der_encode'):
                        encoded = item.der_encode()
                    else:
                        raise TypeError(f"Cannot encode item of type {type(item)} for element_type {field_def.element_type}")
                elif isinstance(field_def.element_type, ASN1Type):
                    encoded = self._encode_value(field_def.element_type, item)
                else:
                    if isinstance(item, ASN1Object):
                        encoded = item.der_encode()
                    else:
                        raise TypeError(f"Expected ASN1Object, got {type(item)}")
            elif isinstance(item, ASN1Object):
                encoded = item.der_encode()
            else:
                encoded = item
            encoded_items.append(encoded)

        return DEREncoder.encode_set(encoded_items)

    def _encode_field(self, field_def: ASN1Field, value: Any) -> bytes:
        if isinstance(value, ASN1Object):
            return value.der_encode()

        asn1_type = field_def.asn1_type

        if isinstance(asn1_type, ASN1Type):
            return self._encode_value(asn1_type, value)
        elif isinstance(asn1_type, str):
            if isinstance(value, bytes):
                return value
            elif isinstance(value, ASN1Object):
                return value.der_encode()
            else:
                raise TypeError(f"Cannot encode custom type {asn1_type}: {type(value)}")
        elif isinstance(asn1_type, type) and issubclass(asn1_type, ASN1Object):
            if not isinstance(value, asn1_type):
                raise TypeError(f"Expected {asn1_type}, got {type(value)}")
            return value.der_encode()
        else:
            raise TypeError(f"Unknown ASN.1 type: {asn1_type}")

    def _encode_value(self, asn1_type: ASN1Type, value: Any) -> bytes:
        from ..der.encoder import DEREncoder

        if asn1_type == ASN1Type.ANY:
            if isinstance(value, bytes):
                return value
            elif isinstance(value, ASN1Object):
                return value.der_encode()
            else:
                raise TypeError(f"ANY type must be bytes or ASN1Object, got {type(value).__name__}")

        if asn1_type == ASN1Type.INTEGER:
            return DEREncoder.encode_integer(int(value))
        elif asn1_type == ASN1Type.BOOLEAN:
            return DEREncoder.encode_boolean(bool(value))
        elif asn1_type == ASN1Type.OCTET_STRING:
            if isinstance(value, str):
                value = value.encode('utf-8')
            return DEREncoder.encode_octet_string(bytes(value))
        elif asn1_type == ASN1Type.BIT_STRING:
            if isinstance(value, str):
                value = value.encode('utf-8')
            return DEREncoder.encode_bit_string(bytes(value))
        elif asn1_type == ASN1Type.NULL:
            return DEREncoder.encode_null()
        elif asn1_type == ASN1Type.OBJECT_IDENTIFIER:
            return DEREncoder.encode_object_identifier(value)
        elif asn1_type == ASN1Type.UTF8String:
            return DEREncoder.encode_utf8_string(str(value))
        elif asn1_type == ASN1Type.PrintableString:
            return DEREncoder.encode_printable_string(str(value))
        elif asn1_type == ASN1Type.IA5String:
            return DEREncoder.encode_ia5_string(str(value))
        else:
            raise ValueError(f"Unsupported ASN.1 type for encoding: {asn1_type}")

    def _apply_tag(self, encoded: bytes, tag: ASN1Tag) -> bytes:
        from ..der.tags import Tag, TagClass, context_tag
        from ..der.length import encode_tlv

        if tag.explicit:
            context = context_tag(tag.number, constructed=True)
            return encode_tlv(context.encode(), encoded)
        elif tag.implicit:
            if len(encoded) < 2:
                raise ValueError("Invalid encoded data for implicit tagging")

            offset = 1
            length_byte = encoded[offset]

            if length_byte & 0x80:
                num_octets = length_byte & 0x7F
                offset += 1 + num_octets
            else:
                offset += 1

            content = encoded[offset:]

            context = context_tag(tag.number, constructed=False)
            return encode_tlv(context.encode(), content)
        else:
            return encoded

    def __repr__(self) -> str:
        field_strs = []
        for field_name in self._asn1_fields.keys():
            value = getattr(self, field_name)
            if value is not None:
                field_strs.append(f"{field_name}={value!r}")
        return f"{self.__class__.__name__}({', '.join(field_strs)})"

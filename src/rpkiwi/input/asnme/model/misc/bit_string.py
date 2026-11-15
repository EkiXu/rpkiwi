from ..der.tags import BIT_STRING_TAG
from ..der.length import encode_tlv

def encode_bit_string_with_hash(hash_bytes: bytes) -> bytes:
    content = bytes([0]) + hash_bytes
    return encode_tlv(BIT_STRING_TAG.encode(), content)

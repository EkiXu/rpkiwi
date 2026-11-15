def encode_length(length: int) -> bytes:
    if length < 0:
        raise ValueError(f"Length cannot be negative: {length}")

    if length < 128:
        return bytes([length])

    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')

    num_octets = len(length_bytes)

    if num_octets > 126:
        raise ValueError(f"Length too large: {length} (requires {num_octets} octets)")

    first_byte = 0x80 | num_octets

    return bytes([first_byte]) + length_bytes

def decode_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Unexpected end of data while decoding length")

    first_byte = data[offset]
    offset += 1

    if first_byte < 128:
        return first_byte, offset

    num_octets = first_byte & 0x7F

    if num_octets == 0:
        raise ValueError("Indefinite length form not allowed in DER")

    if offset + num_octets > len(data):
        raise ValueError(
            f"Unexpected end of data: expected {num_octets} length bytes, "
            f"but only {len(data) - offset} available"
        )

    length_bytes = data[offset:offset + num_octets]
    length = int.from_bytes(length_bytes, 'big')

    if length < 128:
        raise ValueError("Non-canonical length encoding: should use short form")

    if num_octets > 1:
        if length_bytes[0] == 0x00:
            raise ValueError("Non-canonical length encoding: leading zero byte")

    offset += num_octets

    return length, offset

def compute_tlv_size(content_length: int, tag_size: int = 1) -> int:
    length_size = len(encode_length(content_length))
    return tag_size + length_size + content_length

def encode_tlv(tag: bytes, value: bytes) -> bytes:
    return tag + encode_length(len(value)) + value

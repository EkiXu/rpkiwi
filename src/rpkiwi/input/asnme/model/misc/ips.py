import ipaddress
from ..der.length import encode_length

def encode_ip_resources_explicit(ipv4_prefixes: list[str] = None, ipv6_prefixes: list[str] = None) -> bytes:
    families = []

    if ipv4_prefixes:
        families.append(
            _encode_ip_family(
                b'\x00\x01',
                _canonicalize_prefixes(ipv4_prefixes),
                is_v6=False,
            )
        )
    if ipv6_prefixes:
        families.append(
            _encode_ip_family(
                b'\x00\x02',
                _canonicalize_prefixes(ipv6_prefixes),
                is_v6=True,
            )
        )

    inner = b''.join(families)
    return b'\x30' + encode_length(len(inner)) + inner

def _canonicalize_prefixes(prefixes: list[str]) -> list[tuple[int, int, int]]:
    networks = [ipaddress.ip_network(prefix, strict=False) for prefix in prefixes]
    if not networks:
        return []

    networks.sort(key=lambda network: (int(network.network_address), network.prefixlen))
    total_bits = networks[0].max_prefixlen

    intervals: list[list[int]] = []
    for network in networks:
        start = int(network.network_address)
        end = int(network.broadcast_address)
        if intervals and start <= intervals[-1][1] + 1:
            intervals[-1][1] = max(intervals[-1][1], end)
        else:
            intervals.append([start, end])

    return [(start, end, total_bits) for start, end in intervals]

def _encode_ip_family(afi: bytes, prefixes: list[str], is_v6: bool) -> bytes:
    afi_der = b'\x04\x02' + afi

    entries = []
    for start, end, total_bits in prefixes:
        prefix = _interval_to_prefix(start, end, total_bits)
        if prefix is not None:
            entries.append(_encode_prefix_bitstring(prefix, is_v6))
        else:
            entries.append(_encode_ip_range(start, end, total_bits))

    addresses_inner = b''.join(entries)
    addresses_der = b'\x30' + encode_length(len(addresses_inner)) + addresses_inner

    family_inner = afi_der + addresses_der
    return b'\x30' + encode_length(len(family_inner)) + family_inner

def _encode_prefix_bitstring(prefix: str, is_v6: bool) -> bytes:
    network = ipaddress.ip_network(prefix, strict=False)
    prefix_len = network.prefixlen
    num_bytes = (prefix_len + 7) // 8

    if is_v6:
        ip_int = int(network.network_address)
        total_bits = 128
    else:
        ip_int = int(network.network_address)
        total_bits = 32

    mask = ((1 << total_bits) - 1) << (total_bits - prefix_len) & ((1 << total_bits) - 1)
    masked = ip_int & mask
    addr_bytes = masked.to_bytes(total_bits // 8, 'big')[:num_bytes]

    unused_bits = num_bytes * 8 - prefix_len
    content = bytes([unused_bits]) + addr_bytes
    return b'\x03' + encode_length(len(content)) + content

def _interval_to_prefix(start: int, end: int, total_bits: int) -> str | None:
    size = end - start + 1
    if size <= 0 or size & (size - 1):
        return None

    prefix_len = total_bits - (size.bit_length() - 1)
    if start % size != 0:
        return None

    address = ipaddress.ip_address(start)
    return f"{address}/{prefix_len}"

def _encode_ip_range(start: int, end: int, total_bits: int) -> bytes:
    min_keep_bits = total_bits - _count_trailing_zeros(start, total_bits)
    max_keep_bits = total_bits - _count_trailing_ones(end, total_bits)

    min_der = _encode_partial_bitstring(start, total_bits, min_keep_bits)
    max_der = _encode_partial_bitstring(end, total_bits, max_keep_bits)
    content = min_der + max_der
    return b'\x30' + encode_length(len(content)) + content

def _encode_partial_bitstring(value: int, total_bits: int, keep_bits: int) -> bytes:
    if keep_bits < 0 or keep_bits > total_bits:
        raise ValueError(f"invalid keep_bits={keep_bits} for total_bits={total_bits}")

    if keep_bits == 0:
        content = b'\x00'
        return b'\x03' + encode_length(len(content)) + content

    num_bytes = (keep_bits + 7) // 8
    unused_bits = num_bytes * 8 - keep_bits
    addr_bytes = bytearray(value.to_bytes(total_bits // 8, 'big')[:num_bytes])
    if unused_bits:
        addr_bytes[-1] &= 0xFF << unused_bits

    content = bytes([unused_bits]) + bytes(addr_bytes)
    return b'\x03' + encode_length(len(content)) + content

def _count_trailing_zeros(value: int, total_bits: int) -> int:
    if value == 0:
        return total_bits
    return (value & -value).bit_length() - 1

def _count_trailing_ones(value: int, total_bits: int) -> int:
    count = 0
    while count < total_bits and value & 1:
        count += 1
        value >>= 1
    return count

def encode_ip_resources_inherit() -> bytes:
    ipv4_block = bytes([
        0x30, 0x06,
        0x04, 0x02, 0x00, 0x01,
        0x05, 0x00,
    ])

    ipv6_block = bytes([
        0x30, 0x06,
        0x04, 0x02, 0x00, 0x02,
        0x05, 0x00,
    ])

    inner = ipv4_block + ipv6_block
    return bytes([0x30, len(inner)]) + inner

def encode_ip_resources_invalid_prefix_len(prefix_len: int = 129, afi: bytes = b'\x00\x01') -> bytes:
    num_addr_bytes = (prefix_len + 7) // 8
    unused_bits = num_addr_bytes * 8 - prefix_len

    addr = b'\x0a' + b'\x00' * (num_addr_bytes - 1) if num_addr_bytes > 0 else b''

    bs_content = bytes([unused_bits & 0xFF]) + addr
    bitstring = b'\x03' + encode_length(len(bs_content)) + bs_content

    addresses_inner = bitstring
    addresses_der = b'\x30' + encode_length(len(addresses_inner)) + addresses_inner

    afi_der = b'\x04\x02' + afi
    family_inner = afi_der + addresses_der
    family = b'\x30' + encode_length(len(family_inner)) + family_inner

    return b'\x30' + encode_length(len(family)) + family

def encode_as_resources_explicit(asn: int) -> bytes:
    if asn == 0:
        asn_der = b'\x02\x01\x00'
    else:
        asn_bytes = asn.to_bytes((asn.bit_length() + 8) // 8, 'big')
        asn_der = b'\x02' + encode_length(len(asn_bytes)) + asn_bytes

    seq_of_inner = asn_der
    seq_of = b'\x30' + encode_length(len(seq_of_inner)) + seq_of_inner

    explicit_inner = seq_of
    explicit_tag = b'\xA0' + encode_length(len(explicit_inner)) + explicit_inner

    outer = b'\x30' + encode_length(len(explicit_tag)) + explicit_tag
    return outer

def encode_as_resources_inherit() -> bytes:
    return bytes([
        0x30, 0x04,
        0xA0, 0x02,
        0x05, 0x00,
    ])

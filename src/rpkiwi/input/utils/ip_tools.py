import ipaddress

from src.rpkiwi.input.asnme.model.der.length import decode_length

def parse_roa_prefixes(roa_der: bytes) -> tuple[int, list[str], list[str]]:
    _, _, children_start = _read_tag_length(roa_der, 0)
    offset = children_start

    tag = roa_der[offset]
    if tag == 0xA0:
        _, elem_len, val_start = _read_tag_length(roa_der, offset)
        offset = val_start + elem_len

    _, int_len, int_start = _read_tag_length(roa_der, offset)
    asn = int.from_bytes(roa_der[int_start:int_start + int_len], 'big')
    offset = int_start + int_len

    _, blocks_len, blocks_start = _read_tag_length(roa_der, offset)
    blocks_end = blocks_start + blocks_len

    ipv4_prefixes = []
    ipv6_prefixes = []

    pos = blocks_start
    while pos < blocks_end:
        _, fam_len, fam_start = _read_tag_length(roa_der, pos)
        fam_end = fam_start + fam_len

        _, afi_len, afi_start = _read_tag_length(roa_der, fam_start)
        afi = int.from_bytes(roa_der[afi_start:afi_start + afi_len], 'big')
        addr_pos = afi_start + afi_len

        _, addrs_len, addrs_start = _read_tag_length(roa_der, addr_pos)
        addrs_end = addrs_start + addrs_len

        apos = addrs_start
        while apos < addrs_end:
            _, roa_addr_len, roa_addr_start = _read_tag_length(roa_der, apos)

            _, bs_len, bs_start = _read_tag_length(roa_der, roa_addr_start)
            unused = roa_der[bs_start]
            ip_bytes = roa_der[bs_start + 1:bs_start + bs_len]
            pfx_len = len(ip_bytes) * 8 - unused

            if afi == 1:
                ip = ipaddress.IPv4Address(ip_bytes + b'\x00' * (4 - len(ip_bytes)))
                ipv4_prefixes.append(f"{ip}/{pfx_len}")
            else:
                ip = ipaddress.IPv6Address(ip_bytes + b'\x00' * (16 - len(ip_bytes)))
                ipv6_prefixes.append(f"{ip}/{pfx_len}")

            apos = roa_addr_start + roa_addr_len

        pos = fam_end

    return asn, ipv4_prefixes, ipv6_prefixes

def _read_tag_length(data: bytes, offset: int) -> tuple[int, int, int]:
    tag = data[offset]
    offset += 1
    length, offset = decode_length(data, offset)
    return tag, length, offset

def encode_ip_prefix_to_bitstring(prefix_str: str) -> bytes:
    network = ipaddress.ip_network(prefix_str, strict=False)
    prefix_len = network.prefixlen

    num_bytes = (prefix_len + 7) // 8

    if isinstance(network, ipaddress.IPv4Network):
        ip_int = int(network.network_address)
        mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
        ip_int = ip_int & mask
        ip_bytes = ip_int.to_bytes(4, 'big')[:num_bytes]
    else:
        ip_int = int(network.network_address)
        mask = (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF << (128 - prefix_len)) & 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        ip_int = ip_int & mask
        ip_bytes = ip_int.to_bytes(16, 'big')[:num_bytes]

    unused_bits = (num_bytes * 8) - prefix_len

    return bytes([unused_bits]) + ip_bytes

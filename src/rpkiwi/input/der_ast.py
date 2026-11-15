from __future__ import annotations

import base64
import copy
from dataclasses import dataclass, field

def _encode_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    length_bytes = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes

def _encode_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(content)) + content

_CONSTRUCTED_TAGS = frozenset(
    [0x30, 0x31] + list(range(0xA0, 0xB0))
)

@dataclass
class DERNode:
    tag: int
    constructed: bool
    children: list[DERNode] = field(default_factory=list)
    content: bytes = b""
    label: str = ""

    def serialize(self) -> bytes:
        if self.constructed:
            inner = b"".join(c.serialize() for c in self.children)
            return _encode_tlv(self.tag, inner)
        return _encode_tlv(self.tag, self.content)

    def child_by_tag(self, tag: int) -> DERNode | None:
        for c in self.children:
            if c.tag == tag:
                return c
        return None

    def child_by_label(self, label: str) -> DERNode | None:
        for c in self.children:
            if c.label == label:
                return c
        return None

    def children_by_tag(self, tag: int) -> list[DERNode]:
        return [c for c in self.children if c.tag == tag]

    def child_at(self, index: int) -> DERNode:
        return self.children[index]

    def find(self, path: str) -> DERNode | None:
        node = self
        for part in path.split("/"):
            found = node.child_by_label(part)
            if found is None:
                return None
            node = found
        return node

    def to_dict(self) -> dict:
        d: dict = {"t": self.tag}
        if self.label:
            d["n"] = self.label
        if self.constructed:
            d["c"] = [c.to_dict() for c in self.children]
        else:
            d["v"] = base64.b64encode(self.content).decode("ascii")
        return d

    @classmethod
    def from_dict(cls, d: dict) -> DERNode:
        tag = d["t"]
        label = d.get("n", "")
        if "c" in d:
            children = [cls.from_dict(c) for c in d["c"]]
            return cls(tag=tag, constructed=True, children=children, label=label)
        content = base64.b64decode(d.get("v", ""))
        return cls(tag=tag, constructed=False, content=content, label=label)

    @classmethod
    def parse(cls, data: bytes, offset: int = 0) -> DERNode:
        tag = data[offset]
        first_len = data[offset + 1]
        if first_len & 0x80:
            n = first_len & 0x7F
            length = int.from_bytes(data[offset + 2 : offset + 2 + n], "big")
            header_len = 2 + n
        else:
            length = first_len
            header_len = 2

        content_start = offset + header_len
        content_bytes = data[content_start : content_start + length]

        constructed = bool(tag & 0x20) or tag in _CONSTRUCTED_TAGS
        if constructed:
            children: list[DERNode] = []
            cursor = 0
            while cursor < length:
                child = cls.parse(content_bytes, cursor)
                children.append(child)
                child_first_len = content_bytes[cursor + 1]
                if child_first_len & 0x80:
                    cn = child_first_len & 0x7F
                    child_total = 2 + cn + int.from_bytes(
                        content_bytes[cursor + 2 : cursor + 2 + cn], "big"
                    )
                else:
                    child_total = 2 + child_first_len
                cursor += child_total
            return cls(tag=tag, constructed=True, children=children)

        return cls(tag=tag, constructed=False, content=content_bytes)

    def clone(self) -> DERNode:
        return copy.deepcopy(self)

if __name__ == "__main__":
    leaf = DERNode(tag=0x02, constructed=False, content=b"\x2a")
    seq = DERNode(tag=0x30, constructed=True, children=[leaf])
    der_bytes = seq.serialize()
    parsed = DERNode.parse(der_bytes)
    assert parsed.tag == 0x30
    assert parsed.constructed
    assert len(parsed.children) == 1
    assert parsed.children[0].tag == 0x02
    assert parsed.children[0].content == b"\x2a"
    assert parsed.serialize() == der_bytes
    print("Test 1 passed: simple round-trip")

    d = seq.to_dict()
    assert d == {"t": 0x30, "c": [{"t": 0x02, "v": base64.b64encode(b"\x2a").decode()}]}
    restored = DERNode.from_dict(d)
    assert restored.serialize() == der_bytes
    print("Test 2 passed: JSON round-trip")

    oid = DERNode(tag=0x06, constructed=False, content=bytes.fromhex("2a864886f70d010702"))
    octet = DERNode(tag=0x04, constructed=False, content=b"\xde\xad\xbe\xef")
    inner_seq = DERNode(tag=0x30, constructed=True, children=[oid, octet])
    tagged = DERNode(tag=0xA0, constructed=True, children=[inner_seq])
    outer_seq = DERNode(tag=0x30, constructed=True, children=[
        DERNode(tag=0x02, constructed=False, content=b"\x03"),
        tagged,
    ])
    cms_bytes = outer_seq.serialize()
    parsed_cms = DERNode.parse(cms_bytes)
    assert parsed_cms.serialize() == cms_bytes
    assert parsed_cms.child_at(1).tag == 0xA0
    assert parsed_cms.child_at(1).child_at(0).child_by_tag(0x06).content == oid.content
    assert parsed_cms.children_by_tag(0x02) == [parsed_cms.children[0]]
    print("Test 3 passed: nested CMS-like round-trip")

    cloned = outer_seq.clone()
    cloned.children[0].content = b"\xff"
    assert outer_seq.children[0].content == b"\x03"
    print("Test 4 passed: clone independence")

    big_content = bytes(range(256)) * 2
    big_node = DERNode(tag=0x04, constructed=False, content=big_content)
    big_der = big_node.serialize()
    parsed_big = DERNode.parse(big_der)
    assert parsed_big.content == big_content
    assert parsed_big.serialize() == big_der
    print("Test 5 passed: long-form length encoding")

    set_node = DERNode(tag=0x31, constructed=True, children=[
        DERNode(tag=0x02, constructed=False, content=b"\x01"),
    ])
    set_der = set_node.serialize()
    parsed_set = DERNode.parse(set_der)
    assert parsed_set.constructed
    assert parsed_set.children[0].content == b"\x01"
    print("Test 6 passed: SET constructed")

    print("\nAll DERNode tests passed.")

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

RRDP_NS = "http://www.ripe.net/rpki/rrdp"

def element_to_dict(elem: ET.Element) -> dict:
    return {
        "tag": elem.tag,
        "attrib": dict(elem.attrib),
        "text": elem.text,
        "tail": elem.tail,
        "children": [element_to_dict(c) for c in elem],
    }

def dict_to_element(d: dict) -> ET.Element:
    elem = ET.Element(d["tag"], d.get("attrib", {}))
    elem.text = d.get("text")
    elem.tail = d.get("tail")
    for child_dict in d.get("children", []):
        elem.append(dict_to_element(child_dict))
    return elem

def parse_xml(data: bytes) -> ET.Element:
    return ET.fromstring(data)

def serialize_xml(root: ET.Element) -> bytes:
    ET.register_namespace("", RRDP_NS)
    return ET.tostring(root, encoding="unicode", xml_declaration=True).encode("utf-8")

if __name__ == "__main__":
    xml_src = b'<root attr1="val1"><child>text</child><child attr2="v2"/></root>'
    elem = parse_xml(xml_src)
    d = element_to_dict(elem)
    assert d["tag"] == "root"
    assert d["attrib"] == {"attr1": "val1"}
    assert len(d["children"]) == 2
    assert d["children"][0]["text"] == "text"
    restored = dict_to_element(d)
    assert restored.tag == "root"
    assert restored.attrib == {"attr1": "val1"}
    assert len(list(restored)) == 2
    assert list(restored)[0].text == "text"
    print("Test 1 passed: simple XML round-trip")

    clark = f"{{{RRDP_NS}}}"
    snapshot_xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<snapshot xmlns="http://www.ripe.net/rpki/rrdp" version="1" session_id="abc" serial="1">'
        b'<publish uri="rsync://example.com/repo/a.cer">AQID</publish>'
        b'</snapshot>'
    )
    root = parse_xml(snapshot_xml)
    d = element_to_dict(root)
    assert d["tag"] == f"{clark}snapshot"
    assert d["attrib"]["session_id"] == "abc"
    assert len(d["children"]) == 1
    assert d["children"][0]["text"] == "AQID"
    restored = dict_to_element(d)
    out_bytes = serialize_xml(restored)
    reparsed = parse_xml(out_bytes)
    assert reparsed.tag == root.tag
    assert reparsed.attrib == root.attrib
    assert list(reparsed)[0].text == "AQID"
    print("Test 2 passed: RRDP snapshot round-trip")

    mixed = b"<root><a>hello</a>tail<b/></root>"
    elem = parse_xml(mixed)
    d = element_to_dict(elem)
    assert d["children"][0]["tail"] == "tail"
    restored = dict_to_element(d)
    assert list(restored)[0].tail == "tail"
    print("Test 3 passed: tail text preservation")

    print("\nAll XML AST tests passed.")

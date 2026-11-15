from __future__ import annotations

import copy
import os
import random
import xml.etree.ElementTree as ET

RRDP_NS = "http://www.ripe.net/rpki/rrdp"

def _collect_elements(root: ET.Element, max_depth: int = 6) -> list[tuple[ET.Element, ET.Element | None, int]]:
    results: list[tuple[ET.Element, ET.Element | None, int]] = []
    stack: list[tuple[ET.Element, ET.Element | None, int]] = [(root, None, 0)]
    while stack:
        elem, parent, depth = stack.pop()
        results.append((elem, parent, depth))
        if depth < max_depth:
            for child in elem:
                stack.append((child, elem, depth + 1))
    return results

def _pick_element(root: ET.Element) -> tuple[ET.Element, ET.Element | None]:
    elements = _collect_elements(root)
    if len(elements) < 2:
        raise ValueError("tree too small")
    elem, parent, _depth = random.choice(elements[1:])
    return elem, parent

def _pick_child_of(parent: ET.Element) -> tuple[ET.Element, int]:
    children = list(parent)
    if not children:
        raise ValueError("no children")
    idx = random.randrange(len(children))
    return children[idx], idx

def tree_delete(root: ET.Element) -> tuple[ET.Element, str]:
    elem, parent = _pick_element(root)
    if parent is None:
        raise ValueError("cannot delete root")
    parent.remove(elem)
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    return root, f"delete element <{tag}>"

def tree_duplicate(root: ET.Element) -> tuple[ET.Element, str]:
    elem, parent = _pick_element(root)
    if parent is None:
        raise ValueError("cannot duplicate root")
    clone = copy.deepcopy(elem)
    children = list(parent)
    idx = children.index(elem)
    parent.insert(idx + 1, clone)
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    return root, f"duplicate element <{tag}>"

def tree_swap(root: ET.Element) -> tuple[ET.Element, str]:
    elements = _collect_elements(root)
    parents_with_kids = [(e, p, d) for e, p, d in elements if len(list(e)) >= 2]
    if not parents_with_kids:
        raise ValueError("no element with ≥2 children")
    parent_elem, _, _ = random.choice(parents_with_kids)
    children = list(parent_elem)
    i, j = random.sample(range(len(children)), 2)
    child_i = children[i]
    child_j = children[j]
    parent_elem.remove(child_i)
    parent_elem.remove(child_j)
    pos_i = min(i, j)
    pos_j = max(i, j) - 1
    parent_elem.insert(pos_i, child_j)
    parent_elem.insert(pos_j + 1, child_i)
    tag_i = child_i.tag.split("}")[-1] if "}" in child_i.tag else child_i.tag
    tag_j = child_j.tag.split("}")[-1] if "}" in child_j.tag else child_j.tag
    return root, f"swap <{tag_i}> ↔ <{tag_j}>"

def tree_add(root: ET.Element) -> tuple[ET.Element, str]:
    elements = _collect_elements(root)
    parent_elem, _, _ = random.choice(elements)
    tag_choices = ["publish", "withdraw", "delta", "snapshot", "notification",
                   "unknown", "extra", f"fuzz{random.randint(0,999)}"]
    new_tag = random.choice(tag_choices)
    new_elem = ET.SubElement(parent_elem, f"{{{RRDP_NS}}}{new_tag}")
    n_attrs = random.randint(0, 3)
    for _ in range(n_attrs):
        attr_name = random.choice(["uri", "hash", "serial", "session_id", "version", f"attr{random.randint(0,99)}"])
        attr_val = os.urandom(random.randint(4, 32)).hex()
        new_elem.set(attr_name, attr_val)
    if random.random() < 0.5:
        new_elem.text = os.urandom(random.randint(8, 64)).hex()
    return root, f"add <{new_tag}> to tree ({n_attrs} attrs)"

def tree_splice(root: ET.Element) -> tuple[ET.Element, str]:
    elements = _collect_elements(root)
    non_root = [(e, p, d) for e, p, d in elements if p is not None]
    if len(non_root) < 2:
        raise ValueError("not enough elements for splice")
    src_elem, src_parent, _ = random.choice(non_root)
    tgt_parent, _, _ = random.choice(elements)
    if tgt_parent is src_elem:
        raise ValueError("cannot splice into self")
    clone = copy.deepcopy(src_elem)
    src_parent.remove(src_elem)
    tgt_parent.append(clone)
    tag = src_elem.tag.split("}")[-1] if "}" in src_elem.tag else src_elem.tag
    tgt_tag = tgt_parent.tag.split("}")[-1] if "}" in tgt_parent.tag else tgt_parent.tag
    return root, f"splice <{tag}> → under <{tgt_tag}>"

def tree_nest(root: ET.Element) -> tuple[ET.Element, str]:
    elem, parent = _pick_element(root)
    if parent is None:
        raise ValueError("cannot nest root")
    wrapper_tag = random.choice(["wrapper", "container", "group", "nested",
                                  "publish", "delta", "snapshot"])
    children = list(parent)
    idx = children.index(elem)
    parent.remove(elem)
    wrapper = ET.Element(f"{{{RRDP_NS}}}{wrapper_tag}")
    wrapper.append(elem)
    parent.insert(idx, wrapper)
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    return root, f"nest <{tag}> in <{wrapper_tag}>"

def tree_flatten(root: ET.Element) -> tuple[ET.Element, str]:
    elements = _collect_elements(root)
    candidates = [(e, p, d) for e, p, d in elements if p is not None and len(list(e)) > 0]
    if not candidates:
        raise ValueError("no nestable element to flatten")
    elem, parent, _ = random.choice(candidates)
    children_of_elem = list(elem)
    parent_children = list(parent)
    idx = parent_children.index(elem)
    parent.remove(elem)
    for i, child in enumerate(children_of_elem):
        parent.insert(idx + i, child)
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    return root, f"flatten <{tag}> ({len(children_of_elem)} children promoted)"

XML_TREE_OPS = [tree_delete, tree_duplicate, tree_swap, tree_add, tree_splice, tree_nest, tree_flatten]

def node_retag(root: ET.Element) -> tuple[ET.Element, str]:
    elem, _parent = _pick_element(root)
    old_tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    new_tags = ["publish", "withdraw", "delta", "snapshot", "notification",
                "certificate", "roa", "manifest", "crl",
                f"fuzz{random.randint(0,999)}", "INVALID", ""]
    new_tag_local = random.choice([t for t in new_tags if t != old_tag] or new_tags)
    if new_tag_local:
        elem.tag = f"{{{RRDP_NS}}}{new_tag_local}"
    else:
        elem.tag = "empty"
    return root, f"retag <{old_tag}> → <{new_tag_local}>"

def node_replace_content(root: ET.Element) -> tuple[ET.Element, str]:
    elem, _parent = _pick_element(root)
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag

    target = random.choice(["text", "attrib", "both"])

    if target in ("text", "both"):
        mode = random.choice(["empty", "random", "oversized", "bit_flip", "inject"])
        if mode == "empty":
            elem.text = ""
            desc_text = "text=empty"
        elif mode == "random":
            elem.text = os.urandom(random.randint(8, 128)).hex()
            desc_text = f"text=random({len(elem.text)} chars)"
        elif mode == "oversized":
            size = random.choice([1024, 65536, 1048576])
            elem.text = "A" * size
            desc_text = f"text=oversized({size})"
        elif mode == "bit_flip":
            if elem.text:
                ba = bytearray(elem.text.encode())
                for _ in range(random.randint(1, 4)):
                    pos = random.randrange(len(ba))
                    ba[pos] ^= (1 << random.randrange(8))
                elem.text = ba.decode("latin-1")
                desc_text = "text=bit_flip"
            else:
                elem.text = os.urandom(16).hex()
                desc_text = "text=random(was empty)"
        else:
            payloads = [
                '<?xml version="1.0"?>',
                '<!DOCTYPE foo [<!ENTITY xxe "test">]>',
                "]]>",
                "<!--",
                "<![CDATA[test]]>",
                "\x00\x01\x02",
            ]
            elem.text = random.choice(payloads)
            desc_text = f"text=inject({elem.text[:20]})"
    else:
        desc_text = ""

    if target in ("attrib", "both"):
        mode = random.choice(["clear", "random_value", "random_key", "oversized", "delete"])
        if mode == "clear":
            elem.attrib.clear()
            desc_attr = "attribs=cleared"
        elif mode == "random_value":
            if elem.attrib:
                key = random.choice(list(elem.attrib.keys()))
                elem.attrib[key] = os.urandom(random.randint(4, 64)).hex()
                desc_attr = f"attrib[{key}]=random"
            else:
                elem.set(f"fuzz{random.randint(0,99)}", os.urandom(16).hex())
                desc_attr = "attrib=added_random"
        elif mode == "random_key":
            val = os.urandom(16).hex()
            key = f"fuzz_{random.randint(0,9999)}"
            elem.set(key, val)
            desc_attr = f"attrib[{key}]=added"
        elif mode == "oversized":
            key = random.choice(list(elem.attrib.keys())) if elem.attrib else "fuzz"
            elem.set(key, "X" * random.choice([1024, 65536]))
            desc_attr = f"attrib[{key}]=oversized"
        else:
            if elem.attrib:
                key = random.choice(list(elem.attrib.keys()))
                del elem.attrib[key]
                desc_attr = f"attrib[{key}]=deleted"
            else:
                desc_attr = "attrib=none_to_delete"
    else:
        desc_attr = ""

    parts = [p for p in [desc_text, desc_attr] if p]
    desc = f"replace_content <{tag}> [{', '.join(parts)}]"
    return root, desc

XML_NODE_OPS = [node_retag, node_replace_content]

ALL_XML_OPS = XML_TREE_OPS + XML_NODE_OPS

def mutate_xml(root: ET.Element, object_type: str = "SNAPSHOT") -> tuple[ET.Element, str, str]:
    new_root = copy.deepcopy(root)
    op = random.choice(ALL_XML_OPS)
    try:
        result_root, desc = op(new_root)
        return result_root, f"xml_{op.__name__}", desc
    except (ValueError, IndexError, KeyError, ET.ParseError) as exc:
        return root, f"xml_{op.__name__}_failed", f"{op.__name__} failed: {exc}"

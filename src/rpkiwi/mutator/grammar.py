from __future__ import annotations

import os
import random

from src.rpkiwi.input.der_ast import DERNode

def _collect_constructed(root: DERNode, max_depth: int = 6) -> list[tuple[DERNode, DERNode, int]]:
    results: list[tuple[DERNode, DERNode, int]] = []

    def walk(node: DERNode, depth: int) -> None:
        if depth > max_depth or not node.constructed:
            return
        for i, child in enumerate(node.children):
            results.append((node, child, i))
            walk(child, depth + 1)

    walk(root, 0)
    return results

def _pick_parent_child(root: DERNode) -> tuple[DERNode, int]:
    candidates = _collect_constructed(root)
    if not candidates:
        raise ValueError("no navigable nodes")
    parent, _child, idx = random.choice(candidates)
    return parent, idx

def _pick_parent_with_n_children(root: DERNode, min_children: int) -> DERNode:
    candidates = _collect_constructed(root)
    parents = {id(p): p for p, _c, _i in candidates}
    eligible = [p for p in parents.values() if len(p.children) >= min_children]
    if not eligible:
        raise ValueError(f"no parent with ≥{min_children} children")
    return random.choice(eligible)

def tree_delete(root: DERNode) -> tuple[DERNode, str]:
    new_root = root.clone()
    parent, idx = _pick_parent_child(new_root)
    if len(parent.children) < 2:
        raise ValueError("only child, cannot delete")
    tag = parent.children[idx].tag
    del parent.children[idx]
    return new_root, f"delete node (tag 0x{tag:02x})"

def tree_duplicate(root: DERNode) -> tuple[DERNode, str]:
    new_root = root.clone()
    parent, idx = _pick_parent_child(new_root)
    child_copy = parent.children[idx].clone()
    tag = parent.children[idx].tag
    parent.children.insert(idx + 1, child_copy)
    return new_root, f"duplicate node (tag 0x{tag:02x})"

def tree_swap(root: DERNode) -> tuple[DERNode, str]:
    new_root = root.clone()
    parent = _pick_parent_with_n_children(new_root, 2)
    i, j = random.sample(range(len(parent.children)), 2)
    parent.children[i], parent.children[j] = parent.children[j], parent.children[i]
    tag_i = f"0x{parent.children[j].tag:02x}"
    tag_j = f"0x{parent.children[i].tag:02x}"
    return new_root, f"swap siblings (tag {tag_i} ↔ tag {tag_j})"

def tree_add(root: DERNode) -> tuple[DERNode, str]:
    new_root = root.clone()
    parent, idx = _pick_parent_child(new_root)
    new_tag = random.randint(0x00, 0xFF)
    new_content = os.urandom(random.randint(0, 64))
    new_node = DERNode(tag=new_tag, constructed=False, content=new_content)
    parent.children.insert(idx + 1, new_node)
    return new_root, f"add random node (tag 0x{new_tag:02x}, {len(new_content)} bytes)"

def tree_splice(root: DERNode) -> tuple[DERNode, str]:
    new_root = root.clone()
    candidates = _collect_constructed(new_root)
    if len(candidates) < 2:
        raise ValueError("not enough nodes for splice")
    src_parent, src_child, src_idx = random.choice(candidates)
    tgt_parent, tgt_child, tgt_idx = random.choice(candidates)
    replacement = src_child.clone()
    src_tag = f"0x{src_child.tag:02x}"
    tgt_tag = f"0x{tgt_child.tag:02x}"
    tgt_parent.children[tgt_idx] = replacement
    return new_root, f"splice (tag {src_tag} → tag {tgt_tag})"

def tree_nest(root: DERNode) -> tuple[DERNode, str]:
    new_root = root.clone()
    parent, idx = _pick_parent_child(new_root)
    wrapper_tag = random.choice([0x30, 0x31, 0xA0, 0xA1])
    child = parent.children[idx]
    wrapper = DERNode(tag=wrapper_tag, constructed=True, children=[child])
    parent.children[idx] = wrapper
    tag_name = {0x30: "SEQUENCE", 0x31: "SET", 0xA0: "CONTEXT[0]", 0xA1: "CONTEXT[1]"}[wrapper_tag]
    return new_root, f"nest node (tag 0x{child.tag:02x}) in {tag_name}"

def tree_flatten(root: DERNode) -> tuple[DERNode, str]:
    new_root = root.clone()
    parent, idx = _pick_parent_child(new_root)
    child = parent.children[idx]
    if not child.constructed or not child.children:
        raise ValueError("leaf node, cannot flatten")
    first_inner = child.children[0]
    parent.children[idx] = first_inner
    return new_root, f"flatten node (tag 0x{child.tag:02x} → tag 0x{first_inner.tag:02x})"

TREE_OPS = [tree_delete, tree_duplicate, tree_swap, tree_add, tree_splice, tree_nest, tree_flatten]

def node_retype(root: DERNode) -> tuple[DERNode, str]:
    new_root = root.clone()
    parent, idx = _pick_parent_child(new_root)
    child = parent.children[idx]
    old_tag = child.tag
    tags = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0C, 0x13, 0x16, 0x17, 0x18,
            0x30, 0x31, 0xA0, 0xA1, 0xA2, 0xA3]
    new_tag = random.choice([t for t in tags if t != old_tag] or tags)
    child.tag = new_tag
    return new_root, f"retype node (0x{old_tag:02x} → 0x{new_tag:02x})"

def node_replace_content(root: DERNode) -> tuple[DERNode, str]:
    new_root = root.clone()
    parent, idx = _pick_parent_child(new_root)
    child = parent.children[idx]
    content = child.content
    content_len = len(content)

    mode = random.choice(["empty", "random", "truncate", "oversized",
                          "bit_flip", "byte_insert", "byte_delete", "havoc"])

    if mode == "empty":
        new_content = b""
        desc = "empty"
    elif mode == "random":
        new_content = os.urandom(content_len) if content_len > 0 else os.urandom(random.randint(1, 32))
        desc = f"random ({len(new_content)} bytes)"
    elif mode == "truncate":
        cut = max(1, content_len // 2) if content_len > 1 else 0
        new_content = content[:cut]
        desc = f"truncate ({content_len}→{len(new_content)})"
    elif mode == "oversized":
        size = random.choice([256, 1024, 4096, 65536])
        new_content = os.urandom(size)
        desc = f"oversized ({size} bytes)"
    elif mode == "bit_flip":
        if content_len == 0:
            new_content = os.urandom(1)
            desc = "bit_flip (was empty, added 1 byte)"
        else:
            ba = bytearray(content)
            n_flips = random.randint(1, max(1, min(8, content_len)))
            for _ in range(n_flips):
                pos = random.randrange(content_len)
                bit = random.randrange(8)
                ba[pos] ^= (1 << bit)
            new_content = bytes(ba)
            desc = f"bit_flip ({n_flips} bits)"
    elif mode == "byte_insert":
        insert_len = random.randint(1, 16)
        insert_pos = random.randint(0, content_len)
        new_content = content[:insert_pos] + os.urandom(insert_len) + content[insert_pos:]
        desc = f"byte_insert ({insert_len} bytes at {insert_pos})"
    elif mode == "byte_delete":
        if content_len < 2:
            new_content = b""
            desc = "byte_delete (cleared)"
        else:
            del_len = random.randint(1, min(16, content_len - 1))
            del_pos = random.randint(0, content_len - del_len)
            new_content = content[:del_pos] + content[del_pos + del_len:]
            desc = f"byte_delete ({del_len} bytes at {del_pos})"
    else:
        result_bytes = bytearray(content) if content else bytearray(os.urandom(8))
        n_rounds = random.randint(2, 6)
        ops_applied = []
        for _ in range(n_rounds):
            op = random.choice(["flip", "insert", "delete", "replace"])
            if len(result_bytes) == 0:
                result_bytes = bytearray(os.urandom(4))
                ops_applied.append("refill")
                continue
            if op == "flip":
                pos = random.randrange(len(result_bytes))
                result_bytes[pos] ^= (1 << random.randrange(8))
                ops_applied.append("flip")
            elif op == "insert":
                pos = random.randint(0, len(result_bytes))
                result_bytes[pos:pos] = os.urandom(random.randint(1, 4))
                ops_applied.append("insert")
            elif op == "delete" and len(result_bytes) > 1:
                pos = random.randrange(len(result_bytes))
                del result_bytes[pos]
                ops_applied.append("delete")
            elif op == "replace":
                pos = random.randrange(len(result_bytes))
                result_bytes[pos] = random.randint(0, 255)
                ops_applied.append("replace")
        new_content = bytes(result_bytes)
        desc = f"havoc ({n_rounds} rounds: {'→'.join(ops_applied)})"

    child.content = new_content
    child.constructed = False
    return new_root, f"replace_content [{desc}] (tag 0x{child.tag:02x})"

NODE_OPS = [node_retype, node_replace_content]

ALL_OPS = TREE_OPS + NODE_OPS

def mutate_grammar(tree: DERNode) -> tuple[DERNode, str, str]:
    op = random.choice(ALL_OPS)
    try:
        new_tree, desc = op(tree)
        return new_tree, f"grammar_{op.__name__}", desc
    except (ValueError, IndexError, KeyError) as exc:
        return tree, f"grammar_{op.__name__}_failed", f"{op.__name__} failed: {exc}"

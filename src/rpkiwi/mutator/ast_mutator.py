from __future__ import annotations

import os
import random
import string

from src.rpkiwi.input.ast_node import ASTNode

BASE_WEIGHT = 0.1

def match_energy(node_path: str, energy_map: dict[str, float]) -> float:
    best = 0.0
    for energy_path, score in energy_map.items():
        if (node_path == energy_path
                or node_path.startswith(energy_path + "/")
                or energy_path.startswith(node_path + "/")):
            best = max(best, score)
    return best

def _collect_nodes_with_paths(
    root: ASTNode, max_depth: int = 8,
) -> list[tuple[ASTNode, str]]:
    result: list[tuple[ASTNode, str]] = []

    def walk(node: ASTNode, path: str, depth: int) -> None:
        if depth > max_depth:
            return
        result.append((node, path))
        for c in node.children:
            child_path = f"{path}/{c.label}" if path else c.label
            walk(c, child_path, depth + 1)

    for c in root.children:
        walk(c, c.label, 1)
    return result

def _collect_parents(root: ASTNode, max_depth: int = 6) -> list[tuple[ASTNode, int]]:
    results: list[tuple[ASTNode, int]] = []

    def walk(node: ASTNode, depth: int) -> None:
        if depth > max_depth or node.is_leaf:
            return
        for i, child in enumerate(node.children):
            results.append((node, i))
            walk(child, depth + 1)

    walk(root, 0)
    return results

def _pick_parent_child(root: ASTNode) -> tuple[ASTNode, int]:
    candidates = _collect_parents(root)
    if not candidates:
        raise ValueError("no navigable nodes")
    return random.choice(candidates)

def _pick_parent_with_n_children(root: ASTNode, min_children: int) -> ASTNode:
    candidates = _collect_parents(root)
    parents = {id(p): p for p, _i in candidates}
    eligible = [p for p in parents.values() if len(p.children) >= min_children]
    if not eligible:
        raise ValueError(f"no parent with ≥{min_children} children")
    return random.choice(eligible)

def _collect_all_nodes(root: ASTNode, max_depth: int = 8) -> list[ASTNode]:
    result: list[ASTNode] = []

    def walk(node: ASTNode, depth: int) -> None:
        if depth > max_depth:
            return
        result.append(node)
        for c in node.children:
            walk(c, depth + 1)

    walk(root, 0)
    return result

_RANDOM_LABELS = [
    "unknownExtension", "extraField", "bogusNode", "fuzzedElement",
    "testContainer", "paddingField", "reservedSlot", "duplicateEntry",
]

def _random_label() -> str:
    return random.choice(_RANDOM_LABELS)

def _random_value() -> int | str | bytes | None:
    mode = random.choice(["int", "str", "bytes", "none"])
    if mode == "int":
        return random.choice([0, 1, -1, 255, 65535, 2**31 - 1, random.randint(0, 2**32)])
    if mode == "str":
        length = random.randint(0, 32)
        return "".join(random.choices(string.ascii_letters + string.digits, k=length))
    if mode == "bytes":
        return os.urandom(random.randint(0, 64))
    return None

def tree_delete(root: ASTNode) -> tuple[ASTNode, str]:
    parent, idx = _pick_parent_child(root)
    if len(parent.children) < 2:
        raise ValueError("only child, cannot delete")
    label = parent.children[idx].label
    del parent.children[idx]
    return root, f"delete node '{label}'"

def tree_duplicate(root: ASTNode) -> tuple[ASTNode, str]:
    parent, idx = _pick_parent_child(root)
    child_copy = parent.children[idx].clone()
    label = parent.children[idx].label
    parent.children.insert(idx + 1, child_copy)
    return root, f"duplicate node '{label}'"

def tree_swap(root: ASTNode) -> tuple[ASTNode, str]:
    parent = _pick_parent_with_n_children(root, 2)
    i, j = random.sample(range(len(parent.children)), 2)
    parent.children[i], parent.children[j] = parent.children[j], parent.children[i]
    label_i = parent.children[j].label
    label_j = parent.children[i].label
    return root, f"swap siblings '{label_i}' ↔ '{label_j}'"

def tree_add(root: ASTNode) -> tuple[ASTNode, str]:
    parent, idx = _pick_parent_child(root)
    label = _random_label()
    value = _random_value()
    new_node = ASTNode(label=label, value=value)
    parent.children.insert(idx + 1, new_node)
    return root, f"add random node '{label}'"

def tree_splice(root: ASTNode) -> tuple[ASTNode, str]:
    candidates = _collect_parents(root)
    if len(candidates) < 2:
        raise ValueError("not enough nodes for splice")
    src_parent, src_idx = random.choice(candidates)
    tgt_parent, tgt_idx = random.choice(candidates)
    src_label = src_parent.children[src_idx].label
    tgt_label = tgt_parent.children[tgt_idx].label
    replacement = src_parent.children[src_idx].clone()
    tgt_parent.children[tgt_idx] = replacement
    return root, f"splice '{src_label}' → '{tgt_label}'"

def tree_nest(root: ASTNode) -> tuple[ASTNode, str]:
    parent, idx = _pick_parent_child(root)
    child = parent.children[idx]
    wrapper_label = random.choice(["wrappedSequence", "extraContainer", "nestedSet", "contextWrapper"])
    wrapper = ASTNode(label=wrapper_label, children=[child])
    parent.children[idx] = wrapper
    return root, f"nest '{child.label}' in '{wrapper_label}'"

def tree_flatten(root: ASTNode) -> tuple[ASTNode, str]:
    parent, idx = _pick_parent_child(root)
    child = parent.children[idx]
    if child.is_leaf or not child.children:
        raise ValueError("leaf node, cannot flatten")
    label = child.label
    replacement_children = child.children
    parent.children[idx:idx + 1] = replacement_children
    return root, f"flatten '{label}' ({len(replacement_children)} children inlined)"

TREE_OPS = [tree_delete, tree_duplicate, tree_swap, tree_add, tree_splice, tree_nest, tree_flatten]

_KNOWN_LABELS = [
    "contentType", "version", "digestAlgorithms", "algorithm",
    "encapContentInfo", "eContentType", "eContent", "certificates",
    "signerInfos", "asID", "ipAddrBlocks", "addressFamily",
    "address", "maxLength", "customerASID", "providers", "providerASID",
    "manifestNumber", "thisUpdate", "nextUpdate", "fileHashAlgorithm",
    "fileList", "filename", "hash", "SignedData", "ContentInfo",
    "ROAIPAddressFamily", "ROAIPAddress", "addresses", "fileEntry",
]

def node_relabel(root: ASTNode) -> tuple[ASTNode, str]:
    all_nodes = _collect_all_nodes(root)
    if not all_nodes:
        raise ValueError("no nodes")
    node = random.choice(all_nodes)
    old_label = node.label
    new_label = random.choice([l for l in _KNOWN_LABELS if l != old_label] or _KNOWN_LABELS)
    node.label = new_label
    return root, f"relabel '{old_label}' → '{new_label}'"

def node_replace_value(root: ASTNode) -> tuple[ASTNode, str]:
    all_nodes = _collect_all_nodes(root)
    leaves = [n for n in all_nodes if n.is_leaf and n.value is not None and n.value != "auto"]
    if not leaves:
        raise ValueError("no mutable leaf nodes")
    node = random.choice(leaves)
    old_val = node.value
    label = node.label

    if isinstance(old_val, int):
        mode = random.choice(["random", "zero", "max_int", "negative", "boundary"])
        if mode == "random":
            node.value = random.randint(0, 2**32)
        elif mode == "zero":
            node.value = 0
        elif mode == "max_int":
            node.value = 2**31 - 1
        elif mode == "negative":
            node.value = -random.randint(1, 2**31)
        else:
            node.value = random.choice([1, 255, 256, 65535, 65536, 2**32 - 1, 2**32])
        return root, f"replace_value '{label}': {old_val} → {node.value} ({mode})"

    if isinstance(old_val, str):
        mode = random.choice(["empty", "random", "truncate", "flip_chars"])
        if mode == "empty":
            node.value = ""
        elif mode == "random":
            node.value = "".join(random.choices(string.ascii_letters + string.digits,
                                                k=random.randint(1, 64)))
        elif mode == "truncate":
            node.value = old_val[:max(1, len(old_val) // 2)] if old_val else ""
        else:
            if old_val:
                chars = list(old_val)
                n_flips = random.randint(1, max(1, min(4, len(chars))))
                for _ in range(n_flips):
                    pos = random.randrange(len(chars))
                    chars[pos] = chr(ord(chars[pos]) ^ random.randint(1, 127))
                node.value = "".join(chars)
            else:
                node.value = "fuzzed"
        return root, f"replace_value '{label}': str ({mode})"

    if isinstance(old_val, bytes):
        mode = random.choice(["empty", "random", "truncate", "bit_flip"])
        if mode == "empty":
            node.value = b""
        elif mode == "random":
            node.value = os.urandom(random.randint(1, 64))
        elif mode == "truncate":
            node.value = old_val[:max(1, len(old_val) // 2)] if old_val else b""
        else:
            if old_val:
                ba = bytearray(old_val)
                for _ in range(random.randint(1, max(1, min(4, len(ba))))):
                    pos = random.randrange(len(ba))
                    ba[pos] ^= (1 << random.randrange(8))
                node.value = bytes(ba)
            else:
                node.value = os.urandom(4)
        return root, f"replace_value '{label}': bytes ({mode})"

    node.value = _random_value()
    return root, f"replace_value '{label}': unknown type → random"

NODE_OPS = [node_relabel, node_replace_value]

DESTRUCTIVE_OPS = [tree_delete, node_replace_value]
STRUCTURAL_OPS = [tree_swap, tree_splice]

AST_OPS = TREE_OPS + NODE_OPS

def _weighted_op(energy: float) -> callable:
    if energy >= 2.0:
        weights = [3 if op in DESTRUCTIVE_OPS else 1 for op in AST_OPS]
    elif energy < BASE_WEIGHT + 0.01:
        weights = [2 if op in STRUCTURAL_OPS else 1 for op in AST_OPS]
    else:
        weights = [1] * len(AST_OPS)
    return random.choices(AST_OPS, weights=weights, k=1)[0]

def _select_subtree(
    root: ASTNode, energy_map: dict[str, float],
) -> tuple[ASTNode, float, str]:
    candidates = _collect_nodes_with_paths(root)
    if not candidates:
        return root, 0.0, ""
    internal = [(n, p) for n, p in candidates if not n.is_leaf and n.children]
    if not internal:
        internal = candidates
    weights = []
    energies = []
    for node, path in internal:
        e = match_energy(path, energy_map)
        energies.append(e)
        weights.append(e if e > 0 else BASE_WEIGHT)
    idx = random.choices(range(len(internal)), weights=weights, k=1)[0]
    return internal[idx][0], energies[idx], internal[idx][1]

_last_selected_path: dict[str, str | None] = {"path": None}

def mutate_ast_node(
    root: ASTNode, energy_map: dict[str, float] | None = None,
) -> tuple[ASTNode, str, str]:
    new_root = root.clone()
    _last_selected_path["path"] = None

    emap = energy_map if energy_map else {}
    subtree, energy, path = _select_subtree(new_root, emap)
    _last_selected_path["path"] = path
    op = _weighted_op(energy)
    try:
        _, desc = op(subtree)
        return new_root, f"ast_{op.__name__}", desc
    except (ValueError, IndexError):
        pass

    op = random.choice(AST_OPS)
    try:
        new_root, desc = op(new_root)
        return new_root, f"ast_{op.__name__}", desc
    except (ValueError, IndexError) as exc:
        return root, f"ast_{op.__name__}_failed", str(exc)

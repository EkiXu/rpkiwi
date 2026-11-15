from __future__ import annotations

import os
import random
import string
import uuid

from src.rpkiwi.input.ast_node import ASTNode
from src.rpkiwi.mutator.ast_mutator import (
    AST_OPS,
    _select_subtree,
    _weighted_op,
    match_energy,
    mutate_ast_node,
    _last_selected_path,
)

def _find_all_by_label(root: ASTNode, label: str) -> list[ASTNode]:
    result: list[ASTNode] = []
    if root.label == label:
        result.append(root)
    for c in root.children:
        result.extend(_find_all_by_label(c, label))
    return result

def _find_content_nodes(root: ASTNode) -> list[ASTNode]:
    entries = _find_all_by_label(root, "PublishEntry")
    contents = []
    for entry in entries:
        for c in entry.children:
            if c.label not in ("uri", "content_type", "replace_hash"):
                contents.append(c)
    return contents

def _random_uuid() -> str:
    return str(uuid.uuid4())

def rrdp_session_mismatch(root: ASTNode) -> tuple[ASTNode, str]:
    sid = root.child("session_id")
    if sid is None:
        raise ValueError("no session_id")
    old = sid.value
    mode = random.choice(["new_uuid", "empty", "flip_char", "numeric"])
    if mode == "new_uuid":
        sid.value = _random_uuid()
    elif mode == "empty":
        sid.value = ""
    elif mode == "flip_char":
        if old:
            chars = list(str(old))
            pos = random.randrange(len(chars))
            chars[pos] = random.choice(string.hexdigits)
            sid.value = "".join(chars)
        else:
            sid.value = _random_uuid()
    else:
        sid.value = str(random.randint(0, 2**32))
    return root, f"session_mismatch ({mode}): {str(old)[:16]}... → {str(sid.value)[:16]}..."

def rrdp_serial_regress(root: ASTNode) -> tuple[ASTNode, str]:
    serial = root.child("serial")
    if serial is None:
        raise ValueError("no serial")
    old = serial.value if isinstance(serial.value, int) else 0
    mode = random.choice(["zero", "decrement", "negative", "far_past"])
    if mode == "zero":
        serial.value = 0
    elif mode == "decrement":
        serial.value = max(0, old - random.randint(1, 100))
    elif mode == "negative":
        serial.value = -random.randint(1, 2**31)
    else:
        serial.value = old - random.randint(1000, 1000000)
    return root, f"serial_regress ({mode}): {old} → {serial.value}"

def rrdp_serial_overflow(root: ASTNode) -> tuple[ASTNode, str]:
    serial = root.child("serial")
    if serial is None:
        raise ValueError("no serial")
    old = serial.value
    value = random.choice([2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**63 - 1, 2**63, 2**64 - 1])
    serial.value = value
    return root, f"serial_overflow: {old} → {value}"

def rrdp_hash_corrupt(root: ASTNode) -> tuple[ASTNode, str]:
    hash_nodes: list[ASTNode] = []
    for c in _find_all_by_label(root, "hash"):
        if isinstance(c.value, str) and len(c.value) >= 8:
            hash_nodes.append(c)
    if not hash_nodes:
        raise ValueError("no hash fields to corrupt")
    node = random.choice(hash_nodes)
    old = node.value
    mode = random.choice(["flip", "truncate", "empty", "random"])
    if mode == "flip":
        chars = list(old)
        for _ in range(random.randint(1, 4)):
            pos = random.randrange(len(chars))
            chars[pos] = random.choice(string.hexdigits.lower())
        node.value = "".join(chars)
    elif mode == "truncate":
        node.value = old[:len(old) // 2]
    elif mode == "empty":
        node.value = ""
    else:
        node.value = os.urandom(32).hex()
    return root, f"hash_corrupt ({mode}): {old[:16]}... → {str(node.value)[:16]}..."

def rrdp_uri_tamper(root: ASTNode) -> tuple[ASTNode, str]:
    uri_nodes = _find_all_by_label(root, "uri")
    uri_nodes = [n for n in uri_nodes if isinstance(n.value, str) and n.value]
    if not uri_nodes:
        raise ValueError("no URI fields")
    node = random.choice(uri_nodes)
    old = node.value
    mode = random.choice(["path_traversal", "wrong_domain", "empty", "duplicate_slash", "null_byte"])
    if mode == "path_traversal":
        depth = random.randint(1, 5)
        traversal = "../" * depth
        if "/" in old:
            parts = old.rsplit("/", 1)
            node.value = parts[0] + "/" + traversal + parts[1]
        else:
            node.value = traversal + old
    elif mode == "wrong_domain":
        node.value = old.replace("://", "://evil.", 1)
    elif mode == "empty":
        node.value = ""
    elif mode == "duplicate_slash":
        node.value = old.replace("/", "//", 1)
    else:
        node.value = old + "\x00"
    return root, f"uri_tamper ({mode}): {old[:30]}..."

def rrdp_remove_required(root: ASTNode) -> tuple[ASTNode, str]:
    required = ["version", "session_id", "serial"]
    candidates = [c for c in root.children if c.label in required]
    if not candidates:
        raise ValueError("no required fields to remove")
    target = random.choice(candidates)
    label = target.label
    root.children.remove(target)
    return root, f"remove_required: deleted '{label}'"

def rrdp_duplicate_entry(root: ASTNode) -> tuple[ASTNode, str]:
    for container_label in ("publishes", "withdraws", "delta_refs"):
        container = root.child(container_label)
        if container and container.children:
            entry = random.choice(container.children)
            clone = entry.clone()
            container.children.append(clone)
            return root, f"duplicate_entry: cloned {entry.label} in {container_label}"
    raise ValueError("no entries to duplicate")

PROTOCOL_OPS = [
    rrdp_session_mismatch,
    rrdp_serial_regress,
    rrdp_serial_overflow,
    rrdp_hash_corrupt,
    rrdp_uri_tamper,
    rrdp_remove_required,
    rrdp_duplicate_entry,
]

def rrdp_mutate_embedded(root: ASTNode, energy_map: dict[str, float] | None = None) -> tuple[ASTNode, str]:
    contents = _find_content_nodes(root)
    der_contents = [c for c in contents if c.children]
    if not der_contents:
        raise ValueError("no embedded DER content to mutate")
    target = random.choice(der_contents)
    new_subtree, name, desc = mutate_ast_node(target, energy_map=energy_map)

    for entry in _find_all_by_label(root, "PublishEntry"):
        for i, c in enumerate(entry.children):
            if c is target:
                entry.children[i] = new_subtree
                return root, f"mutate_embedded/{name}: {desc}"

    return root, f"mutate_embedded/{name}: {desc}"

_PROTOCOL_FIELD_LABELS = {"session_id", "serial", "version", "hash", "uri"}
_EMBEDDED_PATH_PREFIX = "publishes/PublishEntry/"

def _compute_category_weights(
    root: ASTNode, energy_map: dict[str, float],
) -> tuple[float, float, float]:
    has_embedded = bool(_find_content_nodes(root))
    if not energy_map:
        return (0.40, 0.30 if has_embedded else 0.0, 0.30)

    proto_energy = 0.0
    embed_energy = 0.0
    struct_energy = 0.0
    for path, score in energy_map.items():
        if any(seg in _PROTOCOL_FIELD_LABELS for seg in path.split("/")):
            proto_energy = max(proto_energy, score)
        elif _EMBEDDED_PATH_PREFIX in path or "content" in path:
            embed_energy = max(embed_energy, score)
        else:
            struct_energy = max(struct_energy, score)

    base_p, base_e, base_s = 0.40, 0.30 if has_embedded else 0.0, 0.30
    total = proto_energy + embed_energy + struct_energy
    if total > 0:
        base_p += proto_energy / total * 0.3
        base_e += embed_energy / total * 0.3 if has_embedded else 0.0
        base_s += struct_energy / total * 0.3
    return (base_p, base_e, base_s)

def mutate_rrdp(
    root: ASTNode, energy_map: dict[str, float] | None = None,
) -> tuple[ASTNode, str, str]:
    new_root = root.clone()
    _last_selected_path["path"] = None
    emap = energy_map if energy_map else {}

    w_proto, w_embed, w_struct = _compute_category_weights(new_root, emap)
    roll = random.random()

    if roll < w_proto:
        return _try_protocol(new_root, emap, root)
    elif roll < w_proto + w_embed:
        return _try_embedded(new_root, emap, root)
    else:
        return _try_structural(new_root, emap, root)

def _try_protocol(
    new_root: ASTNode, emap: dict, fallback_root: ASTNode,
) -> tuple[ASTNode, str, str]:
    op = random.choice(PROTOCOL_OPS)
    try:
        _, desc = op(new_root)
        _last_selected_path["path"] = desc.split("'")[1] if "'" in desc else ""
        return new_root, op.__name__, desc
    except (ValueError, IndexError):
        pass
    return _try_structural(new_root, emap, fallback_root)

def _try_embedded(
    new_root: ASTNode, emap: dict, fallback_root: ASTNode,
) -> tuple[ASTNode, str, str]:
    try:
        _, desc = rrdp_mutate_embedded(new_root, energy_map=emap)
        _last_selected_path["path"] = "publishes/PublishEntry/content"
        return new_root, "rrdp_mutate_embedded", desc
    except (ValueError, IndexError):
        pass
    return _try_protocol(new_root, emap, fallback_root)

def _try_structural(
    new_root: ASTNode, emap: dict, fallback_root: ASTNode,
) -> tuple[ASTNode, str, str]:
    subtree, energy, path = _select_subtree(new_root, emap)
    _last_selected_path["path"] = path
    op_func = _weighted_op(energy)
    try:
        _, desc = op_func(new_root)
        return new_root, f"rrdp_structural_{op_func.__name__}", desc
    except (ValueError, IndexError):
        pass
    op_func = random.choice(AST_OPS)
    try:
        new_root, desc = op_func(new_root)
        return new_root, f"rrdp_structural_{op_func.__name__}", desc
    except (ValueError, IndexError) as exc:
        return fallback_root, f"rrdp_{op_func.__name__}_failed", str(exc)

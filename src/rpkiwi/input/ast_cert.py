from __future__ import annotations

from src.rpkiwi.input.ast_node import ASTNode

def explode_ee_certificate(root: ASTNode, path: str) -> ASTNode:
    node = root.find(path)
    if node is None:
        raise KeyError(f"no node at {path!r}")
    if node.children:
        raise ValueError(f"{path!r} is already structured")
    if not isinstance(node.value, (bytes, bytearray)):
        raise ValueError(f"{path!r} has no bytes value to explode")

    from src.rpkiwi.input.ast_node import _parse_ee_cert_structured
    from src.rpkiwi.input.der_ast import DERNode

    der = DERNode.parse(bytes(node.value))
    children = _parse_ee_cert_structured(der).children
    node.children = children
    node.value = None
    return node

def collapse_ee_certificate(root: ASTNode, path: str) -> ASTNode:
    node = root.find(path)
    if node is None:
        raise KeyError(f"no node at {path!r}")
    if not node.children:
        raise ValueError(f"{path!r} is already a bytes leaf")

    from src.rpkiwi.input.ast_encoder import ast_to_der

    der = ast_to_der(node)
    node.children = []
    node.value = der
    return node

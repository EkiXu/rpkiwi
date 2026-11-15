from __future__ import annotations

from datetime import datetime, timezone

from src.rpkiwi.config import RPKIConfig
from src.rpkiwi.input.ast_node import ASTNode
from src.rpkiwi.input.resolver import ExpandContext, get as get_resolver

_CRYPTO_LABELS_DEFERRED = frozenset({
    "signatureValue",
})

def expand(ast: ASTNode, config: RPKIConfig, *, now: datetime | None = None) -> ASTNode:
    result = ast.clone()
    ctx = ExpandContext.from_rpki_config(
        config,
        now=now or datetime.now(timezone.utc).replace(microsecond=0),
    )
    ctx.extras["_root"] = result
    _expand_recursive(result, ctx)
    return result

def _expand_recursive(node: ASTNode, ctx: ExpandContext) -> None:
    if node.is_leaf and node.value == "auto":
        if node.label not in _CRYPTO_LABELS_DEFERRED:
            resolver = get_resolver(node.label)
            if resolver is not None:
                node.value = resolver.fn(node, ctx)
    if node.label == "WithdrawEntry":
        for c in node.children:
            if c.label == "withdrawTarget" and c.is_leaf:
                ctx.extras["withdraw_target_filename"] = c.value
    for child in node.children:
        _expand_recursive(child, ctx)

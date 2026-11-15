from __future__ import annotations

from datetime import timedelta

from src.rpkiwi.input.ast_node import ASTNode
from src.rpkiwi.input.resolver.context import ExpandContext
from src.rpkiwi.input.resolver.registry import register

def _utctime(dt) -> str:
    return dt.strftime("%y%m%d%H%M%SZ")

def _gentime(dt) -> str:
    return dt.strftime("%Y%m%d%H%M%SZ")

@register("notBefore")
def resolve_not_before(_node: ASTNode, ctx: ExpandContext) -> str:
    return _utctime(ctx.now)

@register("notAfter")
def resolve_not_after(_node: ASTNode, ctx: ExpandContext) -> str:
    return _utctime(ctx.now + timedelta(days=7))

@register("signingTime")
def resolve_signing_time(_node: ASTNode, ctx: ExpandContext) -> str:
    return _utctime(ctx.now)

def _is_crl_root(ctx: ExpandContext) -> bool:
    root = ctx.extras.get("_root")
    return root is not None and getattr(root, "label", "") == "CertificateRevocationList"

@register("thisUpdate")
def resolve_this_update(_node: ASTNode, ctx: ExpandContext) -> str:
    return _utctime(ctx.now) if _is_crl_root(ctx) else _gentime(ctx.now)

@register("nextUpdate")
def resolve_next_update(_node: ASTNode, ctx: ExpandContext) -> str:
    later = ctx.now + timedelta(days=1)
    if _is_crl_root(ctx):
        return _utctime(ctx.now + timedelta(days=7))
    return _gentime(later)

@register("revocationDate")
def resolve_revocation_date(_node: ASTNode, ctx: ExpandContext) -> str:
    return _utctime(ctx.now)

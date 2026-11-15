from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from src.rpkiwi.input.ast_node import ASTNode
from src.rpkiwi.input.resolver.context import ExpandContext
from src.rpkiwi.input.resolver.registry import register

_DOMAIN_TO_KEY = {
    "attacker-pp.com": "attacker",
    "victim-pp.com": "victim",
    "myta.com": "myta",
}

def _load_constants(build_dir: Path) -> dict:
    path = build_dir / "public_constants.json"
    return json.loads(path.read_text())

def _rrdp_info(ctx: ExpandContext, scenario: str = "t0") -> dict:
    constants = _load_constants(ctx.build_dir)
    pp_key = _DOMAIN_TO_KEY.get(ctx.base_domain)
    if pp_key is None:
        return {}
    pp = constants.get(pp_key, {})
    sc = pp.get(scenario, pp.get("baseline", {}))
    return sc.get("rrdp", {}).get("notification", {})

def _find_file_hash(ctx: ExpandContext, filename: str, scenario: str = "t0") -> str:
    constants = _load_constants(ctx.build_dir)
    for pp_key in ("victim", "attacker", "myta"):
        pp = constants.get(pp_key, {})
        for sc_key in (scenario, "t1", "t0", "baseline"):
            sc = pp.get(sc_key, {})
            for f in sc.get("repo_files", []):
                if f["filename"] == filename:
                    return f["sha256"]
    return ""

@register("session_id")
def resolve_session_id(_node: ASTNode, ctx: ExpandContext):
    info = _rrdp_info(ctx)
    return info.get("session_id", "")

@register("serial")
def resolve_rrdp_serial(_node: ASTNode, ctx: ExpandContext):
    info = _rrdp_info(ctx)
    base = info.get("serial", 0)
    root = ctx.extras.get("_root")
    if root is not None and root.label == "RRDPDelta":
        return base + 1
    return base

@register("hash")
def resolve_hash(_node: ASTNode, ctx: ExpandContext):
    target = ctx.extras.get("withdraw_target_filename", "")
    scenario = ctx.extras.get("withdraw_target_scenario", "t1")
    if target:
        return _find_file_hash(ctx, target, scenario)
    return ""

from __future__ import annotations

from typing import Iterable

from src.rpkiwi.input.ast_node import ASTNode
from src.rpkiwi.input.resolver.context import ExpandContext
from src.rpkiwi.input.resolver.registry import Resolver, all_resolvers, get as get_resolver

class ReconcileError(RuntimeError):
    pass

def _iter_labeled(ast: ASTNode, label: str, prefix: str = "") -> Iterable[tuple[str, ASTNode]]:
    here = f"{prefix}/{ast.label}" if prefix else ast.label
    if ast.label == label:
        yield here, ast
    for c in ast.children:
        yield from _iter_labeled(c, label, here)

def _path_contains_label(path: str, label: str) -> bool:
    return label in path.split("/")

def _topo_sort(labels: list[str]) -> list[str]:
    order: list[str] = []
    visited: set[str] = set()
    temp: set[str] = set()

    def visit(label: str) -> None:
        if label in visited:
            return
        if label in temp:
            raise ReconcileError(f"cyclic dep involving {label!r}")
        temp.add(label)
        resolver = get_resolver(label)
        if resolver is not None:
            for dep in resolver.deps:
                if dep in labels:
                    visit(dep)
        temp.discard(label)
        visited.add(label)
        order.append(label)

    for label in labels:
        visit(label)
    return order

def reconcile(
    root: ASTNode,
    touched: set[str],
    ctx: ExpandContext,
) -> None:
    if not touched:
        return

    ctx.extras["_root"] = root

    candidates: list[tuple[str, ASTNode, Resolver]] = []
    triggered_labels: list[str] = []

    for resolver in all_resolvers():
        if not resolver.deps:
            continue
        label = resolver.label
        fired = any(
            _path_contains_label(t, dep)
            for t in touched
            for dep in resolver.deps
        )
        if not fired:
            continue
        triggered_labels.append(label)
        for path, node in _iter_labeled(root, label):
            if path in touched:
                continue
            candidates.append((path, node, resolver))

    label_order = _topo_sort(triggered_labels)
    candidates.sort(key=lambda t: label_order.index(t[2].label))

    for path, node, resolver in candidates:
        try:
            new_val = resolver.fn(node, ctx)
        except Exception as e:
            raise ReconcileError(
                f"resolver {resolver.label!r} failed at {path!r}: {e}"
            ) from e
        node.value = new_val
        node.children = []


from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from src.rpkiwi.input.ast_node import ASTNode
from src.rpkiwi.input.resolver.context import ExpandContext

ResolverFn = Callable[[ASTNode, ExpandContext], Any]

@dataclass(frozen=True)
class Resolver:
    label: str
    fn: ResolverFn
    deps: tuple[str, ...] = ()

_REGISTRY: dict[str, Resolver] = {}

def register(label: str, *, deps: tuple[str, ...] = ()) -> Callable[[ResolverFn], ResolverFn]:
    def decorator(fn: ResolverFn) -> ResolverFn:
        if label in _REGISTRY:
            raise ValueError(f"resolver already registered for label={label!r}")
        _REGISTRY[label] = Resolver(label=label, fn=fn, deps=deps)
        return fn
    return decorator

def get(label: str) -> Resolver | None:
    return _REGISTRY.get(label)

def all_labels() -> list[str]:
    return sorted(_REGISTRY)

def all_resolvers() -> list[Resolver]:
    return list(_REGISTRY.values())

def clear() -> None:
    _REGISTRY.clear()

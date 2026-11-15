from __future__ import annotations

import copy

from src.rpkiwi.input.ast_node import ASTNode
from src.rpkiwi.input.resolver.context import ExpandContext
from src.rpkiwi.input.resolver.reconcile import reconcile

class MutationContext:
    def __init__(self, ast: ASTNode, ctx: ExpandContext):
        self._ast = ast
        self._ctx = ctx
        self._touched: set[str] = set()
        self._snapshot: ASTNode | None = None

    def __enter__(self) -> "MutationContext":
        self._snapshot = copy.deepcopy(self._ast)
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None:
            self._rollback()
            return False
        try:
            reconcile(self._ast, self._touched, self._ctx)
        except Exception:
            self._rollback()
            raise
        return False

    def _rollback(self) -> None:
        if self._snapshot is None:
            return
        self._ast.label    = self._snapshot.label
        self._ast.value    = self._snapshot.value
        self._ast.children = self._snapshot.children
        self._ast.signed   = self._snapshot.signed

    def set(self, path: str, value) -> None:
        node = self._ast.find(path)
        if node is None:
            raise KeyError(f"no AST node at {path!r}")
        node.children = []
        node.value    = value
        self._touched.add(self._qualify(path))

    @property
    def touched(self) -> set[str]:
        return set(self._touched)

    def _qualify(self, path: str) -> str:
        root = self._ast.label
        if path == root or path.startswith(root + "/"):
            return path
        return f"{root}/{path}"

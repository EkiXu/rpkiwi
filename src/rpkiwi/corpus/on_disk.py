from __future__ import annotations

import json
import logging
from collections import deque
from pathlib import Path
from typing import Callable

from src.rpkiwi.input.test_input import TestInput
from src.rpkiwi.state.fuzz_state import Finding

logger = logging.getLogger(__name__)

class OnDiskCorpus:
    def __init__(
        self,
        base_dir: str | Path,
        *,
        debug: bool = False,
        log: Callable[[str], None] | None = None,
    ) -> None:
        self.base_dir = Path(base_dir)
        self.queue_dir = self.base_dir / "queue"
        self.solutions_dir = self.base_dir / "solutions"
        self.debug = debug
        self.tested_dir = self.base_dir / "tested" if debug else None
        self._log = log or logger.warning
        self._queue: deque[TestInput] = deque()
        self._counter = 0

        self.queue_dir.mkdir(parents=True, exist_ok=True)
        self.solutions_dir.mkdir(parents=True, exist_ok=True)
        if self.tested_dir:
            self.tested_dir.mkdir(parents=True, exist_ok=True)

    def load_initial_seeds(self, seed_dir: Path, config) -> list[TestInput]:
        seeds = []
        meta_files = sorted(seed_dir.glob("*.meta.json"))
        for meta_path in meta_files:
            stem = meta_path.name.removesuffix(".meta.json")
            input_path = seed_dir / f"{stem}.input"
            try:
                meta = json.loads(meta_path.read_text())
                metadata = meta.get("metadata", {})
                metadata.setdefault("ir_name", stem)

                if input_path.exists():
                    data = input_path.read_bytes()
                elif "ast" in metadata and "n" in metadata["ast"]:
                    can_resign = metadata.get("can_resign", False)
                    ee_key_pem = metadata.get("ee_key_pem")
                    data = self._serialize_from_ast(metadata["ast"], config, can_resign, ee_key_pem, metadata)
                    input_path.write_bytes(data)
                    self._log(f"[*] serialized {stem}.input from AST ({len(data)} bytes)")
                else:
                    self._log(f"[!] skipping {stem}: no .input and no AST")
                    continue

                ti = TestInput(
                    data=data,
                    object_type=meta["object_type"],
                    format=meta["format"],
                    metadata=metadata,
                )
                seeds.append(ti)
                self._log(f"[+] loaded initial seed: {stem} ({len(data)} bytes)")
            except Exception as exc:
                self._log(f"[!] failed to load {meta_path}: {exc}")
        return seeds

    def load_queue(self, config=None) -> int:
        loaded = 0
        meta_files = sorted(self.queue_dir.glob("*.meta.json"))
        for meta_path in meta_files:
            stem = meta_path.name.removesuffix(".meta.json")
            input_path = self.queue_dir / f"{stem}.input"
            try:
                meta = json.loads(meta_path.read_text())
                metadata = meta.get("metadata", {})

                if input_path.exists():
                    data = input_path.read_bytes()
                elif "ast" in metadata and "n" in metadata["ast"] and config:
                    can_resign = metadata.get("can_resign", False)
                    ee_key_pem = metadata.get("ee_key_pem")
                    data = self._serialize_from_ast(metadata["ast"], config, can_resign, ee_key_pem, metadata)
                    input_path.write_bytes(data)
                else:
                    continue

                ti = TestInput(
                    data=data,
                    object_type=meta["object_type"],
                    format=meta["format"],
                    metadata=metadata,
                )
                self._queue.append(ti)
                loaded += 1
            except Exception as exc:
                self._log(f"[!] failed to load queue entry {meta_path}: {exc}")
        if loaded > 0:
            self._counter = max(self._counter, loaded)
        return loaded

    def enqueue(self, test_input: TestInput, tags: dict | None = None) -> str:
        tags = tags or {}
        stem = f"{self._counter:06d}-{test_input.object_type.lower()}"
        self._counter += 1

        input_path = self.queue_dir / f"{stem}.input"
        meta_path = self.queue_dir / f"{stem}.meta.json"

        input_path.write_bytes(test_input.data)
        meta_to_store = dict(test_input.metadata)
        meta_to_store.pop("parent_metadata", None)
        meta_path.write_text(json.dumps({
            "object_type": test_input.object_type,
            "format": test_input.format,
            "metadata": meta_to_store,
            "tags": tags,
        }, indent=2))

        self._queue.append(test_input)
        return str(input_path)

    def pop(self, object_type: str) -> TestInput | None:
        otype = object_type.upper()
        attempts = len(self._queue)
        for _ in range(attempts):
            if not self._queue:
                return None
            entry = self._queue.popleft()
            if entry.object_type == otype:
                return entry
            self._log(f"[!] queue entry is {entry.object_type}, fuzzing {otype} -- skipping")
        return None

    def queue_size(self) -> int:
        return len(self._queue)

    def save_tested(self, test_input: TestInput, tags: dict | None = None) -> str | None:
        if not self.debug or not self.tested_dir:
            return None
        tags = tags or {}
        stem = f"{self._counter:06d}-{test_input.object_type.lower()}"
        self._counter += 1

        input_path = self.tested_dir / f"{stem}.input"
        meta_path = self.tested_dir / f"{stem}.meta.json"

        input_path.write_bytes(test_input.data)
        meta_to_store = dict(test_input.metadata)
        meta_to_store.pop("parent_metadata", None)
        meta_path.write_text(json.dumps({
            "object_type": test_input.object_type,
            "format": test_input.format,
            "metadata": meta_to_store,
            "tags": tags,
        }, indent=2))
        return str(input_path)

    def save_solution(
        self,
        test_input: TestInput,
        finding: Finding,
        verdict: "OracleVerdict",
    ) -> str:
        slug = finding.mutation_name.replace(":", "_").replace(" ", "_")[:60]
        sol_name = f"{finding.iteration:06d}-{finding.classification}-{slug}"
        sol_dir = self.solutions_dir / sol_name
        sol_dir.mkdir(parents=True, exist_ok=True)

        (sol_dir / "input.bin").write_bytes(test_input.data)

        meta_to_store = dict(test_input.metadata)
        meta_to_store.pop("parent_metadata", None)
        (sol_dir / "meta.json").write_text(json.dumps({
            "object_type": test_input.object_type,
            "format": test_input.format,
            "metadata": meta_to_store,
        }, indent=2))

        (sol_dir / "verdict.json").write_text(json.dumps({
            "classification": verdict.classification,
            "reason": verdict.reason,
            "evidence": verdict.evidence,
            "validator_classes": verdict.validator_classes,
            "finding": {
                "iteration": finding.iteration,
                "mutation_name": finding.mutation_name,
                "mutation_description": finding.mutation_description,
            },
        }, indent=2))

        self._log(f"  [solution] {sol_name}/")
        return str(sol_dir)

    def save(self, finding: Finding, mutated_bytes: bytes) -> str:
        class_dir = self.base_dir / finding.classification
        class_dir.mkdir(parents=True, exist_ok=True)
        index = len(list(class_dir.glob("*.bin")))
        stem = f"{finding.iteration:06d}-{finding.mutation_name}-{index}"
        bin_path = class_dir / f"{stem}.bin"
        meta_path = class_dir / f"{stem}.json"
        bin_path.write_bytes(mutated_bytes)
        meta_path.write_text(json.dumps({
            "iteration": finding.iteration,
            "classification": finding.classification,
            "mutation_name": finding.mutation_name,
            "mutation_description": finding.mutation_description,
            "evidence": finding.evidence,
            "size": len(mutated_bytes),
        }, indent=2))
        return str(bin_path)

    @staticmethod
    def _serialize_from_ast(ast_dict: dict, config: "RPKIConfig", can_resign: bool = False,
                            ee_key_pem: str | None = None,
                            metadata: dict | None = None) -> bytes:
        from src.rpkiwi.input.ast_node import ASTNode, serialize
        from src.rpkiwi.input.rrdp_ast import RRDP_ROOT_LABELS, serialize_rrdp_from_ast
        tree = ASTNode.from_dict(ast_dict)
        if tree.has_auto():
            from src.rpkiwi.input.ast_expand import expand
            tree = expand(tree, config)
        if tree.label in RRDP_ROOT_LABELS:
            otype = {"RRDPSnapshot": "SNAPSHOT", "RRDPNotification": "NOTIFICATION", "RRDPDelta": "DELTA"}[tree.label]
            return serialize_rrdp_from_ast(tree, otype, config)
        metadata = metadata or {}
        return serialize(tree, config, can_resign=can_resign, ee_key_pem=ee_key_pem,
                         preserve_cms_digest=bool(metadata.get("preserve_cms_digest", False)),
                         preserve_cms_signature=bool(metadata.get("preserve_cms_signature", False)),
                         preserve_object_signature=bool(metadata.get("preserve_object_signature", False)))

from __future__ import annotations

from src.rpkiwi.input.der_ast import DERNode
from src.rpkiwi.input.test_input import TestInput, SERIALIZATION_KEYS
from src.rpkiwi.mutator.grammar import mutate_grammar

def _get_config(test_input: TestInput, config=None):
    if config is not None:
        return config
    from src.rpkiwi.config import attacker_config
    return attacker_config()

def mutate(test_input: TestInput, config=None) -> TestInput:
    ast_dict = test_input.metadata.get("ast")
    energy_map = test_input.metadata.get("mutate_energy", {})

    if test_input.format == "xml":
        from src.rpkiwi.input.ast_node import ASTNode
        from src.rpkiwi.input.rrdp_ast import (
            parse_rrdp_to_ast, serialize_rrdp_from_ast, is_rrdp_semantic_ast,
        )
        from src.rpkiwi.mutator.rrdp_mutator import mutate_rrdp, _last_selected_path

        cfg = _get_config(test_input, config)

        if ast_dict and is_rrdp_semantic_ast(ast_dict):
            tree = ASTNode.from_dict(ast_dict)
        else:
            tree = parse_rrdp_to_ast(test_input.data, test_input.object_type, cfg)

        work_energy = dict(energy_map) if energy_map else {}
        max_retries = 5
        for attempt in range(max_retries):
            new_tree, name, desc = mutate_rrdp(tree, energy_map=work_energy or None)
            try:
                new_data = serialize_rrdp_from_ast(new_tree, test_input.object_type, cfg)
                break
            except Exception as exc:
                failed_path = _last_selected_path.get("path")
                if attempt < max_retries - 1:
                    if failed_path and work_energy:
                        old = work_energy.get(failed_path, 0.5)
                        work_energy[failed_path] = old * 0.1
                    tree = (ASTNode.from_dict(ast_dict)
                            if ast_dict and is_rrdp_semantic_ast(ast_dict)
                            else parse_rrdp_to_ast(test_input.data, test_input.object_type, cfg))
                else:
                    name = name + "_serialize_fallback"
                    desc = f"{desc} (serialize failed after {attempt+1} attempts: {exc}, using original bytes)"
                    new_data = test_input.data
                    break

        if work_energy != energy_map:
            energy_map = work_energy
        new_ast = new_tree.to_dict()

    elif ast_dict and "n" in ast_dict:
        from src.rpkiwi.input.ast_node import ASTNode, serialize
        from src.rpkiwi.input.test_input import serialization_options
        from src.rpkiwi.mutator.ast_mutator import mutate_ast_node, _last_selected_path

        tree = ASTNode.from_dict(ast_dict)
        cfg = _get_config(test_input, config)
        work_energy = dict(energy_map) if energy_map else {}
        # Keep deliberate digest/signature faults across mutation re-signing.
        preserve = serialization_options(test_input.metadata)

        max_retries = 5
        for attempt in range(max_retries):
            new_tree, name, desc = mutate_ast_node(
                tree, energy_map=work_energy or None,
            )
            try:
                can_resign = test_input.metadata.get("can_resign", False)
                ee_key_pem = test_input.metadata.get("ee_key_pem")
                new_data = serialize(new_tree, cfg, can_resign=can_resign, ee_key_pem=ee_key_pem, **preserve)
                break
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                failed_path = _last_selected_path.get("path")
                if attempt < max_retries - 1 and failed_path:
                    old = work_energy.get(failed_path, 0.5)
                    work_energy[failed_path] = old * 0.1
                    tree = ASTNode.from_dict(ast_dict)
                else:
                    name = name + "_serialize_fallback"
                    desc = f"{desc} (serialize failed after {attempt+1} attempts: {exc}, using original bytes)"
                    new_data = test_input.data
                    break
        if work_energy != energy_map:
            energy_map = work_energy
        new_ast = new_tree.to_dict()

    else:
        if ast_dict:
            tree = DERNode.from_dict(ast_dict)
        else:
            tree = DERNode.parse(test_input.data)
        new_tree, name, desc = mutate_grammar(tree)
        new_data = new_tree.serialize()
        new_ast = new_tree.to_dict()

    new_metadata = {
        "source": "mutation",
        "mutation_name": name,
        "mutation_description": desc,
        "ast": new_ast,
        "parent_metadata": test_input.metadata,
    }
    if energy_map:
        new_metadata["mutate_energy"] = energy_map

    for key in ("ee_key_pem", "can_resign", *SERIALIZATION_KEYS):
        if key in test_input.metadata:
            new_metadata[key] = test_input.metadata[key]
        else:
            parent = test_input.metadata.get("parent_metadata", {})
            if key in parent:
                new_metadata[key] = parent[key]

    return TestInput(
        data=new_data,
        object_type=test_input.object_type,
        format=test_input.format,
        metadata=new_metadata,
    )

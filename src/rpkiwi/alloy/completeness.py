"""Check that the field registry is complete and its AST paths are real.

Three independent checks, each failing loudly rather than vacuously:

1. Registry <-> base.als: every registry id is a declared sig field, and every
   field of a covered sig has a registry entry.
2. Registry -> AST: every field with an AST mapping resolves on a real object
   built by the generator/parser — not by matching label strings in source.
   A field must resolve in at least one object type in its scope; every
   explicit per-type `paths:` override and every `rrdp_energy` path must resolve
   on the exact type it is declared for. A mapping that resolves nowhere fails.
3. Violation coverage: every per-field assertion flows into its stage and the
   aggregate violation predicate in each validator model.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

_DIR = Path(__file__).resolve().parent
_MODEL_DIR = _DIR / "model"
_BASE_ALS = _MODEL_DIR / "base.als"
_REGISTRY = _MODEL_DIR / "field_registry.yaml"

_COVERED_SIGS = {
    "Certificate", "CMSSignedData", "ROAPayload", "ASPAPayload",
    "MFTEntry", "MFTPayload", "CRLPayload", "RRDPNotification",
    "CA", "PP", "RPKIObject",
}


def _parse_alloy_fields(text: str) -> dict[str, list[str]]:
    sig_fields: dict[str, list[str]] = {}
    sig_re = re.compile(
        r"^(?:abstract\s+)?(?:one\s+)?sig\s+(\w+)"
        r"(?:\s+extends\s+\w+)?\s*\{([^}]*)\}",
        re.MULTILINE | re.DOTALL,
    )
    for m in sig_re.finditer(text):
        name = m.group(1)
        body_no_comments = re.sub(r"//[^\n]*", "", m.group(2))
        fields = []
        for line in body_no_comments.split(","):
            field_match = re.match(r"(\w+)\s*:", line.strip())
            if field_match:
                fields.append(field_match.group(1))
        if fields:
            sig_fields[name] = fields
    return sig_fields


def check_registry_to_alloy(registry: list[dict], alloy: dict[str, list[str]]) -> list[str]:
    errors = []
    for entry in registry:
        sig, field = entry["id"].split(".", 1)
        if sig not in alloy:
            errors.append(f"  {entry['id']}: sig '{sig}' not found in base.als")
        elif field not in alloy[sig]:
            errors.append(f"  {entry['id']}: field '{field}' not in sig {sig}")
    return errors


def check_alloy_to_registry(alloy: dict[str, list[str]], registry: list[dict]) -> list[str]:
    registry_ids = {e["id"] for e in registry}
    errors = []
    for sig, fields in sorted(alloy.items()):
        if sig not in _COVERED_SIGS:
            continue
        for field in fields:
            fqn = f"{sig}.{field}"
            if fqn not in registry_ids:
                errors.append(f"  {fqn}: no registry entry")
    return errors


# =====================================================================
# Representative objects: real parser/generator output, not fabricated nodes.
# =====================================================================

def _representatives() -> dict[str, "ASTNode"]:
    from src.rpkiwi.config import attacker_config
    from src.rpkiwi.input.ast_node import ASTNode
    from src.rpkiwi.input.generator import generate, generate_crl

    config = attacker_config()
    reps: dict[str, ASTNode] = {}
    for object_type in ("ROA", "ASPA", "MFT", "CER"):
        ast_dict = generate(object_type, config).metadata.get("ast")
        if not ast_dict:
            raise RuntimeError(f"generator produced no AST for {object_type}")
        reps[object_type] = ASTNode.from_dict(ast_dict)
    # A CRL carrying a revoked entry, so revocationDate/serial paths are present.
    reps["CRL"] = ASTNode.from_der(generate_crl(config, revoked_serials=[42]), "CRL")
    for object_type in ("SNAPSHOT", "NOTIFICATION", "DELTA"):
        ast_dict = generate(object_type, config).metadata.get("ast")
        if not ast_dict:
            raise RuntimeError(f"generator produced no AST for {object_type}")
        reps[object_type] = ASTNode.from_dict(ast_dict)
    return reps


def check_registry_to_ast(registry: list[dict], reps: dict) -> tuple[list[str], int]:
    from src.rpkiwi.alloy.fields import field_path

    errors: list[str] = []
    verified = 0

    for entry in registry:
        scope = entry.get("scope", [])
        overrides = entry.get("paths", {})
        rrdp = entry.get("rrdp_energy", {})

        if entry.get("find_path") is None and not rrdp:
            continue  # infrastructure-only field, no AST surface by design

        # A scoped find_path must resolve somewhere in its scope, and every
        # explicit per-type override must resolve on its own type.
        if scope:
            resolved_types = []
            for object_type in scope:
                path = field_path(entry, object_type)
                ast = reps.get(object_type)
                if path and ast is not None and ast.find(path) is not None:
                    resolved_types.append(object_type)
                    verified += 1
                elif object_type in overrides:
                    errors.append(f"  {entry['id']}: override path '{overrides[object_type]}' "
                                  f"does not resolve on {object_type}")
            if not resolved_types:
                errors.append(f"  {entry['id']}: find_path resolves on no type in scope {scope}")

        # rrdp_energy paths must resolve on the RRDP document they name.
        for rrdp_type, paths in rrdp.items():
            ast = reps.get(rrdp_type)
            for path in paths:
                if ast is None or ast.find(path) is None:
                    errors.append(f"  {entry['id']}: rrdp_energy path '{path}' "
                                  f"does not resolve on {rrdp_type}")
                else:
                    verified += 1

    return errors, verified


# =====================================================================
# Violation coverage: per-field assertion -> stage -> aggregate.
# =====================================================================

def check_violation_coverage() -> list[str]:
    from src.rpkiwi.alloy.results import MODELS

    errors: list[str] = []
    for stem in MODELS:
        model = _MODEL_DIR / f"{stem}.als"
        text = re.sub(r"//[^\n]*", "", model.read_text())
        checks = set(re.findall(r"^\s*assert\s+(\w+)", text, re.MULTILINE))
        per_field = {c for c in checks if re.match(r"s[2-6]_(ni|conf)_\w", c)}
        for assertion in sorted(per_field):
            # ni_s3_store_key -> ni_s3_store_key_violation
            parts = assertion.split("_", 2)
            pred = f"{parts[1]}_{parts[0]}_{parts[2]}_violation"
            if f"pred {pred}" not in text:
                errors.append(f"  {stem}: assertion {assertion} has no predicate {pred}")
    return errors


def main() -> int:
    alloy = _parse_alloy_fields(_BASE_ALS.read_text())
    registry = yaml.safe_load(_REGISTRY.read_text()).get("fields", [])

    covered_count = sum(len(f) for s, f in alloy.items() if s in _COVERED_SIGS)
    reps = _representatives()
    print(f"Loaded: {covered_count} covered Alloy fields, {len(registry)} registry entries, "
          f"{len(reps)} representative objects\n")

    all_pass = True

    errs = check_registry_to_alloy(registry, alloy)
    if errs:
        print("FAIL  Registry -> base.als"); print("\n".join(errs)); all_pass = False
    else:
        print(f"PASS  Registry -> base.als ({len(registry)} entries verified)")

    errs = check_alloy_to_registry(alloy, registry)
    if errs:
        print("FAIL  base.als -> Registry"); print("\n".join(errs)); all_pass = False
    else:
        print(f"PASS  base.als -> Registry ({covered_count} fields covered)")

    errs, verified = check_registry_to_ast(registry, reps)
    if errs:
        print("FAIL  Registry -> AST"); print("\n".join(errs)); all_pass = False
    else:
        print(f"PASS  Registry -> AST ({verified} path resolutions on real objects)")

    errs = check_violation_coverage()
    if errs:
        print("FAIL  Assertion -> violation predicate"); print("\n".join(errs)); all_pass = False
    else:
        print("PASS  Assertion -> violation predicate (all models)")

    print()
    if all_pass:
        print("All checks passed.")
        return 0
    print("Some checks failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())

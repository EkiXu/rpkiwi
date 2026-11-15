"""Shared field-to-AST mapping for seed generation and schema checks."""
from pathlib import Path

import yaml

REGISTRY = Path(__file__).resolve().parent / "model" / "field_registry.yaml"


def load_fields() -> dict[str, dict]:
    entries = yaml.safe_load(REGISTRY.read_text())["fields"]
    result = {entry["id"]: entry for entry in entries}
    if len(result) != len(entries):
        raise ValueError("duplicate entries in field_registry.yaml")
    return result


def field_path(entry: dict, object_type: str) -> str | None:
    if object_type not in entry.get("scope", []):
        return None
    return entry.get("paths", {}).get(object_type, entry.get("find_path"))


def energy_paths(entry: dict, object_type: str) -> list[str]:
    path = field_path(entry, object_type)
    return [path] if path else entry.get("rrdp_energy", {}).get(object_type, [])

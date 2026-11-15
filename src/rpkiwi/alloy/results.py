"""Read Alloy results without treating missing, failed or stale runs as UNSAT."""
from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MODEL_DIR = Path(__file__).resolve().parent / "model"
OUTPUT_DIR = Path(__file__).resolve().parent / "output"
MODELS = {
    "routinator": "Routinator", "rpki_client": "rpki-client", "fort": "Fort",
    "cfrpki": "OctoRPKI", "rpki_prover": "rpki-prover", "rpstir2": "rpstir2",
    "rpki_validator_3": "RIPE Validator 3",
}
# Exactly the nine obligations printed in the paper's Table 2:
#   S2 NI; S3/S4/S5/S6 Conf + NI.  The paper says confinement is
# enforced downstream of S2, so there is no S2 Conf obligation.
CELLS = ["S2-NI", "S3-NI", "S3-Conf", "S4-NI", "S4-Conf",
         "S5-NI", "S5-Conf", "S6-NI", "S6-Conf"]


class InvalidRun(ValueError):
    """The artifact does not establish a completed check of the current model."""


@dataclass(frozen=True)
class AlloyResult:
    command: str
    satisfiable: bool
    kind: str = "check"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def model_sources(model: Path) -> dict[str, str]:
    """Fingerprint the model and its local imports (e.g. topo and base)."""
    pending, seen = [model.resolve()], {}
    while pending:
        path = pending.pop()
        if path.name in seen:
            continue
        seen[path.name] = digest(path)
        code = re.sub(r"//[^\n]*", "", path.read_text())
        for name in re.findall(r"^\s*open\s+([\w/]+)", code, re.MULTILINE):
            dependency = path.parent / (name + ".als")
            if dependency.is_file():
                pending.append(dependency.resolve())
    return dict(sorted(seen.items()))


def declared_commands(model: Path) -> dict[str, str]:
    code = re.sub(r"//[^\n]*", "", model.read_text())
    pairs = re.findall(r"^\s*(check|run)\s+(\w+)\b", code, re.MULTILINE)
    commands = {name: kind for kind, name in pairs}
    if not commands or len(commands) != len(pairs):
        raise InvalidRun(f"{model.name}: missing or duplicate named Alloy commands")
    return commands


def read_receipt(path: Path) -> tuple[dict[str, Any], list[AlloyResult]]:
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise InvalidRun(f"cannot read Alloy receipt: {path}: {exc}") from exc
    return read_receipt_dict(data)


def read_receipt_dict(data: Any) -> tuple[dict[str, Any], list[AlloyResult]]:
    commands = data.get("commands") if isinstance(data, dict) else None
    if not isinstance(commands, dict) or not commands:
        raise InvalidRun("Alloy receipt has no completed commands")
    results = []
    for name, command in commands.items():
        if not isinstance(command, dict) or command.get("type") not in {"check", "run"}:
            raise InvalidRun(f"{name}: missing command type")
        if not isinstance(command.get("source"), str) or command.get("error"):
            raise InvalidRun(f"{name}: missing source or command error")
        solutions = command.get("solution", [])
        if not isinstance(solutions, list) or any(
            not isinstance(s, dict) or not isinstance(s.get("instances"), list)
            or not s["instances"] or any(not isinstance(i, dict) for i in s["instances"])
            for s in solutions
        ):
            raise InvalidRun(f"{name}: invalid solution data")
        results.append(AlloyResult(name, bool(solutions), command["type"]))
    return data, results


def witness_artifacts(data: dict, output: Path) -> dict[str, str]:
    """Require full XML instances: Alloy 6.2.0's JSON can omit live atoms."""
    artifacts = {}
    for name, command in data["commands"].items():
        for index, solution in enumerate(command.get("solution", [])):
            filename = f"{name}-solution-{index}.xml"
            path = output / filename
            try:
                root = ET.parse(path).getroot()
            except (OSError, ET.ParseError) as exc:
                raise InvalidRun(f"{filename}: missing or invalid XML witness") from exc
            instances = root.findall("instance")
            if root.tag != "alloy" or len(instances) != len(solution["instances"]):
                raise InvalidRun(f"{filename}: incomplete XML witness")
            for instance in instances:
                xml_command = instance.get("command", "").split(maxsplit=1)
                receipt_command = command["source"].split(maxsplit=1)
                if (len(xml_command) != 2 or len(receipt_command) != 2
                    or xml_command[0].lower() != receipt_command[0].lower()
                    or xml_command[1] != receipt_command[1]):
                    raise InvalidRun(f"{filename}: witness belongs to another command or scope")
                if not instance.findall("sig"):
                    raise InvalidRun(f"{filename}: witness has no signatures")
            artifacts[filename] = digest(path)
    return artifacts


def check_commands(model: Path, results: list[AlloyResult]) -> None:
    expected = declared_commands(model)
    actual = {r.command: r.kind for r in results}
    if actual != expected:
        raise InvalidRun(f"{model.name}: incomplete command set; "
                         f"missing={sorted(expected.keys() - actual.keys())}, "
                         f"extra={sorted(actual.keys() - expected.keys())}")
    for result in results:
        if result.kind == "run" and result.command == "model_satisfiable" and not result.satisfiable:
            raise InvalidRun(f"{model.name}: assumptions are inconsistent (model_satisfiable is UNSAT)")


def load_validated(model: Path, output: Path) -> tuple[dict[str, Any], list[AlloyResult]]:
    """Require a successful invocation bound to these exact sources and receipt."""
    try:
        record = json.loads((output / "run.json").read_text())
    except (OSError, ValueError) as exc:
        raise InvalidRun(f"{output}: no valid run record; rerun rpkiwi.alloy.runner") from exc
    if record.get("status") != "complete" or record.get("exit_code") != 0:
        raise InvalidRun(f"{output}: last run did not complete successfully")
    if record.get("sources") != model_sources(model):
        raise InvalidRun(f"{model.name}: stale results; model or imported sources changed")
    receipt = output / "receipt.json"
    if not receipt.exists() or record.get("receipt_sha256") != digest(receipt):
        raise InvalidRun(f"{output}: missing or changed receipt")
    data, results = read_receipt(receipt)
    check_commands(model, results)
    if record.get("witnesses") != witness_artifacts(data, output):
        raise InvalidRun(f"{output}: missing or changed witness artifacts; rerun Alloy")
    return data, results


def cell_of(name: str) -> str | None:
    match = re.match(r"s([2-6])_(ni|conf)(?:_|$)", name)
    if match:
        return f"S{match[1]}-{'NI' if match[2] == 'ni' else 'Conf'}"
    return None


def table2_row(results: list[AlloyResult]) -> dict[str, bool]:
    row, covered = {cell: False for cell in CELLS}, set()
    for result in results:
        cell = cell_of(result.command) if result.kind == "check" else None
        if cell in row:
            covered.add(cell)
            row[cell] |= result.satisfiable
    if covered != set(CELLS):
        raise InvalidRun(f"unverified Table 2 cells: {sorted(set(CELLS) - covered)}")
    return row

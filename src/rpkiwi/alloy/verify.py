"""Report only completed Alloy runs bound to the current model sources.

    python -m rpkiwi.alloy.verify --all
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .results import (
    MODELS, MODEL_DIR, OUTPUT_DIR, InvalidRun, cell_of, load_validated, table2_row,
)


def _classify(name: str) -> dict[str, str]:
    cell = cell_of(name)
    if cell:
        stage, prop = cell.split("-")
        return {"stage": stage, "property": "non-interference" if prop == "NI" else "confinement"}
    return {"stage": "all", "property": "aggregate"}


def parse_receipt(receipt_path: Path) -> list[dict[str, Any]]:
    stem = receipt_path.parent.name
    data, results = load_validated(MODEL_DIR / f"{stem}.als", receipt_path.parent)
    return [{
        "name": result.command, "kind": result.kind, **_classify(result.command),
        "result": "SAT" if result.satisfiable else "UNSAT",
        "scope": data["commands"][result.command].get("scopes", []),
    } for result in results]


def build_report(stem: str, assertions: list[dict[str, Any]]) -> dict[str, Any]:
    checks = [a for a in assertions if a["kind"] == "check"]
    sat = sum(a["result"] == "SAT" for a in checks)
    return {
        "validator": MODELS[stem], "model": stem,
        "interpretation": "Bounded audit candidates; runtime replay is required to confirm a vulnerability.",
        "assertions": assertions,
        "summary": {
            "checks": len(checks), "total_sat": sat, "total_unsat": len(checks) - sat,
            "non_interference_violations": sum(a["property"] == "non-interference" and a["result"] == "SAT" for a in checks),
            "confinement_violations": sum(a["property"] == "confinement" and a["result"] == "SAT" for a in checks),
            "satisfiability_runs": {a["name"]: a["result"] for a in assertions if a["kind"] == "run"},
        },
    }


def print_summary(report: dict[str, Any]) -> None:
    summary = report["summary"]
    print(f"{report['validator']}: {summary['total_sat']} SAT candidates, "
          f"{summary['total_unsat']} UNSAT checks within scope")
    for assertion in report["assertions"]:
        print(f"  {assertion['kind']:5s} {assertion['name']:40s} {assertion['result']}")


def verify_validator(stem: str) -> dict[str, Any]:
    output = OUTPUT_DIR / stem
    report = build_report(stem, parse_receipt(output / "receipt.json"))
    _, results = load_validated(MODEL_DIR / f"{stem}.als", output)
    report["cells"] = table2_row(results)
    report["run"] = json.loads((output / "run.json").read_text())
    (output / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print_summary(report)
    return report


def get_all_validators() -> list[str]:
    # Missing validators are errors, not silently omitted from --all.
    return list(MODELS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("models", nargs="*")
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    stems = get_all_validators() if args.all else args.models
    if not stems or any(stem not in MODELS for stem in stems):
        parser.error(f"provide --all or model names from: {', '.join(MODELS)}")
    success = True
    for stem in stems:
        try:
            verify_validator(stem)
        except (OSError, InvalidRun) as exc:
            success = False
            print(f"{stem}: ERROR: {exc}", file=sys.stderr)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

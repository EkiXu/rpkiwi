"""Run bounded audit models and report the solver's actual results.

    python -m rpkiwi.alloy.runner --all --json

SAT identifies a candidate in the manually audited abstraction, not a confirmed
implementation vulnerability. UNSAT is limited to the declared scope.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .results import (
    AlloyResult, CELLS, MODELS, MODEL_DIR, OUTPUT_DIR, InvalidRun,
    cell_of, check_commands, digest, model_sources, read_receipt, table2_row, witness_artifacts,
)

ALLOY_DIR = Path(__file__).resolve().parent
ALLOY_BIN = ALLOY_DIR / "thirdparty" / "alloy-6.2.0" / "bin" / "alloy"

def _write_record(output: Path, record: dict) -> None:
    temporary = output / "run.json.tmp"
    temporary.write_text(json.dumps(record, indent=2) + "\n")
    temporary.replace(output / "run.json")


def _run_alloy_exec(als_path: Path, output_dir: Path, timeout_seconds: int) -> list[AlloyResult]:
    output_dir.mkdir(parents=True, exist_ok=True)
    record = {"status": "running", "started_at": datetime.now(timezone.utc).isoformat()}
    # Invalidate the old run before any operation that can fail, including startup.
    _write_record(output_dir, record)
    try:
        if not ALLOY_BIN.is_file():
            raise FileNotFoundError(f"Alloy binary not found: {ALLOY_BIN}")
        sources = model_sources(als_path)
        record["sources"] = sources
        with tempfile.TemporaryDirectory(prefix=f".{als_path.stem}-", dir=output_dir.parent) as tmp:
            staging = Path(tmp) / "results"
            command = [str(ALLOY_BIN), "exec", "--force", "--type", "xml", "--output", str(staging), str(als_path.resolve())]
            process = subprocess.run(command, capture_output=True, text=True,
                                     timeout=timeout_seconds, cwd=als_path.parent)
            (output_dir / "stdout.txt").write_text(process.stdout)
            (output_dir / "stderr.txt").write_text(process.stderr)
            record["exit_code"] = process.returncode
            if process.returncode != 0:
                raise InvalidRun(f"Alloy exited {process.returncode} on {als_path.name}: "
                                 f"{process.stderr[-2000:]}")
            data, results = read_receipt(staging / "receipt.json")
            check_commands(als_path, results)
            artifacts = witness_artifacts(data, staging)
            if sources != model_sources(als_path):
                raise InvalidRun("model sources changed while Alloy was running")
            # Readers accept these files only after the complete record is published.
            for path in staging.iterdir():
                if path.is_file():
                    shutil.copy2(path, output_dir / path.name)
            record.update(status="complete", receipt_sha256=digest(output_dir / "receipt.json"),
                          alloy_sha256=digest(ALLOY_BIN), command=command, witnesses=artifacts,
                          completed_at=datetime.now(timezone.utc).isoformat())
            _write_record(output_dir, record)
            return results
    except Exception as exc:
        if isinstance(exc, subprocess.TimeoutExpired):
            for name, partial in (("stdout.txt", exc.stdout), ("stderr.txt", exc.stderr)):
                (output_dir / name).write_text(partial.decode(errors="replace") if isinstance(partial, bytes) else partial or "")
        record.update(status="error", error=str(exc), completed_at=datetime.now(timezone.utc).isoformat())
        _write_record(output_dir, record)
        raise


def _parse_receipt(receipt_path: Path) -> list[AlloyResult]:
    return read_receipt(receipt_path)[1]


def _cell_of(assertion: str) -> tuple[str, str] | None:
    cell = cell_of(assertion)
    return tuple(cell.split("-")) if cell else None


def run_model(stem: str, timeout_seconds: int = 900) -> dict[str, bool]:
    return table2_row(_run_alloy_exec(MODEL_DIR / f"{stem}.als", OUTPUT_DIR / stem, timeout_seconds))


def _fmt(row: dict[str, bool]) -> str:
    return " ".join("X" if row[cell] else "." for cell in CELLS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("models", nargs="*")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    stems = list(MODELS) if args.all or not args.models else args.models
    if any(stem not in MODELS for stem in stems):
        parser.error(f"known models: {', '.join(MODELS)}")
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    print("Bounded audit results (X = SAT candidate, . = UNSAT within scope)")
    print(f"{'model':17s} | {'  '.join(CELLS)}")
    summary, success = {}, True
    for stem in stems:
        try:
            row = run_model(stem, args.timeout)
            got = _fmt(row)
            summary[stem] = {"row": got, "cells": row, "status": "complete"}
            print(f"{MODELS[stem]:17s} | {got}")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            success = False
            summary[stem] = {"error": str(exc)}
            print(f"{MODELS[stem]}: ERROR: {exc}", file=sys.stderr)
    if args.json:
        print(json.dumps(summary, indent=2))
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

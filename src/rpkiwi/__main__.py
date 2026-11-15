from __future__ import annotations

import argparse
import json
import sys

from src.rpkiwi.config import RPKIConfig, attacker_config
from src.rpkiwi.loop import run_fuzz_loop, ALL_OBJECT_TYPES

VALID_TYPES = sorted(ALL_OBJECT_TYPES)

def _run_parse(args: argparse.Namespace) -> int:
    from pathlib import Path
    from src.rpkiwi.input.ast_node import ASTNode, print_ast

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"error: file not found: {input_path}")
        return 1

    data = input_path.read_bytes()
    otype = args.object_type.upper()

    if otype in ("SNAPSHOT", "NOTIFICATION", "DELTA"):
        from src.rpkiwi.input.xml_ast import element_to_dict, parse_xml
        tree_dict = element_to_dict(parse_xml(data))
        ast_format = "xml"
    else:
        ast = ASTNode.from_der(data, otype)
        tree_dict = ast.to_dict()
        ast_format = "astnode"
        print_ast(ast)
        print()

    out_path = Path(args.output) if args.output else input_path.with_suffix(".meta.json")
    meta = {
        "object_type": otype,
        "format": "xml" if otype in ("SNAPSHOT", "NOTIFICATION", "DELTA") else "der",
        "metadata": {
            "source": "victim_public",
            "can_resign": False,
            "parsed_from": str(input_path),
            "ast": tree_dict,
        },
    }
    import json
    out_path.write_text(json.dumps(meta, indent=2))
    print(f"[+] {otype}: {len(data)} bytes -> {out_path}")
    return 0

def _run_expand(args: argparse.Namespace) -> int:
    from pathlib import Path
    from src.rpkiwi.input.ast_node import ASTNode
    from src.rpkiwi.input.ast_expand import expand

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"error: file not found: {input_path}")
        return 1

    if args.build_dir:
        config = RPKIConfig(build_dir=args.build_dir)
    else:
        config = attacker_config()

    meta = json.loads(input_path.read_text())
    ast_dict = meta.get("metadata", {}).get("ast")
    if not ast_dict:
        print(f"error: no AST found in {input_path}")
        return 1

    ast = ASTNode.from_dict(ast_dict)
    expanded = expand(ast, config)
    meta["metadata"]["ast"] = expanded.to_dict()
    input_path.write_text(json.dumps(meta, indent=2))
    print(f"[+] expanded {input_path}")
    return 0

def _run_generate(args: argparse.Namespace) -> int:
    from pathlib import Path
    from src.rpkiwi.input.generator import generate

    if args.build_dir:
        config = RPKIConfig(build_dir=args.build_dir)
    else:
        config = attacker_config()

    otype = args.object_type.upper()
    if otype not in ALL_OBJECT_TYPES:
        print(f"error: unknown object type {args.object_type!r}")
        print(f"valid types: {', '.join(VALID_TYPES)}")
        return 1

    initial_dir = Path(args.corpus_dir) / "initial"
    initial_dir.mkdir(parents=True, exist_ok=True)

    ti = generate(otype, config)

    stem = f"000000-{otype.lower()}"
    existing = sorted(initial_dir.glob("*.meta.json"))
    if existing:
        last_stem = existing[-1].name.removesuffix(".meta.json")
        try:
            last_num = int(last_stem.split("-")[0])
            stem = f"{last_num + 1:06d}-{otype.lower()}"
        except (ValueError, IndexError):
            pass

    input_path = initial_dir / f"{stem}.input"
    meta_path = initial_dir / f"{stem}.meta.json"

    input_path.write_bytes(ti.data)
    meta_to_store = dict(ti.metadata)
    meta_to_store.pop("parent_metadata", None)
    meta_path.write_text(json.dumps({
        "object_type": ti.object_type,
        "format": ti.format,
        "metadata": meta_to_store,
    }, indent=2))

    print(f"[+] {otype}: {len(ti.data)} bytes -> {input_path}")
    print(f"    meta: {meta_path}")
    print(f"    edit meta.json to customize, then run: rpkiwi fuzz --initial-seed-folder {initial_dir}")
    return 0

def main() -> int:
    parser = argparse.ArgumentParser(prog="rpkiwi", description="RPKI fuzzer")
    sub = parser.add_subparsers(dest="command")

    parse_parser = sub.add_parser("parse", help="Parse DER/XML file into labeled ASTNode meta.json")
    parse_parser.add_argument("--input", "-i", required=True, help="Input DER/XML file path")
    parse_parser.add_argument(
        "-t", "--type", default="ROA", dest="object_type",
        help=f"Object type: {', '.join(VALID_TYPES)} (default: ROA)",
    )
    parse_parser.add_argument("--output", "-o", default=None, help="Output meta.json path (default: <input>.meta.json)")


    rmlock_parser = sub.add_parser("rmlock", help="Remove checkpoint locks to force fresh warmup on next fuzz run")
    rmlock_parser.add_argument("validator", nargs="?", default=None,
                               help="Specific validator to clear (default: all)")
    rmlock_parser.add_argument("--build-dir", default=None, help="Override build directory")

    gen_parser = sub.add_parser("generate", help="Generate baseline seed into corpus/initial/")
    gen_parser.add_argument(
        "-t", "--type", default="ROA", dest="object_type",
        help=f"Object type: {', '.join(VALID_TYPES)} (default: ROA)",
    )
    gen_parser.add_argument("--corpus-dir", default="corpus", help="Corpus output directory")
    gen_parser.add_argument("--build-dir", default=None, help="Override build directory")

    expand_parser = sub.add_parser("expand", help="Expand all auto fields in a seed meta.json")
    expand_parser.add_argument("--input", "-i", required=True, help="Input meta.json path")
    expand_parser.add_argument("--build-dir", default=None, help="Override build directory")

    fuzz_parser = sub.add_parser("fuzz", help="Run the fuzz loop")
    fuzz_parser.add_argument("--rp", default="cfrpki", help="Validator to target (default: cfrpki)")
    fuzz_parser.add_argument(
        "-t", "--type", default="ROA", dest="object_type",
        help=f"Object type to fuzz: {', '.join(VALID_TYPES)} (default: ROA)",
    )
    fuzz_parser.add_argument("--iterations", "-n", type=int, default=100, help="Number of iterations (default: 100)")
    fuzz_parser.add_argument("--corpus-dir", default="corpus", help="Corpus output directory")
    fuzz_parser.add_argument("--settle", type=float, default=2.0, help="Seconds to wait after execution (default: 2.0)")
    fuzz_parser.add_argument("--skip-baseline", action="store_true", help="Skip baseline check")
    fuzz_parser.add_argument("--no-aspa", action="store_true",
                             help="Disable ASPA: exclude .asa from publication and oracle. "
                                  "Auto-enabled for validators that don't support ASPA.")
    fuzz_parser.add_argument("--build-dir", default=None, help="Override build directory")
    fuzz_parser.add_argument("--initial-seed-folder", default=None, help="Directory with hand-written initial seed meta.json files")
    fuzz_parser.add_argument("--debug", action="store_true", help="Save all tested seeds to tested/")
    fuzz_parser.add_argument("--mode", default=None, choices=["criu", "snapshot_restart", "hot", "parallel"],
                             help="Override state manager mode. 'parallel' runs 5 validators simultaneously.")
    fuzz_parser.add_argument("--no-differential", action="store_true",
                             help="In parallel mode, disable differential feedback — only per-validator V1/V2/V3 drive corpus admission.")
    fuzz_parser.add_argument("--no-feedback", action="store_true",
                             help="Disable all corpus feedback — findings are recorded but never re-enqueued. For ablation baseline.")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1


    if args.command == "rmlock":
        from pathlib import Path
        build_dir = args.build_dir or str(Path("build"))
        lock_dir = Path(build_dir) / ".checkpoint-locks"
        if not lock_dir.exists():
            print("[*] no checkpoint locks found")
            return 0
        if args.validator:
            lock = lock_dir / f"{args.validator}.lock"
            if lock.exists():
                lock.unlink()
                print(f"[+] removed {lock}")
            else:
                print(f"[*] no lock for {args.validator}")
        else:
            removed = 0
            for lock in lock_dir.glob("*.lock"):
                lock.unlink()
                print(f"[+] removed {lock}")
                removed += 1
            if removed == 0:
                print("[*] no checkpoint locks found")
            else:
                print(f"[+] removed {removed} lock(s)")
        return 0

    if args.command == "parse":
        return _run_parse(args)

    if args.command == "expand":
        return _run_expand(args)

    if args.command == "generate":
        return _run_generate(args)

    if args.command == "fuzz":
        from src.rpkiwi.log import logger, setup as setup_log

        otype = args.object_type.upper()
        if otype not in ALL_OBJECT_TYPES:
            print(f"error: unknown object type {args.object_type!r}")
            print(f"valid types: {', '.join(VALID_TYPES)}")
            return 1

        if args.build_dir:
            config = RPKIConfig(build_dir=args.build_dir)
        else:
            config = attacker_config()

        log_label = "parallel" if args.mode == "parallel" else args.rp
        log_path = setup_log(validator=log_label)
        log_fn = logger.info

        logger.info(f"log file: {log_path}")

        if args.mode == "parallel":
            from src.rpkiwi.parallel_loop import run_parallel_fuzz_loop
            state = run_parallel_fuzz_loop(
                config,
                object_type=otype,
                iterations=args.iterations,
                corpus_dir=args.corpus_dir,
                no_aspa=args.no_aspa,
                debug=args.debug,
                no_differential=getattr(args, 'no_differential', False),
                no_feedback=getattr(args, 'no_feedback', False),
                initial_seed_folder=args.initial_seed_folder,
                logger=log_fn,
            )
        else:
            assert otype != "ASPA" or not args.no_aspa, "ASPA object type cannot be tested with --no-aspa"

            state = run_fuzz_loop(
                config,
                object_type=otype,
                validator=args.rp,
                iterations=args.iterations,
                corpus_dir=args.corpus_dir,
                settle_seconds=args.settle,
                skip_baseline=args.skip_baseline,
                no_aspa=args.no_aspa,
                initial_seed_folder=args.initial_seed_folder,
                debug=args.debug,
                mode_override=args.mode,
                logger=log_fn,
            )

        if state.findings:
            logger.info(f"\n{'='*60}")
            logger.info(f"FINDINGS ({len(state.findings)}):")
            for f in state.findings:
                logger.info(f"  [{f.iteration}] {f.classification}: {f.mutation_name}")
                if f.corpus_path:
                    logger.info(f"         saved: {f.corpus_path}")
                for e in f.evidence:
                    logger.info(f"         {e}")
            logger.info(f"{'='*60}")

        return 0 if not state.errors else 1

    return 0

if __name__ == "__main__":
    sys.exit(main())

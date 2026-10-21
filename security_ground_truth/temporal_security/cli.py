"""Portable local AST/history helpers; no model API or target-code execution."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .gumtree import summarize_pair
from .history import git_history


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    pair = commands.add_parser("describe-change", help="Match two observed Python snapshots using GumTree")
    pair.add_argument("before", type=Path)
    pair.add_argument("after", type=Path)
    pair.add_argument("--path", required=True, help="Repository-relative path recorded in the evidence")
    pair.add_argument("--event-id", required=True, help="Commit/edit/observation identifier")
    pair.add_argument("--symbol", help="Qualified Python symbol, for example Parser.load")
    pair.add_argument("--max-operations", type=int, default=24)
    pair.add_argument("--output", type=Path, required=True)

    history = commands.add_parser("prepare-history", help="Compress only immutable-cutoff Git ancestors")
    history.add_argument("--repo-cache", type=Path, required=True, help="Bare, non-shallow Git object cache")
    history.add_argument("--cutoff", required=True, help="Full 40-character base commit SHA")
    history.add_argument("--targets", type=Path, required=True, help="JSON list of {path, symbol optional}")
    history.add_argument("--repository-kind", choices=["ordinary", "masked-benchmark"], required=True,
                         help="Masked benchmark ancestors may contain withheld answers and are not exposed")
    history.add_argument("--max-pairs", type=int, default=3)
    history.add_argument("--output", type=Path, required=True)
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "describe-change":
            from ..runtime.git_history.query import GitHistoryView
            path = GitHistoryView._path(args.path)
            result = summarize_pair(args.before.read_text(), args.after.read_text(), path, args.event_id,
                                    symbol=args.symbol, max_operations=args.max_operations)
        else:
            targets = json.loads(args.targets.read_text())
            if not isinstance(targets, list) or not all(isinstance(t, dict) and isinstance(t.get("path"), str)
                                                       and (t.get("symbol") is None or isinstance(t["symbol"], str))
                                                       for t in targets):
                raise ValueError("Targets must be a JSON list of {path: string, symbol: optional string}")
            if not 1 <= args.max_pairs <= 20:
                raise ValueError("max-pairs must be between 1 and 20")
            result = git_history(args.repo_cache, args.cutoff, targets,
                                 pre_reference_allowed=args.repository_kind == "ordinary",
                                 max_pairs_per_target=args.max_pairs)
            result["repository_kind"] = args.repository_kind
        args.output.parent.mkdir(parents=True, exist_ok=True)
        # Evidence is immutable. A repeated invocation must choose another artifact path.
        with args.output.open("x") as stream:
            json.dump(result, stream, ensure_ascii=False, sort_keys=True, indent=2)
            stream.write("\n")
        print(json.dumps({"status": result["status"], "output": str(args.output)}))
        return 0 if result["status"] in {"ok", "unchanged", "available", "no_relevant_changes"} else 2
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({"status": "error", "type": type(error).__name__, "message": str(error)}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

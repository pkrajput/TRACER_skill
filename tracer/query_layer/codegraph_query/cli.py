"""CLI for the graph-narrowed query funnel."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .config import QueryConfig
from .funnel import ReasoningFunnel


def cmd_ask(args: argparse.Namespace) -> int:
    """Run the graph-narrowed funnel for one question and print the answer."""
    config = QueryConfig(
        repo_root=Path(args.repo),
        graph_db_path=Path(args.graph_db) if args.graph_db else None,
        trace_dir=Path(args.trace_dir) if args.trace_dir else None,
        embedding_model=args.embedding_model or "hash",
        neighbour_hops=args.hops,
        top_k=args.top_k,
        llm_model=args.llm_model,
    )
    with ReasoningFunnel(config) as funnel:
        result = funnel.query(
            args.question,
            anchor=args.anchor,
            top_k=args.top_k,
            use_llm=not args.no_llm,
        )

    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
        return 0

    print(f"Question: {result.question}")
    if result.anchors:
        print("\nAnchors:")
        for a in result.anchors:
            print(f"  - {a.node.qualified_name} ({a.match_reason})")
    print(f"\nNeighbourhood: {len(result.neighbourhood)} node(s)")
    print(f"Candidates gathered via node_links: {len(result.candidates)}")
    if result.ranked:
        print("\nTop ranked reasoning:")
        for i, rs in enumerate(result.ranked, 1):
            c = rs.candidate
            print(f"  {i}. score={rs.score:.3f}  step={c.step_id[:20]}…")
            print(f"     prompt: {' '.join(c.prompt.split())[:120]}")
    print("\n--- Answer ---\n")
    print(result.answer)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for ``codegraph-query``."""
    p = argparse.ArgumentParser(
        prog="codegraph-query",
        description=(
            "Graph-narrowed query funnel: find code in the graph, walk dependencies, "
            "gather linked reasoning, rank, and answer."
        ),
    )
    p.add_argument("question", help="Natural-language question about code changes.")
    p.add_argument("--repo", default=".", help="Repository root (holds .codegraph-trace/).")
    p.add_argument("--graph-db", default=None, help="Path to the code-graph SQLite DB.")
    p.add_argument("--trace-dir", default=None, help="Override .codegraph-trace directory.")
    p.add_argument(
        "--anchor",
        default=None,
        help="Explicit qualified name, symbol name, or file path (skips graph search).",
    )
    p.add_argument("--hops", type=int, default=1, help="Dependency walk depth (default 1).")
    p.add_argument("-k", "--top-k", type=int, default=5, help="Ranked steps to keep.")
    p.add_argument(
        "--embedding-model",
        default="hash",
        help="Embedding model for ranking (default hash; or all-MiniLM-L6-v2).",
    )
    p.add_argument("--llm-model", default=None, help="LiteLLM model for final answer.")
    p.add_argument("--no-llm", action="store_true", help="Template answer only (no LLM call).")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of formatted text.")
    p.set_defaults(func=cmd_ask)
    return p


def _force_utf8_output() -> None:
    """Print UTF-8 regardless of the console codepage (Windows defaults to cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point for the query funnel."""
    _force_utf8_output()
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

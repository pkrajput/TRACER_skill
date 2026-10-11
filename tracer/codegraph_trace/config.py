"""Configuration for the recording layer.

A :class:`TraceConfig` bundles every path and knob the recorder needs: the repo being
recorded, where the recording layer keeps its own data (``.codegraph-trace/``), where the
read-only code-graph SQLite lives, and which embedding model to use.
"""

from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

TRACE_DIR_NAME = ".codegraph-trace"
DEFAULT_EMBEDDING_MODEL = "all-MiniLM-L6-v2"

# Windows drive under WSL, e.g. /mnt/c/Users/... -> C:/Users/...
_WSL_DRIVE = re.compile(r"^/mnt/([a-zA-Z])/(.*)$")


class GraphDbSetupError(Exception):
    """No matching code-map DB for the current repository (or an explicit path mismatches)."""


def graph_db_setup_message(repo_root: Path) -> str:
    """Clear setup instructions when no matching code-map exists for ``repo_root``."""
    root = Path(repo_root).resolve()
    cache = _cache_dir()
    return (
        f"No code-map database found for this repository:\n"
        f"  {root}\n\n"
        f"Index it with codebase-memory-mcp first, for example:\n"
        f'  index_repository(repo_path="{root.as_posix()}", mode="fast")\n\n'
        f"Then either set --graph-db / codegraph.graphDbPath to the resulting .db\n"
        f"(under {cache}), or leave it unset so auto-discovery can match\n"
        f"projects.root_path to this repository. Never reuse another project's map."
    )


def canonical_repo_path(path: Path | str) -> str:
    """Comparable absolute path: forward slashes, WSL drives mapped, casefolded."""
    raw = str(Path(path).expanduser())
    try:
        resolved = Path(raw).resolve()
        raw = str(resolved)
    except OSError:
        raw = os.path.abspath(raw)
    raw = raw.replace("\\", "/")
    m = _WSL_DRIVE.match(raw)
    if m:
        raw = f"{m.group(1).upper()}:/{m.group(2)}"
    if len(raw) >= 2 and raw[1] == ":":
        raw = raw[0].upper() + raw[1:]
    return raw.rstrip("/").casefold()


def _looks_absolute(path: str) -> bool:
    p = (path or "").replace("\\", "/").strip()
    if not p:
        return False
    if p.startswith("/") or p.startswith("//"):
        return True
    return len(p) >= 2 and p[1] == ":"


def read_graph_root_paths(db_path: Path) -> list[str]:
    """Return ``projects.root_path`` values from a codebase-memory SQLite DB."""
    try:
        conn = sqlite3.connect(f"file:{Path(db_path).as_posix()}?mode=ro", uri=True)
    except sqlite3.Error:
        return []
    try:
        try:
            rows = conn.execute(
                "SELECT root_path FROM projects WHERE root_path IS NOT NULL AND root_path != ''"
            ).fetchall()
        except sqlite3.Error:
            return []
        return [str(r[0]) for r in rows if r and r[0]]
    finally:
        conn.close()


def graph_db_match_status(db_path: Path, repo_root: Path) -> str:
    """Classify whether ``db_path`` indexes ``repo_root``.

    Returns:
      ``"match"`` — at least one absolute ``projects.root_path`` equals the repo
      ``"mismatch"`` — absolute root_path(s) present and none equal the repo
      ``"unknown"`` — no absolute root_path (synthetic/test DBs, or unreadable)
    """
    if not Path(db_path).is_file():
        return "unknown"
    roots = read_graph_root_paths(Path(db_path))
    abs_roots = [r for r in roots if _looks_absolute(r)]
    if not abs_roots:
        return "unknown"
    target = canonical_repo_path(repo_root)
    for root in abs_roots:
        if canonical_repo_path(root) == target:
            return "match"
    return "mismatch"


def graph_db_matches_repo(db_path: Path, repo_root: Path) -> bool:
    """True only when the DB is known to index ``repo_root``."""
    return graph_db_match_status(db_path, repo_root) == "match"


def _cache_dir() -> Path:
    cache = os.environ.get("CBM_CACHE_DIR")
    if cache:
        return Path(cache)
    return Path.home() / ".cache" / "codebase-memory-mcp"


def discover_graph_db(repo_root: Optional[Path] = None) -> Optional[Path]:
    """Best-effort discovery of the code-graph SQLite DB for ``repo_root``.

    Order of precedence:
      1. ``CODEGRAPH_DB`` environment variable (only if it matches ``repo_root``).
      2. A ``*.db`` next to the repo that matches ``repo_root``.
      3. A ``*.db`` under the codebase-memory cache directory
         (``CBM_CACHE_DIR`` or ``~/.cache/codebase-memory-mcp``) that matches.

    When ``repo_root`` is set, candidates whose ``projects.root_path`` points at a
    *different* repository are skipped — never silently reuse another project's map.
    Returns ``None`` when nothing matches; callers should show
    :func:`graph_db_setup_message` rather than picking an arbitrary DB.
    """
    root = Path(repo_root).resolve() if repo_root is not None else None

    def _accept(candidate: Path) -> bool:
        if not candidate.is_file():
            return False
        if root is None:
            # Without a repo we cannot verify ownership — refuse shared-cache guesses.
            return False
        status = graph_db_match_status(candidate, root)
        if status == "mismatch":
            return False
        if status == "match":
            return True
        # unknown: allow only repo-local *.db (explicit beside the tree), not cache.
        try:
            candidate.resolve().parent.resolve()
            return candidate.resolve().parent == root
        except OSError:
            return False

    env = os.environ.get("CODEGRAPH_DB")
    if env:
        p = Path(env).expanduser()
        if _accept(p):
            return p
        # Wrong-project or missing env path: fall through; never return a mismatch.

    candidates: list[Path] = []
    if root is not None:
        candidates.extend(sorted(root.glob("*.db")))

    cache_dir = _cache_dir()
    if cache_dir.is_dir():
        candidates.extend(sorted(p for p in cache_dir.glob("*.db") if not p.name.startswith("_")))

    for c in candidates:
        if _accept(c):
            return c
    return None


def resolve_graph_db(
    repo_root: Path,
    explicit: Optional[Path] = None,
    *,
    require: bool = False,
) -> Optional[Path]:
    """Resolve the code-map DB for ``repo_root``, or raise :class:`GraphDbSetupError`.

    ``explicit`` (from ``--graph-db`` / settings) is preferred when present. A definite
    ownership mismatch always raises. Missing maps raise only when ``require`` is True.
    """
    root = Path(repo_root).resolve()
    if explicit is not None:
        path = Path(explicit).expanduser()
        if not path.is_file():
            raise GraphDbSetupError(
                f"Code-graph DB not found at {path}.\n\n{graph_db_setup_message(root)}"
            )
        status = graph_db_match_status(path, root)
        if status == "mismatch":
            roots = read_graph_root_paths(path)
            raise GraphDbSetupError(
                f"Code-map DB does not belong to this repository.\n"
                f"  repo:    {root}\n"
                f"  db:      {path}\n"
                f"  indexes: {', '.join(roots) if roots else '(unknown)'}\n\n"
                f"{graph_db_setup_message(root)}"
            )
        return path

    found = discover_graph_db(root)
    if found is not None:
        return found
    if require:
        raise GraphDbSetupError(graph_db_setup_message(root))
    return None


@dataclass
class TraceConfig:
    """All paths and knobs for one recording session.

    Attributes:
        repo_root: Root of the repository being recorded (where git runs).
        graph_db_path: Path to the read-only code-graph SQLite DB.
        embedding_model: Embedding model name. ``"hash"`` selects a deterministic, offline
            embedder useful for tests; anything else is treated as a sentence-transformers
            model name (default ``all-MiniLM-L6-v2``, switchable to e.g. ``bge-m3``).
        trace_dir: Where the recording layer stores its data (defaults to
            ``<repo_root>/.codegraph-trace``).
    """

    repo_root: Path
    graph_db_path: Optional[Path] = None
    embedding_model: str = DEFAULT_EMBEDDING_MODEL
    trace_dir: Optional[Path] = None

    def __post_init__(self) -> None:
        self.repo_root = Path(self.repo_root).resolve()
        if self.trace_dir is None:
            self.trace_dir = self.repo_root / TRACE_DIR_NAME
        else:
            self.trace_dir = Path(self.trace_dir)
        if self.graph_db_path is None:
            self.graph_db_path = discover_graph_db(self.repo_root)
        else:
            # Expand a leading ``~`` so user-home paths resolve (argparse does not do this).
            explicit = Path(self.graph_db_path).expanduser()
            # Refuse another project's map even when the path was passed explicitly.
            if explicit.is_file() and graph_db_match_status(explicit, self.repo_root) == "mismatch":
                raise GraphDbSetupError(
                    f"Code-map DB does not belong to this repository.\n"
                    f"  repo: {self.repo_root}\n"
                    f"  db:   {explicit}\n\n"
                    f"{graph_db_setup_message(self.repo_root)}"
                )
            self.graph_db_path = explicit

    # --- derived paths -------------------------------------------------
    @property
    def trace_db_path(self) -> Path:
        """Path to ``.codegraph-trace/trace.db`` under the repo root."""
        return self.trace_dir / "trace.db"

    @property
    def chroma_dir(self) -> Path:
        """Path to the ChromaDB directory under ``.codegraph-trace/``."""
        return self.trace_dir / "chroma"

    @property
    def snapshots_dir(self) -> Path:
        """Path to the per-commit snapshot JSON directory."""
        return self.trace_dir / "snapshots"

    def ensure_dirs(self) -> None:
        """Create the trace directory tree if it does not yet exist."""
        self.trace_dir.mkdir(parents=True, exist_ok=True)
        self.chroma_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

"""Read-only access to the existing code-graph SQLite database.

The code graph is produced by ``codebase-memory-mcp`` and is treated as immutable here. We
only ever read from it. Schema (confirmed via the project's ``codegraph_reader.py``):

    nodes(id INTEGER, label, name, qualified_name, file_path, start_line, end_line)
    edges(source_id, target_id, type)
    projects(name, indexed_at, root_path)

The main job of this module is :meth:`CodeGraph.resolve_nodes`: given a file and the set of
changed line ranges, return the code nodes that actually overlap those lines (every innermost
overlapping symbol - a hunk spanning several siblings links each of them - falling back to
the file node).
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Iterable, Optional

from .ast_symbols import extract_symbols, symbols_for_range
from .models import NodeRef

# Labels that represent a concrete symbol with a line span we can match against a diff hunk.
_SYMBOL_LABELS = {
    "Function",
    "Method",
    "Class",
    "Interface",
    "Enum",
    "Type",
    "Module",
    "Route",
    "Resource",
}


def normalize_path(path: str) -> str:
    """Normalize a path for comparison against code-graph ``file_path`` values."""
    p = (path or "").replace("\\", "/").strip()
    if p.startswith("./"):
        p = p[2:]
    return p


class CodeGraph:
    """A read-only handle on the code-graph SQLite DB."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        secondary_db_paths: Optional[Iterable[str | Path]] = None,
    ) -> None:
        self.db_path = Path(db_path)
        if not self.db_path.is_file():
            raise FileNotFoundError(f"Code-graph database not found: {self.db_path}")
        # Connect normally (robust across platforms, incl. Windows drive-letter paths) and
        # enforce read-only at the connection level so we can never mutate the code graph.
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA query_only = ON")

        # Secondary read-only graphs from imported repos. They let us resolve anchors that live
        # in another codebase. Their integer node ids are local to their own DB, so nodes
        # resolved from a secondary are returned with ``node_id=None`` to keep the (same-DB)
        # neighbourhood BFS from following a foreign id; cross-repo reasoning is still retrieved
        # by qualified_name via the merged node_links.
        self.secondaries: list[sqlite3.Connection] = []
        for p in secondary_db_paths or []:
            if p and Path(p).is_file():
                conn = sqlite3.connect(str(p))
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA query_only = ON")
                self.secondaries.append(conn)

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self.conn.close()
        for conn in self.secondaries:
            conn.close()

    def __enter__(self) -> "CodeGraph":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # --- node lookups --------------------------------------------------
    def _row_to_node(self, row: sqlite3.Row) -> NodeRef:
        return NodeRef(
            node_id=row["id"],
            label=row["label"],
            qualified_name=row["qualified_name"] or row["name"] or "",
            file_path=normalize_path(row["file_path"] or ""),
            start_line=row["start_line"] or 0,
            end_line=row["end_line"] or 0,
        )

    def nodes_in_file(self, file_path: str) -> list[NodeRef]:
        """All nodes whose ``file_path`` matches ``file_path`` (path-normalized).

        Tries an indexed exact match first (fast on large graphs), then falls back to a
        normalized full scan only if needed (handles backslash / ``./`` stored variants).
        """
        target = normalize_path(file_path)
        cols = "id, label, name, qualified_name, file_path, start_line, end_line"
        rows = self.conn.execute(
            f"SELECT {cols} FROM nodes WHERE file_path = ?", (target,)
        ).fetchall()
        if rows:
            return [self._row_to_node(r) for r in rows]

        rows = self.conn.execute(
            f"SELECT {cols} FROM nodes WHERE file_path IS NOT NULL"
        ).fetchall()
        return [
            self._row_to_node(r)
            for r in rows
            if normalize_path(r["file_path"] or "") == target
        ]

    def file_node(self, file_path: str) -> Optional[NodeRef]:
        """Return the ``File`` node for ``file_path`` if one exists."""
        for node in self.nodes_in_file(file_path):
            if node.label == "File":
                return node
        # Some indexes store the file under a single node that is not labelled File but whose
        # qualified_name equals the path; fall back to a synthetic ref so callers always get
        # something stable to link against.
        return None

    def resolve_nodes(
        self,
        file_path: str,
        ranges: Iterable[tuple[int, int]],
    ) -> list[NodeRef]:
        """Resolve changed line ranges in ``file_path`` to the code nodes they touched.

        For each changed hunk we keep every *innermost* symbol node whose ``[start_line,
        end_line]`` span overlaps the hunk (a hunk spanning several sibling symbols links each
        of them; a node that strictly contains another overlapping node is dropped as an outer
        container). When no symbol overlaps (e.g. a top-level edit or a file the indexer only
        tracks at file granularity), we fall back to the file node, or a synthetic file-level
        ref so the change is never silently dropped.
        """
        ranges = [(int(a), int(b)) for a, b in ranges]
        if not ranges:
            return []

        nodes = self.nodes_in_file(file_path)
        symbols = [
            n for n in nodes if n.label in _SYMBOL_LABELS and n.end_line >= n.start_line > 0
        ]

        matched: dict[str, NodeRef] = {}
        unmatched_ranges = 0
        for (lo, hi) in ranges:
            if hi < lo:
                lo, hi = hi, lo
            overlapping = [
                n for n in symbols if _overlaps(n.start_line, n.end_line, lo, hi)
            ]
            if overlapping:
                for node in _innermost(overlapping):
                    matched[node.qualified_name] = node
            else:
                unmatched_ranges += 1

        if unmatched_ranges or not matched:
            fallback = self.file_node(file_path) or self._synthetic_file_ref(file_path)
            matched.setdefault(fallback.qualified_name, fallback)

        return list(matched.values())

    def resolve_nodes_via_source(
        self,
        file_path: str,
        ranges: Iterable[tuple[int, int]],
        source: str,
        language: str,
    ) -> list[NodeRef]:
        """Resolve changed ranges using the file's *current* source, not the stale graph.

        Symbol spans are recovered from ``source`` (so brand-new symbols are visible), then
        each range is attributed to **every** innermost live symbol it overlaps - a hunk that
        spans several sibling symbols (e.g. two functions added in one edit) links each of
        them. When a symbol already exists in the code graph we reuse its node (durable
        ``node_id`` + canonical ``qualified_name`` + label); otherwise we synthesize a
        ``NodeRef`` whose ``qualified_name`` follows codebase-memory-mcp's scheme so it
        reconciles on the next re-index. Ranges with no enclosing symbol (module-level code)
        and symbol-less files fall back to the file node, so a change is never dropped.
        """
        ranges = [(int(a), int(b)) for a, b in ranges]
        if not ranges:
            return []

        symbols = extract_symbols(source, language=language)
        norm = normalize_path(file_path)
        prefix: Optional[str] = None  # resolved lazily, only when a symbol is matched

        matched: dict[str, NodeRef] = {}
        unmatched_ranges = 0
        for (lo, hi) in ranges:
            if hi < lo:
                lo, hi = hi, lo
            syms = symbols_for_range(symbols, lo, hi)
            if not syms:
                unmatched_ranges += 1
                continue
            if prefix is None:
                prefix = self.module_prefix(file_path) or ""
            for sym in syms:
                target_qn = f"{prefix}.{sym.dotted_suffix}" if prefix else sym.dotted_suffix
                node = self.find_node_by_qualified_name(target_qn)
                if node is None:
                    node = NodeRef(
                        node_id=None,
                        label=sym.kind,
                        qualified_name=target_qn,
                        file_path=norm,
                        start_line=sym.start_line,
                        end_line=sym.end_line,
                    )
                matched[node.qualified_name] = node

        if unmatched_ranges or not matched:
            fallback = self.file_node(file_path) or self._synthetic_file_ref(file_path)
            matched.setdefault(fallback.qualified_name, fallback)

        return list(matched.values())

    def find_node_by_qualified_name(self, qualified_name: str) -> Optional[NodeRef]:
        """Return the node with this exact ``qualified_name`` from any graph (primary first).

        A match found only in a secondary (imported) graph is returned with ``node_id=None`` so
        callers treat it as external and do not BFS its foreign id.
        """
        if not qualified_name:
            return None
        sql = """
            SELECT id, label, name, qualified_name, file_path, start_line, end_line
            FROM nodes WHERE qualified_name = ?
        """
        row = self.conn.execute(sql, (qualified_name,)).fetchone()
        if row:
            return self._row_to_node(row)
        for conn in self.secondaries:
            row = conn.execute(sql, (qualified_name,)).fetchone()
            if row:
                return replace(self._row_to_node(row), node_id=None)
        return None

    def search_secondary_nodes_by_name(self, name: str, limit: int = 5) -> list[NodeRef]:
        """Find symbols by short name across imported graphs (external; ``node_id=None``)."""
        if not name or not self.secondaries:
            return []
        out: list[NodeRef] = []
        for conn in self.secondaries:
            rows = conn.execute(
                """
                SELECT id, label, name, qualified_name, file_path, start_line, end_line
                FROM nodes
                WHERE name = ? AND label IN (
                    'Function','Method','Class','Interface','File','Module'
                )
                ORDER BY label, qualified_name
                LIMIT ?
                """,
                (name, limit),
            ).fetchall()
            out.extend(replace(self._row_to_node(r), node_id=None) for r in rows)
        return out[:limit]

    def module_prefix(self, file_path: str) -> Optional[str]:
        """The qualified-name prefix shared by symbols in ``file_path`` (e.g. ``proj.src.calc``).

        Prefers the file's ``File`` node qualified_name (the module path the indexer assigned),
        which is authoritative even when the indexer strips a source root. Falls back to deriving
        it from the ``projects`` name + the repo-relative path when the file is brand-new and has
        no node in the graph yet.

        codebase-memory-mcp names the ``File`` node ``<module>.__file__`` but hangs the file's
        symbols under ``<module>`` (e.g. File ``x.DiscountCalculator.__file__``, Method
        ``x.DiscountCalculator.DiscountCalculator.applyDiscount``). We strip that ``.__file__``
        sentinel leaf so a synthesized new-symbol name matches the graph's real symbol
        qualified_names and stays stable whether or not the file has been indexed yet. Without
        this, a re-index would start injecting ``.__file__`` into new-symbol names, breaking
        reconciliation with the graph and silently bypassing human provenance locks.
        """
        for node in self.nodes_in_file(file_path):
            qn = node.qualified_name or ""
            if node.label == "File" and qn and "::" not in qn:
                if qn.endswith(".__file__"):
                    qn = qn[: -len(".__file__")]
                return qn
        return self._module_prefix_from_path(file_path)

    def _module_prefix_from_path(self, file_path: str) -> Optional[str]:
        norm = normalize_path(file_path)
        # Strip the file extension from the basename only (keep any dots in directory names).
        slash = norm.rfind("/")
        base = norm[slash + 1 :]
        dot = base.rfind(".")
        if dot > 0:
            base = base[:dot]
        module = (norm[: slash + 1] + base) if slash != -1 else base
        module = module.replace("/", ".").strip(".")
        if not module:
            return None
        try:
            row = self.conn.execute("SELECT name FROM projects LIMIT 1").fetchone()
        except sqlite3.OperationalError:
            row = None
        project = row["name"] if row and row["name"] else None
        return f"{project}.{module}" if project else module

    def _synthetic_file_ref(self, file_path: str) -> NodeRef:
        """A stable file-level ref used when the index has no explicit File node."""
        norm = normalize_path(file_path)
        return NodeRef(
            node_id=None,
            label="File",
            qualified_name=f"file::{norm}",
            file_path=norm,
            start_line=0,
            end_line=0,
        )

    # --- edge fingerprint ----------------------------------------------
    def edge_fingerprint(self, node_id: Optional[int]) -> str:
        """A stable hash of a node's incident edges.

        Used to decide whether a node's edges (not just its body) actually changed. Two index
        states with the same incident ``(type, other_qualified_name)`` multiset hash equal.
        """
        if node_id is None:
            return ""
        rows = self.conn.execute(
            """
            SELECT e.type AS type, n.qualified_name AS qn, 'out' AS dir
            FROM edges e JOIN nodes n ON n.id = e.target_id
            WHERE e.source_id = ?
            UNION ALL
            SELECT e.type AS type, n.qualified_name AS qn, 'in' AS dir
            FROM edges e JOIN nodes n ON n.id = e.source_id
            WHERE e.target_id = ?
            """,
            (node_id, node_id),
        ).fetchall()
        parts = sorted(f"{r['dir']}:{r['type']}:{r['qn']}" for r in rows)
        if not parts:
            return ""
        return hashlib.sha1("\n".join(parts).encode("utf-8")).hexdigest()


def _overlaps(a_lo: int, a_hi: int, b_lo: int, b_hi: int) -> bool:
    return a_lo <= b_hi and b_lo <= a_hi


def _innermost(nodes: list[NodeRef]) -> list[NodeRef]:
    """The nodes that do not strictly contain another node in the list.

    Given the symbol nodes overlapping one hunk, this keeps the most specific ones: a class
    that contains an overlapping method is dropped (the method wins), while sibling symbols
    both spanned by the hunk are all kept. Ordered by ``start_line``.
    """

    def _contains(outer: NodeRef, inner: NodeRef) -> bool:
        return (
            outer.start_line <= inner.start_line
            and inner.end_line <= outer.end_line
            and (outer.end_line - outer.start_line) > (inner.end_line - inner.start_line)
        )

    leaves = [
        n for n in nodes if not any(o is not n and _contains(n, o) for o in nodes)
    ]
    leaves.sort(key=lambda n: (n.start_line, n.end_line - n.start_line))
    return leaves

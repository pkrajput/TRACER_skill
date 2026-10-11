"""Post-session reconciliation of the trace against a freshly re-indexed code graph.

During a session the recorder resolves changes against a graph indexed *before* the agent
ran, so brand-new symbols are recorded with ``node_id = NULL`` and a qualified name
synthesized to match codebase-memory-mcp's naming scheme (see
:meth:`codegraph_trace.codegraph.CodeGraph.resolve_nodes_via_source`). After the session the
user re-runs codebase-memory-mcp's ``index_repository`` tool on the repo; :func:`reconcile`
then reads the refreshed graph SQLite and repairs the trace:

1. **Exact backfill** - a synthesized qualified name that now exists in the graph gets its
   real integer ``node_id`` (and the graph's label/span/edge fingerprint) written back into
   ``node_links`` / ``node_signatures``.
2. **Drift repair** - when the indexer assigned a *different* qualified name than the one we
   synthesized (project prefix, source-root stripping, nested-symbol naming), the single
   unambiguous same-file/same-short-name graph node is adopted as canonical and the old name
   is rewritten across ``node_links``, ``node_signatures`` (preserving human locks),
   ``proposals`` and the co-change matrix. Ambiguous matches are never guessed - they are
   reported as unresolved instead.
3. **Chroma metadata** - best-effort: affected steps' flattened ``node_ids`` /
   ``qualified_names`` metadata is patched so semantic search filters stay accurate.

The graph itself is never written (it stays read-only); codebase-memory-mcp's output is the
single source of truth for node identity. Historical per-commit snapshots are left untouched:
they are an immutable record of what was known at record time.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .codegraph import _SYMBOL_LABELS, CodeGraph, normalize_path
from .config import TraceConfig
from .models import NodeRef
from .store.trace_db import TraceDB


class StaleGraphError(RuntimeError):
    """The code graph predates the last recorded step; a re-index is required first."""


@dataclass
class SymbolOutcome:
    """What reconciliation decided for one synthesized qualified name."""

    qualified_name: str
    action: str  # "backfill" | "rename" | "unresolved"
    node_id: Optional[int] = None
    new_qualified_name: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize one reconcile outcome for JSON output."""
        out: dict[str, Any] = {"qualified_name": self.qualified_name, "action": self.action}
        if self.node_id is not None:
            out["node_id"] = self.node_id
        if self.new_qualified_name:
            out["new_qualified_name"] = self.new_qualified_name
        if self.reason:
            out["reason"] = self.reason
        return out


@dataclass
class ReconcileResult:
    """Counts and per-symbol outcomes of one reconcile run."""

    backfilled: list[SymbolOutcome] = field(default_factory=list)
    renamed: list[SymbolOutcome] = field(default_factory=list)
    unresolved: list[SymbolOutcome] = field(default_factory=list)
    steps_updated: int = 0
    chroma_updated: int = 0
    chroma_error: Optional[str] = None
    dry_run: bool = False
    graph_indexed_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize the full reconcile result for JSON output."""
        return {
            "dry_run": self.dry_run,
            "graph_indexed_at": self.graph_indexed_at,
            "backfilled": [o.to_dict() for o in self.backfilled],
            "renamed": [o.to_dict() for o in self.renamed],
            "unresolved": [o.to_dict() for o in self.unresolved],
            "steps_updated": self.steps_updated,
            "chroma_updated": self.chroma_updated,
            "chroma_error": self.chroma_error,
        }


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    """Lenient ISO-8601 parse; returns None when the value is missing or unparseable.

    Naive timestamps are interpreted as *local* time: adapter-produced step timestamps (e.g.
    OpenHands events) carry no timezone but are wall-clock local, while the graph's
    ``indexed_at`` is UTC-suffixed. Assuming UTC for naive values would push local steps hours
    into the future and make a genuinely fresh re-index look stale.
    """
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.astimezone()  # naive -> aware, assuming local wall-clock time
    return dt


def _graph_indexed_at(graph: CodeGraph) -> Optional[str]:
    try:
        row = graph.conn.execute("SELECT indexed_at FROM projects LIMIT 1").fetchone()
    except Exception:
        return None
    return row["indexed_at"] if row else None


def _latest_step_timestamp(db: TraceDB) -> Optional[str]:
    row = db.conn.execute(
        "SELECT MAX(timestamp) AS t FROM steps WHERE source_repo IS NULL"
    ).fetchone()
    return row["t"] if row else None


def _short_name(qualified_name: str) -> str:
    return qualified_name.rsplit(".", 1)[-1]


def _overlaps(a_lo: int, a_hi: int, b_lo: int, b_hi: int) -> bool:
    return a_lo <= b_hi and b_lo <= a_hi


def reconcile(
    config: TraceConfig,
    *,
    dry_run: bool = False,
    force: bool = False,
    enable_embeddings: bool = True,
) -> ReconcileResult:
    """Repair the trace against the (re-indexed) code graph. See the module docstring.

    Raises :class:`StaleGraphError` when the graph predates the last recorded step and
    ``force`` is not set, and :class:`FileNotFoundError` when there is no graph DB at all.
    """
    if config.graph_db_path is None or not Path(config.graph_db_path).is_file():
        raise FileNotFoundError(
            f"Code-graph database not found: {config.graph_db_path}. Index the repo with "
            f'codebase-memory-mcp first: index_repository(repo_path="{config.repo_root}", '
            f'mode="fast")'
        )

    graph = CodeGraph(config.graph_db_path)
    db = TraceDB(config.trace_db_path)
    try:
        result = ReconcileResult(dry_run=dry_run)
        result.graph_indexed_at = _graph_indexed_at(graph)

        latest_step = _latest_step_timestamp(db)
        indexed_dt = _parse_ts(result.graph_indexed_at)
        latest_dt = _parse_ts(latest_step)
        if not force and indexed_dt is not None and latest_dt is not None and indexed_dt < latest_dt:
            raise StaleGraphError(
                f"Code graph at {config.graph_db_path} was indexed at "
                f"{result.graph_indexed_at}, before the last recorded step ({latest_step}). "
                f"Re-index with codebase-memory-mcp first:\n"
                f'    index_repository(repo_path="{config.repo_root}", mode="fast")\n'
                f"then re-run reconcile (or pass --force to reconcile against this graph)."
            )

        pending = [
            row["qualified_name"]
            for row in db.conn.execute(
                """
                SELECT DISTINCT qualified_name FROM node_links
                WHERE node_id IS NULL
                  AND source_repo IS NULL
                  AND qualified_name NOT LIKE 'file::%'
                ORDER BY qualified_name
                """
            ).fetchall()
        ]

        # Decide every outcome first so --dry-run reports the full plan without writing.
        plan: list[tuple[SymbolOutcome, Optional[NodeRef]]] = []
        for qn in pending:
            node = graph.find_node_by_qualified_name(qn)
            if node is not None and node.node_id is not None:
                plan.append(
                    (SymbolOutcome(qualified_name=qn, action="backfill", node_id=node.node_id), node)
                )
                continue
            outcome, target = _plan_drift_repair(db, graph, qn)
            plan.append((outcome, target))

        for outcome, _ in plan:
            {
                "backfill": result.backfilled,
                "rename": result.renamed,
                "unresolved": result.unresolved,
            }[outcome.action].append(outcome)

        if dry_run:
            return result

        # Collect affected steps before rewriting (renames change the lookup key).
        affected_steps: set[str] = set()
        for outcome, _ in plan:
            if outcome.action == "unresolved":
                continue
            rows = db.conn.execute(
                "SELECT DISTINCT step_id FROM node_links "
                "WHERE qualified_name = ? AND source_repo IS NULL",
                (outcome.qualified_name,),
            ).fetchall()
            affected_steps.update(r["step_id"] for r in rows)

        for outcome, node in plan:
            if outcome.action == "backfill" and node is not None:
                _apply_backfill(db, graph, outcome.qualified_name, node)
            elif outcome.action == "rename" and node is not None:
                _apply_rename(db, graph, outcome.qualified_name, node)
        db.conn.commit()

        result.steps_updated = len(affected_steps)
        if enable_embeddings and affected_steps:
            updated, error = _update_chroma_metadata(config, db, sorted(affected_steps))
            result.chroma_updated = updated
            result.chroma_error = error
        return result
    finally:
        graph.close()
        db.close()


def _plan_drift_repair(
    db: TraceDB, graph: CodeGraph, qualified_name: str
) -> tuple[SymbolOutcome, Optional[NodeRef]]:
    """Find the single unambiguous graph node this synthesized name drifted from.

    Candidates share the file and the short (last dotted segment) name; the recorded span from
    ``node_signatures`` breaks ties. Anything still ambiguous is reported, never guessed.
    """
    sig = db.get_signature(qualified_name)
    file_path = (sig or {}).get("file_path")
    if not file_path:
        row = db.conn.execute(
            "SELECT file_path FROM node_links "
            "WHERE qualified_name = ? AND source_repo IS NULL LIMIT 1",
            (qualified_name,),
        ).fetchone()
        file_path = row["file_path"] if row else None
    if not file_path:
        return (
            SymbolOutcome(qualified_name, "unresolved", reason="no recorded file path"),
            None,
        )

    short = _short_name(qualified_name)
    candidates = [
        n
        for n in graph.nodes_in_file(file_path)
        if n.node_id is not None
        and n.label in _SYMBOL_LABELS
        and _short_name(n.qualified_name) == short
        and n.qualified_name != qualified_name
    ]
    if len(candidates) > 1 and sig and (sig.get("start_line") or 0) > 0:
        lo, hi = int(sig["start_line"]), int(sig["end_line"] or sig["start_line"])
        overlapping = [
            n for n in candidates if _overlaps(n.start_line, n.end_line, lo, hi)
        ]
        if overlapping:
            candidates = overlapping

    if not candidates:
        return (
            SymbolOutcome(
                qualified_name,
                "unresolved",
                reason=f"no node named '{short}' in {normalize_path(file_path)} in the graph",
            ),
            None,
        )
    if len(candidates) > 1:
        names = ", ".join(sorted(n.qualified_name for n in candidates))
        return (
            SymbolOutcome(
                qualified_name,
                "unresolved",
                reason=f"ambiguous: {len(candidates)} candidates ({names})",
            ),
            None,
        )
    node = candidates[0]
    return (
        SymbolOutcome(
            qualified_name,
            "rename",
            node_id=node.node_id,
            new_qualified_name=node.qualified_name,
        ),
        node,
    )


def _apply_backfill(db: TraceDB, graph: CodeGraph, qualified_name: str, node: NodeRef) -> None:
    """Write the real node id (and the graph's label/span/fingerprint) for an exact match."""
    db.conn.execute(
        "UPDATE node_links SET node_id = ?, label = ? "
        "WHERE qualified_name = ? AND source_repo IS NULL AND node_id IS NULL",
        (node.node_id, node.label, qualified_name),
    )
    _refresh_signature(db, graph, qualified_name, node)


def _apply_rename(db: TraceDB, graph: CodeGraph, old_qn: str, node: NodeRef) -> None:
    """Adopt the graph's canonical qualified name for a drifted synthesized one."""
    new_qn = node.qualified_name

    # node_links: drop rows that would collide on the (step_id, qualified_name) PK, then rename.
    db.conn.execute(
        """
        DELETE FROM node_links WHERE qualified_name = ? AND source_repo IS NULL
          AND step_id IN (SELECT step_id FROM node_links WHERE qualified_name = ?)
        """,
        (old_qn, new_qn),
    )
    db.conn.execute(
        "UPDATE node_links SET qualified_name = ?, node_id = ?, label = ? "
        "WHERE qualified_name = ? AND source_repo IS NULL",
        (new_qn, node.node_id, node.label, old_qn),
    )

    # node_signatures: merge the old row into the new name, preserving human locks from either.
    old_sig = db.get_signature(old_qn)
    new_sig = db.get_signature(new_qn)
    db.conn.execute("DELETE FROM node_signatures WHERE qualified_name = ?", (old_qn,))
    if old_sig or new_sig:
        _refresh_signature(db, graph, new_qn, node, merge_from=(old_sig, new_sig))

    db.conn.execute(
        "UPDATE proposals SET qualified_name = ? WHERE qualified_name = ?", (new_qn, old_qn)
    )
    _rename_co_change(db, old_qn, new_qn)


def _refresh_signature(
    db: TraceDB,
    graph: CodeGraph,
    qualified_name: str,
    node: NodeRef,
    merge_from: Optional[tuple[Optional[dict], Optional[dict]]] = None,
) -> None:
    """Upsert a signature with the graph's authoritative label/span/edge fingerprint.

    ``merge_from`` carries (old, new) signature rows for a rename; lock/author/last_step_id
    provenance survives, with a human lock from either side winning.
    """
    if merge_from is None:
        existing = db.get_signature(qualified_name)
        sigs = [existing] if existing else []
        if not sigs:
            return  # never recorded a signature (e.g. links only); nothing to refresh
    else:
        sigs = [s for s in merge_from if s]

    locked = any(int(s.get("locked") or 0) for s in sigs)
    author = "human" if any((s.get("author") or "") == "human" for s in sigs) else (
        next((s.get("author") for s in sigs if s.get("author")), None) or "agent"
    )
    last_step_id = next((s.get("last_step_id") for s in sigs if s.get("last_step_id")), None)

    db.upsert_signature(
        qualified_name=qualified_name,
        file_path=node.file_path,
        label=node.label,
        start_line=node.start_line,
        end_line=node.end_line,
        edge_fingerprint=graph.edge_fingerprint(node.node_id),
        step_id=last_step_id or "",
        author=author,
        locked=locked,
    )


def _rename_co_change(db: TraceDB, old_qn: str, new_qn: str) -> None:
    """Rewrite the co-change matrix, re-canonicalizing pair ordering and merging on collision."""
    rows = db.conn.execute(
        "SELECT * FROM co_change WHERE qn_a = ? OR qn_b = ?", (old_qn, old_qn)
    ).fetchall()
    for r in rows:
        other = r["qn_b"] if r["qn_a"] == old_qn else r["qn_a"]
        db.conn.execute(
            "DELETE FROM co_change WHERE qn_a = ? AND qn_b = ?", (r["qn_a"], r["qn_b"])
        )
        if other == new_qn:
            continue  # a symbol never co-changes with itself; the pair collapses
        a, b = sorted((new_qn, other))
        db.conn.execute(
            """
            INSERT INTO co_change (qn_a, qn_b, count, last_step_id, last_seq, source_repo)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(qn_a, qn_b) DO UPDATE SET
                count = count + excluded.count,
                last_step_id = excluded.last_step_id,
                last_seq = excluded.last_seq
            """,
            (a, b, r["count"], r["last_step_id"], r["last_seq"], r["source_repo"]),
        )

    events = db.conn.execute(
        "SELECT * FROM co_change_events WHERE qn_a = ? OR qn_b = ?", (old_qn, old_qn)
    ).fetchall()
    for r in events:
        other = r["qn_b"] if r["qn_a"] == old_qn else r["qn_a"]
        db.conn.execute(
            "DELETE FROM co_change_events WHERE step_id = ? AND qn_a = ? AND qn_b = ?",
            (r["step_id"], r["qn_a"], r["qn_b"]),
        )
        if other == new_qn:
            continue
        a, b = sorted((new_qn, other))
        db.conn.execute(
            "INSERT OR IGNORE INTO co_change_events (step_id, qn_a, qn_b) VALUES (?, ?, ?)",
            (r["step_id"], a, b),
        )


def _update_chroma_metadata(
    config: TraceConfig, db: TraceDB, step_ids: list[str]
) -> tuple[int, Optional[str]]:
    """Best-effort: patch affected steps' flattened node metadata in ChromaDB.

    A failure here (missing dependency, absent collection, ...) never loses the SQLite repair;
    it is returned as an error string instead.
    """
    try:
        from .store.chroma_store import ChromaStore

        chroma = ChromaStore(config.chroma_dir, config.embedding_model)
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"

    updated = 0
    try:
        for step_id in step_ids:
            rows = db.conn.execute(
                "SELECT node_id, qualified_name, file_path FROM node_links WHERE step_id = ?",
                (step_id,),
            ).fetchall()
            node_ids = [r["node_id"] for r in rows if r["node_id"] is not None]
            qns = [r["qualified_name"] for r in rows]
            files = sorted({r["file_path"] for r in rows if r["file_path"]})
            if chroma.update_step_node_metadata(
                step_id, node_ids=node_ids, qualified_names=qns, file_paths=files
            ):
                updated += 1
    except Exception as exc:
        return updated, f"{type(exc).__name__}: {exc}"
    return updated, None

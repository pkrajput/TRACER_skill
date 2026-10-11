"""Find anchor nodes in the code graph and walk their dependency neighbourhood."""

from __future__ import annotations

import re
import sqlite3
from typing import Iterable, Optional

from codegraph_trace.codegraph import CodeGraph, normalize_path
from codegraph_trace.models import NodeRef

from .models import AnchorNode

_SYMBOL_LABELS = {
    "Function", "Method", "Class", "Interface", "Enum", "Type", "Module", "Route", "Resource", "File",
}

# Edge types that define structural / behavioural neighbourhood.
_DEFAULT_EDGE_TYPES = ("CALLS", "IMPORTS", "DEFINES", "REFERENCES", "EXTENDS", "IMPLEMENTS", "CONTAINS")

_STOPWORDS = {
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "must", "shall", "can", "need", "dare",
    "ought", "used", "to", "of", "in", "for", "on", "with", "at", "by",
    "from", "up", "about", "into", "through", "during", "before", "after",
    "above", "below", "between", "out", "off", "over", "under", "again",
    "further", "then", "once", "here", "there", "when", "where", "why",
    "how", "all", "each", "few", "more", "most", "other", "some", "such",
    "no", "nor", "not", "only", "own", "same", "so", "than", "too", "very",
    "just", "and", "but", "if", "or", "because", "as", "until", "while",
    "what", "which", "who", "whom", "this", "that", "these", "those", "it",
    "its", "my", "your", "his", "her", "their", "our", "me", "him", "them",
    "us", "you", "i", "we", "they", "he", "she", "change", "changed", "break",
    "breaks", "function", "file", "code", "why", "what", "might", "would",
}


def _tokens_from_question(question: str) -> list[str]:
    """Pull searchable tokens from a natural-language question."""
    raw = re.findall(r"[A-Za-z_][A-Za-z0-9_./-]*", question or "")
    out: list[str] = []
    seen: set[str] = set()
    for tok in raw:
        low = tok.lower()
        if low in _STOPWORDS or len(low) < 2:
            continue
        if low not in seen:
            seen.add(low)
            out.append(tok)
    return out


def _row_to_node(row: sqlite3.Row) -> NodeRef:
    return NodeRef(
        node_id=row["id"],
        label=row["label"],
        qualified_name=row["qualified_name"] or row["name"] or "",
        file_path=normalize_path(row["file_path"] or ""),
        start_line=row["start_line"] or 0,
        end_line=row["end_line"] or 0,
    )


class GraphNavigator:
    """Read-only graph search and neighbourhood expansion."""

    def __init__(self, graph: CodeGraph) -> None:
        self.graph = graph

    def find_anchors(
        self,
        question: str,
        *,
        explicit: Optional[str] = None,
        limit: int = 5,
    ) -> list[AnchorNode]:
        """Locate entry-point nodes from an explicit target or the question text."""
        if explicit:
            hits = self._resolve_explicit(explicit)
            if hits:
                return hits[:limit]

        tokens = _tokens_from_question(question)
        if not tokens:
            return []

        scored: dict[str, tuple[NodeRef, int, str]] = {}
        for token in tokens:
            for node, score, reason in self._search_token(token):
                prev = scored.get(node.qualified_name)
                if prev is None or score > prev[1]:
                    scored[node.qualified_name] = (node, score, reason)

        ranked = sorted(scored.values(), key=lambda x: (-x[1], x[0].qualified_name))
        return [AnchorNode(node=n, match_reason=r) for n, _, r in ranked[:limit]]

    def neighbourhood(
        self,
        anchors: Iterable[NodeRef],
        *,
        hops: int = 1,
        edge_types: tuple[str, ...] = _DEFAULT_EDGE_TYPES,
    ) -> list[NodeRef]:
        """BFS over incoming/outgoing edges to collect the local dependency neighbourhood."""
        if hops < 0:
            hops = 0

        seen: dict[str, NodeRef] = {}
        frontier: list[tuple[NodeRef, int]] = []

        for anchor in anchors:
            seen[anchor.qualified_name] = anchor
            if anchor.node_id is not None:
                frontier.append((anchor, 0))

        while frontier:
            node, depth = frontier.pop(0)
            if depth >= hops or node.node_id is None:
                continue
            for neighbour in self._neighbours(node.node_id, edge_types):
                if neighbour.qualified_name not in seen:
                    seen[neighbour.qualified_name] = neighbour
                    if neighbour.node_id is not None and depth + 1 < hops:
                        frontier.append((neighbour, depth + 1))

        return list(seen.values())

    # --- internal -------------------------------------------------------
    def _resolve_explicit(self, target: str) -> list[AnchorNode]:
        target = target.strip()
        norm = normalize_path(target)

        # Exact qualified name (checks imported graphs too).
        node = self.graph.find_node_by_qualified_name(target)
        if node is not None:
            return [AnchorNode(node=node, match_reason="explicit qualified_name")]

        # File path.
        if "/" in norm or "\\" in norm or norm.endswith(".py"):
            nodes = self.graph.nodes_in_file(norm)
            if nodes:
                symbols = [n for n in nodes if n.label in _SYMBOL_LABELS and n.label != "File"]
                pick = symbols or nodes
                return [
                    AnchorNode(node=n, match_reason=f"explicit file path {norm}")
                    for n in pick[:3]
                ]

        # Short name (function/class name).
        rows = self.graph.conn.execute(
            """
            SELECT id, label, name, qualified_name, file_path, start_line, end_line
            FROM nodes WHERE name = ? AND label IN (
                'Function','Method','Class','Interface','File','Module'
            )
            ORDER BY label, qualified_name
            LIMIT 5
            """,
            (target,),
        ).fetchall()
        if rows:
            return [
                AnchorNode(node=_row_to_node(r), match_reason=f"explicit name {target}")
                for r in rows
            ]
        # Fall back to imported graphs so a symbol that lives in another repo can be anchored.
        return [
            AnchorNode(node=n, match_reason=f"explicit name {target} (imported)")
            for n in self.graph.search_secondary_nodes_by_name(target)
        ]

    def _search_token(self, token: str) -> list[tuple[NodeRef, int, str]]:
        hits: list[tuple[NodeRef, int, str]] = []
        low = token.lower()

        # FTS when available.
        if self._has_fts():
            try:
                fts_query = f'"{token}"*' if len(token) > 2 else token
                rows = self.graph.conn.execute(
                    """
                    SELECT n.id, n.label, n.name, n.qualified_name, n.file_path,
                           n.start_line, n.end_line
                    FROM nodes_fts fts
                    JOIN nodes n ON n.id = fts.rowid
                    WHERE nodes_fts MATCH ?
                    LIMIT 10
                    """,
                    (fts_query,),
                ).fetchall()
                for row in rows:
                    node = _row_to_node(row)
                    hits.append((node, 80, f"fts match on {token!r}"))
            except sqlite3.OperationalError:
                pass

        # Name / qualified_name / file_path LIKE fallback.
        like = f"%{low}%"
        rows = self.graph.conn.execute(
            """
            SELECT id, label, name, qualified_name, file_path, start_line, end_line
            FROM nodes
            WHERE lower(name) = ?
               OR lower(qualified_name) LIKE ?
               OR lower(file_path) LIKE ?
            LIMIT 15
            """,
            (low, like, like),
        ).fetchall()
        for row in rows:
            node = _row_to_node(row)
            score = 40
            reason = f"substring match on {token!r}"
            if (row["name"] or "").lower() == low:
                score = 100
                reason = f"exact name {token!r}"
            elif node.label in ("Function", "Method", "Class"):
                score = 70
            hits.append((node, score, reason))

        return hits

    def _has_fts(self) -> bool:
        row = self.graph.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='nodes_fts'"
        ).fetchone()
        return row is not None

    def _neighbours(self, node_id: int, edge_types: tuple[str, ...]) -> list[NodeRef]:
        placeholders = ",".join("?" * len(edge_types))
        params = (node_id, *edge_types, node_id, *edge_types)
        rows = self.graph.conn.execute(
            f"""
            SELECT n.id, n.label, n.name, n.qualified_name, n.file_path,
                   n.start_line, n.end_line
            FROM edges e
            JOIN nodes n ON n.id = e.target_id
            WHERE e.source_id = ? AND e.type IN ({placeholders})
            UNION
            SELECT n.id, n.label, n.name, n.qualified_name, n.file_path,
                   n.start_line, n.end_line
            FROM edges e
            JOIN nodes n ON n.id = e.source_id
            WHERE e.target_id = ? AND e.type IN ({placeholders})
            """,
            params,
        ).fetchall()
        return [_row_to_node(r) for r in rows]

    def callers(self, node_id: int, limit: int = 20) -> list[NodeRef]:
        """Nodes that call/reference this node (useful for impact analysis)."""
        rows = self.graph.conn.execute(
            """
            SELECT n.id, n.label, n.name, n.qualified_name, n.file_path,
                   n.start_line, n.end_line
            FROM edges e
            JOIN nodes n ON n.id = e.source_id
            WHERE e.target_id = ? AND e.type IN ('CALLS', 'REFERENCES', 'IMPORTS')
            LIMIT ?
            """,
            (node_id, limit),
        ).fetchall()
        return [_row_to_node(r) for r in rows]

    def callees(self, node_id: int, limit: int = 20) -> list[NodeRef]:
        """Nodes this node depends on."""
        rows = self.graph.conn.execute(
            """
            SELECT n.id, n.label, n.name, n.qualified_name, n.file_path,
                   n.start_line, n.end_line
            FROM edges e
            JOIN nodes n ON n.id = e.target_id
            WHERE e.source_id = ? AND e.type IN ('CALLS', 'REFERENCES', 'IMPORTS', 'DEFINES')
            LIMIT ?
            """,
            (node_id, limit),
        ).fetchall()
        return [_row_to_node(r) for r in rows]

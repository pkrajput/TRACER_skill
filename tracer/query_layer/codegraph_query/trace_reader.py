"""Read reasoning steps linked to a set of code-graph nodes via node_links."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Optional

from codegraph_trace.lineage import LineageInfo, resolve_lineage
from codegraph_trace.store.trace_db import TraceDB

from .models import ReasoningCandidate


class TraceReader:
    """Batch read-side access to recorded steps for the funnel."""

    def __init__(
        self,
        trace_db_path,
        *,
        repo_root: Optional[Path] = None,
        lineage: Optional[LineageInfo] = None,
    ) -> None:
        self.db = TraceDB(trace_db_path)
        self._lineage = lineage
        if self._lineage is None and repo_root is not None:
            self._lineage = resolve_lineage(
                self.db, repo_root, allow_unregistered=True
            )

    @property
    def lineage(self) -> Optional[LineageInfo]:
        """Active development lineage used for one-way visibility, if any."""
        return self._lineage

    def close(self) -> None:
        """Close the underlying trace DB connection."""
        self.db.close()

    def __enter__(self) -> "TraceReader":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def co_changed(
        self,
        seed_qualified_names: Iterable[str],
        *,
        limit_per_seed: int = 10,
        total_limit: int = 20,
    ) -> list[tuple[str, int]]:
        """Symbols historically co-edited with any seed symbol, most-coupled first.

        Aggregates the co-change matrix across all seed qualified names, keeps the highest count
        seen for each partner, drops partners that are already seeds, and returns
        ``[(qualified_name, count), ...]`` ordered by descending count (reverse importance).
        """
        seeds = {q for q in seed_qualified_names if q}
        if not seeds:
            return []
        best: dict[str, int] = {}
        for qn in seeds:
            for other, count in self.db.co_changed(
                qn, limit=limit_per_seed, lineage=self._lineage
            ):
                if other in seeds:
                    continue
                if count > best.get(other, 0):
                    best[other] = count
        ranked = sorted(best.items(), key=lambda kv: (-kv[1], kv[0]))
        return ranked[:total_limit]

    def steps_for_neighbourhood(
        self,
        qualified_names: Iterable[str],
        file_paths: Optional[Iterable[str]] = None,
    ) -> list[ReasoningCandidate]:
        """Return all steps linked to any node in the neighbourhood (one funnel path)."""
        qnames = list({q for q in qualified_names if q})
        paths = list({p for p in (file_paths or []) if p})
        if not qnames and not paths:
            return []

        clauses: list[str] = []
        params: list = []
        if qnames:
            placeholders = ",".join("?" * len(qnames))
            clauses.append(f"nl.qualified_name IN ({placeholders})")
            params.extend(qnames)
        if paths:
            placeholders = ",".join("?" * len(paths))
            clauses.append(f"nl.file_path IN ({placeholders})")
            params.extend(paths)

        where = " OR ".join(clauses)
        # Include imported steps for cross-repo context; still hide other lineages' locals.
        vis_sql, vis_params = self.db._visible_clause(
            self._lineage, alias="s", include_imports=True
        )
        rows = self.db.conn.execute(
            f"""
            SELECT DISTINCT s.*
            FROM steps s
            JOIN node_links nl ON nl.step_id = s.step_id
            WHERE ({where}) AND {vis_sql}
            ORDER BY s.seq
            """,
            (*params, *vis_params),
        ).fetchall()

        out: list[ReasoningCandidate] = []
        for row in rows:
            step_id = row["step_id"]
            links = self.db.links_for_step(step_id)
            out.append(
                ReasoningCandidate(
                    step_id=step_id,
                    prompt=row["prompt"] or "",
                    reasoning_text=row["reasoning_text"] or "",
                    timestamp=row["timestamp"] or "",
                    before_sha=row["before_sha"],
                    after_sha=row["after_sha"],
                    linked_qualified_names=sorted(
                        {ln["qualified_name"] for ln in links if ln.get("qualified_name")}
                    ),
                    linked_files=sorted(
                        {ln["file_path"] for ln in links if ln.get("file_path")}
                    ),
                )
            )
        return out

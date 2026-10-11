"""The recording layer's own SQLite store.

Tables, all owned by us and kept separate from the code graph:

- ``steps``            - one row per agent step.
- ``node_links``       - the bridge: which code nodes each step touched.
- ``node_signatures``  - a per-node cache of the last recorded signature, used to detect real
  changes (and skip reformat-only noise) and to compute snapshot deltas.
- ``co_change`` / ``co_change_events`` - the sparse symbol-to-symbol co-edit matrix and the
  per-step events that feed it (so re-recording a step is idempotent).
- ``imported_repos``   - registry of other repos whose reasoning graph was merged in. Merged
  ``steps`` / ``node_links`` / ``co_change`` rows carry a ``source_repo`` tag; a NULL tag means
  the row is local. Imported steps are excluded from the local version sequence.
- ``proposals``        - agent-suggested changes against human-locked nodes. When an agent step
  would touch a node a human wrote, the human record is left intact and the agent's attempted
  change is stored here as a ``pending`` proposal for the human to review.
- ``branches``         - the decision ledger: per step, what it added and whether that attempt
  survived, was abandoned, or was revised by the end of the same session (plus error retries
  from the raw event trail). Derived deterministically by ``codegraph-trace branches derive``
  (see :mod:`codegraph_trace.branches`); never written during recording. Not a git/dev fork.
- ``lineages``         - development forks of the trace (git-like). Steps carry ``lineage_id``;
  one-way visibility: a feature lineage sees its base through the fork point plus its own
  steps; main never sees unmerged feature steps. See :mod:`codegraph_trace.lineage`.

Provenance: ``steps.author`` / ``node_links.author`` record who produced a change
(``"agent"`` by default, ``"human"`` for human-captured edits). A human edit also sets
``node_signatures.locked = 1`` so later agent recording can never overwrite or delete it.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Optional, TYPE_CHECKING

from ..models import LinkedNode, Step

if TYPE_CHECKING:
    from ..lineage import LineageInfo

_SCHEMA = """
CREATE TABLE IF NOT EXISTS steps (
    step_id       TEXT PRIMARY KEY,
    prompt        TEXT,
    reasoning_text TEXT,
    -- The same reasoning split into provenance-tagged segments (JSON list of
    -- {provenance, text}; see codegraph_trace.models.REASONING_PROVENANCES). NULL for steps
    -- recorded before the taxonomy existed or via explicit `record` calls.
    reasoning_segments TEXT,
    timestamp     TEXT,
    before_sha    TEXT,
    after_sha     TEXT,
    changed_files TEXT,
    snapshot_path TEXT,
    raw_event     TEXT,
    seq           INTEGER,
    source_repo   TEXT,
    author        TEXT,
    lineage_id    TEXT
);

CREATE TABLE IF NOT EXISTS node_links (
    step_id        TEXT NOT NULL,
    node_id        INTEGER,
    qualified_name TEXT NOT NULL,
    file_path      TEXT,
    label          TEXT,
    change_kind    TEXT,
    source_repo    TEXT,
    author         TEXT,
    PRIMARY KEY (step_id, qualified_name)
);

CREATE TABLE IF NOT EXISTS node_signatures (
    qualified_name   TEXT NOT NULL,
    file_path        TEXT,
    label            TEXT,
    start_line       INTEGER,
    end_line         INTEGER,
    edge_fingerprint TEXT,
    last_step_id     TEXT,
    source_repo      TEXT,
    author           TEXT,
    locked           INTEGER NOT NULL DEFAULT 0,
    lineage_id       TEXT NOT NULL DEFAULT 'main',
    PRIMARY KEY (qualified_name, lineage_id)
);

-- Agent-suggested changes against human-locked nodes. When an agent step would touch a node a
-- human wrote, the human record stays intact and the agent's attempted change lands here as a
-- ``pending`` proposal the human can later accept (unlock) or reject (keep locked).
CREATE TABLE IF NOT EXISTS proposals (
    proposal_id    TEXT PRIMARY KEY,
    step_id        TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    file_path      TEXT,
    change_kind    TEXT,
    author         TEXT,
    prompt         TEXT,
    reasoning_text TEXT,
    after_sha      TEXT,
    status         TEXT NOT NULL DEFAULT 'pending',
    created_at     TEXT
);

-- Registry of other repositories whose reasoning graph has been merged into this one. Each
-- import is either ``editable`` or ``read_only``; read-only imports can be read for context but
-- are never modified by recording, so the other repo's history stays intact.
CREATE TABLE IF NOT EXISTS imported_repos (
    name           TEXT PRIMARY KEY,
    repo_root      TEXT,
    trace_db_path  TEXT,
    graph_db_path  TEXT,
    mode           TEXT NOT NULL DEFAULT 'read_only',
    imported_at    TEXT
);

-- The co-change matrix: a sparse N x N count of how often two symbols were edited together.
-- Pairs are stored once with canonical ordering (qn_a < qn_b). ``co_change_events`` records
-- each step's contribution so re-recording a step is idempotent (we subtract its old
-- contribution before re-adding).
CREATE TABLE IF NOT EXISTS co_change (
    qn_a         TEXT NOT NULL,
    qn_b         TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    last_step_id TEXT,
    last_seq     INTEGER,
    source_repo  TEXT,
    PRIMARY KEY (qn_a, qn_b)
);

CREATE TABLE IF NOT EXISTS co_change_events (
    step_id TEXT NOT NULL,
    qn_a    TEXT NOT NULL,
    qn_b    TEXT NOT NULL,
    PRIMARY KEY (step_id, qn_a, qn_b)
);

-- The decision ledger: attempts a step made and what became of them by the end of the same
-- session. Derived deterministically from steps + git (see codegraph_trace.branches); never
-- written during recording. ``kind`` is survived / abandoned / revised / error_retry. A row
-- with an empty ``qualified_name`` is file-level; otherwise it is a symbol-level verdict.
CREATE TABLE IF NOT EXISTS branches (
    branch_id             INTEGER PRIMARY KEY,
    session_id            TEXT NOT NULL,
    step_id               TEXT NOT NULL,
    seq                   INTEGER,
    file_path             TEXT NOT NULL,
    qualified_name        TEXT NOT NULL DEFAULT '',
    kind                  TEXT NOT NULL,
    survival_ratio        REAL,
    superseded_by_step_id TEXT,
    abandoned_content     TEXT,
    lineage_id            TEXT
);

-- Development lineages (git-like forks of the trace). Distinct from the decision-ledger
-- ``branches`` table above.
CREATE TABLE IF NOT EXISTS lineages (
    lineage_id      TEXT PRIMARY KEY,
    git_ref         TEXT NOT NULL,
    base_step_id    TEXT,
    base_seq        INTEGER,
    base_commit     TEXT,
    parent_lineage  TEXT NOT NULL DEFAULT 'main',
    status          TEXT NOT NULL DEFAULT 'open',
    created_at      TEXT,
    merged_at       TEXT
);

CREATE INDEX IF NOT EXISTS idx_node_links_qn ON node_links(qualified_name);
CREATE INDEX IF NOT EXISTS idx_node_links_file ON node_links(file_path);
CREATE INDEX IF NOT EXISTS idx_steps_seq ON steps(seq);
CREATE INDEX IF NOT EXISTS idx_co_change_a ON co_change(qn_a);
CREATE INDEX IF NOT EXISTS idx_co_change_b ON co_change(qn_b);
CREATE INDEX IF NOT EXISTS idx_proposals_status ON proposals(status);
CREATE INDEX IF NOT EXISTS idx_proposals_qn ON proposals(qualified_name);
CREATE INDEX IF NOT EXISTS idx_branches_session ON branches(session_id);
CREATE INDEX IF NOT EXISTS idx_branches_step_qn ON branches(step_id, qualified_name);
CREATE INDEX IF NOT EXISTS idx_branches_file ON branches(file_path);
-- Lineage indexes (idx_steps_lineage, idx_branches_lineage, idx_lineages_git_ref) are
-- created in ``_migrate`` after ALTER TABLE adds ``lineage_id`` on older DBs. Putting them
-- in this script fails open: CREATE TABLE IF NOT EXISTS leaves pre-lineage tables intact,
-- then CREATE INDEX ON steps(lineage_id) raises before ``_migrate`` can run.
"""


class TraceDB:
    """A thin wrapper over the trace SQLite database."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(_SCHEMA)
        self._migrate()
        self.conn.commit()

    def _migrate(self) -> None:
        """Add columns/tables introduced after a DB was first created (idempotent).

        ``CREATE TABLE IF NOT EXISTS`` does not add new columns to a pre-existing table, so we
        add the ``source_repo`` provenance column and the human-edit provenance/lock columns
        (``author`` / ``locked``) to the older tables when missing. Also bootstraps lineages
        and lineage-scoped ``node_signatures``.
        """
        for table in ("steps", "node_links", "node_signatures", "co_change"):
            if not self._table_exists(table):
                continue
            cols = {
                row["name"]
                for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if "source_repo" not in cols:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN source_repo TEXT")

        # Provenance-tagged reasoning segments (JSON), added after DBs already existed.
        if self._table_exists("steps"):
            cols = {
                row["name"]
                for row in self.conn.execute("PRAGMA table_info(steps)").fetchall()
            }
            if "reasoning_segments" not in cols:
                self.conn.execute("ALTER TABLE steps ADD COLUMN reasoning_segments TEXT")

        # Human-edit provenance: who authored a step/link and whether a node is locked.
        for table in ("steps", "node_links", "node_signatures"):
            if not self._table_exists(table):
                continue
            cols = {
                row["name"]
                for row in self.conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            if "author" not in cols:
                self.conn.execute(f"ALTER TABLE {table} ADD COLUMN author TEXT")
            if table == "node_signatures" and "locked" not in cols:
                self.conn.execute(
                    "ALTER TABLE node_signatures ADD COLUMN locked INTEGER NOT NULL DEFAULT 0"
                )

        # Development lineages: tag steps / decision-ledger rows; ensure lineages table.
        if self._table_exists("steps"):
            cols = {
                row["name"]
                for row in self.conn.execute("PRAGMA table_info(steps)").fetchall()
            }
            if "lineage_id" not in cols:
                self.conn.execute("ALTER TABLE steps ADD COLUMN lineage_id TEXT")

        if self._table_exists("branches"):
            cols = {
                row["name"]
                for row in self.conn.execute("PRAGMA table_info(branches)").fetchall()
            }
            if "lineage_id" not in cols:
                self.conn.execute("ALTER TABLE branches ADD COLUMN lineage_id TEXT")

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lineages (
                lineage_id      TEXT PRIMARY KEY,
                git_ref         TEXT NOT NULL,
                base_step_id    TEXT,
                base_seq        INTEGER,
                base_commit     TEXT,
                parent_lineage  TEXT NOT NULL DEFAULT 'main',
                status          TEXT NOT NULL DEFAULT 'open',
                created_at      TEXT,
                merged_at       TEXT
            )
            """
        )
        # ``merged_at`` arrived with lineage merge; add it to pre-merge DBs.
        cols = {
            row["name"]
            for row in self.conn.execute("PRAGMA table_info(lineages)").fetchall()
        }
        if "merged_at" not in cols:
            self.conn.execute("ALTER TABLE lineages ADD COLUMN merged_at TEXT")
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_lineages_git_ref ON lineages(git_ref)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_steps_lineage ON steps(lineage_id)"
        )
        self.conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_branches_lineage ON branches(lineage_id)"
        )

        # Bootstrap main lineage for every DB.
        row = self.conn.execute(
            "SELECT 1 FROM lineages WHERE lineage_id = 'main'"
        ).fetchone()
        if row is None:
            self.conn.execute(
                """
                INSERT INTO lineages
                    (lineage_id, git_ref, base_step_id, base_seq, base_commit,
                     parent_lineage, status, created_at)
                VALUES ('main', 'main', NULL, NULL, NULL, 'main', 'open', datetime('now'))
                """
            )

        self._migrate_node_signatures_lineage()

    def _migrate_node_signatures_lineage(self) -> None:
        """Rebuild ``node_signatures`` with a (qualified_name, lineage_id) primary key."""
        if not self._table_exists("node_signatures"):
            return
        cols = {
            row["name"]
            for row in self.conn.execute("PRAGMA table_info(node_signatures)").fetchall()
        }
        if "lineage_id" in cols:
            # Already lineage-scoped (fresh schema or prior migrate).
            return
        self.conn.execute("ALTER TABLE node_signatures RENAME TO node_signatures_pre_lineage")
        self.conn.execute(
            """
            CREATE TABLE node_signatures (
                qualified_name   TEXT NOT NULL,
                file_path        TEXT,
                label            TEXT,
                start_line       INTEGER,
                end_line         INTEGER,
                edge_fingerprint TEXT,
                last_step_id     TEXT,
                source_repo      TEXT,
                author           TEXT,
                locked           INTEGER NOT NULL DEFAULT 0,
                lineage_id       TEXT NOT NULL DEFAULT 'main',
                PRIMARY KEY (qualified_name, lineage_id)
            )
            """
        )
        self.conn.execute(
            """
            INSERT INTO node_signatures
                (qualified_name, file_path, label, start_line, end_line, edge_fingerprint,
                 last_step_id, source_repo, author, locked, lineage_id)
            SELECT qualified_name, file_path, label, start_line, end_line, edge_fingerprint,
                   last_step_id, source_repo, author, COALESCE(locked, 0), 'main'
            FROM node_signatures_pre_lineage
            """
        )
        self.conn.execute("DROP TABLE node_signatures_pre_lineage")

    def _table_exists(self, name: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        return row is not None

    def _visible_clause(
        self,
        lineage: Optional["LineageInfo"],
        *,
        alias: str = "s",
        include_imports: bool = False,
    ) -> tuple[str, list[Any]]:
        """SQL visibility predicate; when ``lineage`` is None, only filter to local steps."""
        if lineage is None:
            if include_imports:
                return "1=1", []
            return f"({alias}.source_repo IS NULL)", []
        from ..lineage import visible_step_sql

        return visible_step_sql(
            lineage, alias=alias, include_imports=include_imports
        )

    def close(self) -> None:
        """Close the SQLite connection."""
        self.conn.close()

    def __enter__(self) -> "TraceDB":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # --- steps ---------------------------------------------------------
    def has_step(self, step_id: str) -> bool:
        """Return True if ``step_id`` is already stored."""
        row = self.conn.execute(
            "SELECT 1 FROM steps WHERE step_id = ?", (step_id,)
        ).fetchone()
        return row is not None

    def _next_seq(self) -> int:
        # Only local steps participate in the version sequence; imported steps carry their own
        # foreign seq and are excluded from versions / goto.
        row = self.conn.execute(
            "SELECT COALESCE(MAX(seq), 0) AS m FROM steps WHERE source_repo IS NULL"
        ).fetchone()
        return int(row["m"]) + 1

    def peek_seq(self, step_id: str) -> int:
        """The monotonic step number this ``step_id`` will get, without inserting.

        Returns the existing ``seq`` when the step is already recorded (idempotent
        re-recording), otherwise the next number in sequence. Used so a snapshot can carry its
        step number even though it is built before the step row is written.
        """
        existing = self.conn.execute(
            "SELECT seq FROM steps WHERE step_id = ?", (step_id,)
        ).fetchone()
        return int(existing["seq"]) if existing else self._next_seq()

    def upsert_step(
        self,
        step: Step,
        changed_files: list[str],
        snapshot_path: Optional[str],
    ) -> None:
        """Insert (or replace) a step row. Idempotent on ``step_id``."""
        existing = self.conn.execute(
            "SELECT seq FROM steps WHERE step_id = ?", (step.step_id,)
        ).fetchone()
        seq = int(existing["seq"]) if existing else self._next_seq()

        raw = step.raw_event
        if raw is not None and not isinstance(raw, str):
            raw = json.dumps(raw, default=str)

        segments = getattr(step, "reasoning_segments", None) or []
        segments_json = (
            json.dumps([s.to_json() for s in segments]) if segments else None
        )

        lineage_id = getattr(step, "lineage_id", None) or "main"
        self.conn.execute(
            """
            INSERT INTO steps (step_id, prompt, reasoning_text, reasoning_segments, timestamp,
                               before_sha, after_sha, changed_files, snapshot_path, raw_event,
                               seq, author, lineage_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(step_id) DO UPDATE SET
                prompt=excluded.prompt,
                reasoning_text=excluded.reasoning_text,
                reasoning_segments=excluded.reasoning_segments,
                timestamp=excluded.timestamp,
                before_sha=excluded.before_sha,
                after_sha=excluded.after_sha,
                changed_files=excluded.changed_files,
                snapshot_path=excluded.snapshot_path,
                raw_event=excluded.raw_event,
                author=excluded.author,
                lineage_id=excluded.lineage_id
            """,
            (
                step.step_id,
                step.prompt,
                step.reasoning_text,
                segments_json,
                step.timestamp,
                step.before_sha,
                step.after_sha,
                ",".join(changed_files),
                snapshot_path,
                raw,
                seq,
                getattr(step, "author", "agent") or "agent",
                lineage_id,
            ),
        )
        self.conn.commit()

    # --- node links ----------------------------------------------------
    def replace_node_links(
        self, step_id: str, links: list[LinkedNode], author: str = "agent"
    ) -> None:
        """Replace the set of node links for a step (idempotent re-recording)."""
        self.conn.execute("DELETE FROM node_links WHERE step_id = ?", (step_id,))
        self.conn.executemany(
            """
            INSERT OR REPLACE INTO node_links
                (step_id, node_id, qualified_name, file_path, label, change_kind, author)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    step_id,
                    ln.node.node_id,
                    ln.node.qualified_name,
                    ln.node.file_path,
                    ln.node.label,
                    ln.change_kind,
                    author,
                )
                for ln in links
            ],
        )
        self.conn.commit()

    # --- node signatures ----------------------------------------------
    def get_signature(
        self, qualified_name: str, lineage_id: str = "main"
    ) -> Optional[dict[str, Any]]:
        """Return the cached signature row for ``qualified_name`` on ``lineage_id``, or None."""
        row = self.conn.execute(
            "SELECT * FROM node_signatures WHERE qualified_name = ? AND lineage_id = ?",
            (qualified_name, lineage_id or "main"),
        ).fetchone()
        return dict(row) if row else None

    def upsert_signature(
        self,
        qualified_name: str,
        file_path: str,
        label: str,
        start_line: int,
        end_line: int,
        edge_fingerprint: str,
        step_id: str,
        author: str = "agent",
        locked: bool = False,
        lineage_id: str = "main",
    ) -> None:
        """Insert or update the cached signature used for change detection (per lineage)."""
        lid = lineage_id or "main"
        self.conn.execute(
            """
            INSERT INTO node_signatures
                (qualified_name, file_path, label, start_line, end_line,
                 edge_fingerprint, last_step_id, author, locked, lineage_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(qualified_name, lineage_id) DO UPDATE SET
                file_path=excluded.file_path,
                label=excluded.label,
                start_line=excluded.start_line,
                end_line=excluded.end_line,
                edge_fingerprint=excluded.edge_fingerprint,
                last_step_id=excluded.last_step_id,
                author=excluded.author,
                locked=excluded.locked
            """,
            (
                qualified_name,
                file_path,
                label,
                start_line,
                end_line,
                edge_fingerprint,
                step_id,
                author,
                1 if locked else 0,
                lid,
            ),
        )
        self.conn.commit()

    # --- co-change matrix ---------------------------------------------
    def bump_co_change(
        self,
        qualified_names: list[str],
        step_id: str,
        seq: Optional[int],
    ) -> None:
        """Record that the given symbols were edited together in one step.

        Every unordered pair (canonical ``qn_a < qn_b``) has its ``count`` incremented. File-
        level pseudo-nodes (``file::``) are excluded - the matrix is symbol-to-symbol. The
        operation is idempotent: re-recording the same ``step_id`` first removes its previous
        contribution (tracked in ``co_change_events``) so counts never double.
        """
        qns = sorted({q for q in qualified_names if q and not q.startswith("file::")})
        self._clear_co_change_for_step(step_id)
        if len(qns) < 2:
            self.conn.commit()
            return
        for i in range(len(qns)):
            for j in range(i + 1, len(qns)):
                a, b = qns[i], qns[j]
                self.conn.execute(
                    "INSERT OR IGNORE INTO co_change_events (step_id, qn_a, qn_b) VALUES (?, ?, ?)",
                    (step_id, a, b),
                )
                self.conn.execute(
                    """
                    INSERT INTO co_change (qn_a, qn_b, count, last_step_id, last_seq)
                    VALUES (?, ?, 1, ?, ?)
                    ON CONFLICT(qn_a, qn_b) DO UPDATE SET
                        count = count + 1,
                        last_step_id = excluded.last_step_id,
                        last_seq = excluded.last_seq
                    """,
                    (a, b, step_id, seq),
                )
        self.conn.commit()

    def _clear_co_change_for_step(self, step_id: str) -> None:
        rows = self.conn.execute(
            "SELECT qn_a, qn_b FROM co_change_events WHERE step_id = ?", (step_id,)
        ).fetchall()
        for r in rows:
            self.conn.execute(
                "UPDATE co_change SET count = count - 1 WHERE qn_a = ? AND qn_b = ?",
                (r["qn_a"], r["qn_b"]),
            )
        self.conn.execute("DELETE FROM co_change WHERE count <= 0")
        self.conn.execute("DELETE FROM co_change_events WHERE step_id = ?", (step_id,))

    def co_changed(
        self,
        qualified_name: str,
        limit: int = 10,
        *,
        lineage: Optional["LineageInfo"] = None,
    ) -> list[tuple[str, int]]:
        """Symbols historically co-edited with ``qualified_name``, most frequent first.

        Returns ``[(other_qualified_name, count), ...]`` ordered by descending co-change count
        (reverse importance), so callers can pull the most-coupled symbols' reasoning first.

        When ``lineage`` is set, counts are rebuilt from ``co_change_events`` joined to
        *visible* steps only, so a feature lineage cannot inflate main's co-change view.
        """
        if not qualified_name:
            return []
        if lineage is None:
            rows = self.conn.execute(
                """
                SELECT other, count FROM (
                    SELECT qn_b AS other, count FROM co_change WHERE qn_a = ?
                    UNION ALL
                    SELECT qn_a AS other, count FROM co_change WHERE qn_b = ?
                )
                ORDER BY count DESC, other
                LIMIT ?
                """,
                (qualified_name, qualified_name, limit),
            ).fetchall()
            return [(r["other"], int(r["count"])) for r in rows]

        vis_sql, vis_params = self._visible_clause(lineage, alias="s")
        rows = self.conn.execute(
            f"""
            SELECT other, COUNT(*) AS count FROM (
                SELECT CASE WHEN e.qn_a = ? THEN e.qn_b ELSE e.qn_a END AS other
                FROM co_change_events e
                JOIN steps s ON s.step_id = e.step_id
                WHERE (e.qn_a = ? OR e.qn_b = ?) AND {vis_sql}
            )
            GROUP BY other
            ORDER BY count DESC, other
            LIMIT ?
            """,
            (qualified_name, qualified_name, qualified_name, *vis_params, limit),
        ).fetchall()
        return [(r["other"], int(r["count"])) for r in rows]

    # --- lineages (development forks) ---------------------------------
    def get_lineage(self, lineage_id: str) -> Optional["LineageInfo"]:
        """Return one lineage by id, or None."""
        from ..lineage import row_to_lineage

        row = self.conn.execute(
            "SELECT * FROM lineages WHERE lineage_id = ?", (lineage_id,)
        ).fetchone()
        return row_to_lineage(dict(row)) if row else None

    def get_lineage_by_git_ref(self, git_ref: str) -> Optional["LineageInfo"]:
        """Return the lineage bound to ``git_ref``, or None."""
        from ..lineage import row_to_lineage

        row = self.conn.execute(
            "SELECT * FROM lineages WHERE git_ref = ?", (git_ref,)
        ).fetchone()
        return row_to_lineage(dict(row)) if row else None

    def list_lineages(self) -> list["LineageInfo"]:
        """Every lineage, main first then by id."""
        from ..lineage import row_to_lineage

        rows = self.conn.execute(
            """
            SELECT * FROM lineages
            ORDER BY CASE WHEN lineage_id = 'main' THEN 0 ELSE 1 END, lineage_id
            """
        ).fetchall()
        return [row_to_lineage(dict(r)) for r in rows]

    def upsert_lineage(
        self,
        *,
        lineage_id: str,
        git_ref: str,
        base_step_id: Optional[str],
        base_seq: Optional[int],
        base_commit: Optional[str],
        parent_lineage: str,
        status: str,
        created_at: str,
    ) -> None:
        """Insert or replace a lineage registry row."""
        self.conn.execute(
            """
            INSERT INTO lineages
                (lineage_id, git_ref, base_step_id, base_seq, base_commit,
                 parent_lineage, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(lineage_id) DO UPDATE SET
                git_ref=excluded.git_ref,
                base_step_id=excluded.base_step_id,
                base_seq=excluded.base_seq,
                base_commit=excluded.base_commit,
                parent_lineage=excluded.parent_lineage,
                status=excluded.status,
                created_at=excluded.created_at
            """,
            (
                lineage_id,
                git_ref,
                base_step_id,
                base_seq,
                base_commit,
                parent_lineage,
                status,
                created_at,
            ),
        )
        self.conn.commit()

    def delete_lineage(self, lineage_id: str) -> None:
        """Remove a lineage registry row (does not delete its steps)."""
        self.conn.execute("DELETE FROM lineages WHERE lineage_id = ?", (lineage_id,))
        self.conn.commit()

    def merged_lineage_ids(self) -> frozenset[str]:
        """Ids of lineages folded into main (``status = 'merged'``)."""
        rows = self.conn.execute(
            "SELECT lineage_id FROM lineages WHERE status = 'merged'"
        ).fetchall()
        return frozenset(r["lineage_id"] for r in rows)

    def set_lineage_status(
        self, lineage_id: str, status: str, *, merged_at: Optional[str] = None
    ) -> None:
        """Update a lineage's ``status`` (and ``merged_at`` when it is being merged)."""
        if merged_at is not None:
            self.conn.execute(
                "UPDATE lineages SET status = ?, merged_at = ? WHERE lineage_id = ?",
                (status, merged_at, lineage_id),
            )
        else:
            self.conn.execute(
                "UPDATE lineages SET status = ? WHERE lineage_id = ?",
                (status, lineage_id),
            )
        self.conn.commit()

    def fold_signatures_into_main(self, lineage_id: str) -> int:
        """Fold a merged lineage's ``node_signatures`` into main's cache.

        For each signature the feature lineage recorded, main's row is replaced when the
        feature's ``last_step_id`` belongs to a later step (higher ``seq``) than main's — i.e.
        the branch holds the newest recorded state of that node. Human locks on the feature
        row survive the fold. Idempotent: re-running compares the same seqs and rewrites the
        same rows. Returns the number of main rows written.
        """
        rows = self.conn.execute(
            """
            SELECT f.*, sf.seq AS f_seq, sm.seq AS m_seq
            FROM node_signatures f
            LEFT JOIN steps sf ON sf.step_id = f.last_step_id
            LEFT JOIN node_signatures m
                ON m.qualified_name = f.qualified_name AND m.lineage_id = 'main'
            LEFT JOIN steps sm ON sm.step_id = m.last_step_id
            WHERE f.lineage_id = ?
            """,
            (lineage_id,),
        ).fetchall()
        written = 0
        for r in rows:
            f_seq = r["f_seq"]
            m_seq = r["m_seq"]
            if f_seq is None:
                continue
            if m_seq is not None and int(m_seq) >= int(f_seq):
                continue
            self.conn.execute(
                """
                INSERT INTO node_signatures
                    (qualified_name, file_path, label, start_line, end_line,
                     edge_fingerprint, last_step_id, source_repo, author, locked, lineage_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'main')
                ON CONFLICT(qualified_name, lineage_id) DO UPDATE SET
                    file_path=excluded.file_path,
                    label=excluded.label,
                    start_line=excluded.start_line,
                    end_line=excluded.end_line,
                    edge_fingerprint=excluded.edge_fingerprint,
                    last_step_id=excluded.last_step_id,
                    author=excluded.author,
                    locked=MAX(node_signatures.locked, excluded.locked)
                """,
                (
                    r["qualified_name"],
                    r["file_path"],
                    r["label"],
                    r["start_line"],
                    r["end_line"],
                    r["edge_fingerprint"],
                    r["last_step_id"],
                    r["source_repo"],
                    r["author"],
                    r["locked"],
                ),
            )
            written += 1
        self.conn.commit()
        return written

    # --- branches (the decision ledger) --------------------------------
    def replace_branches_for_sessions(
        self, session_ids: list[str], rows: list[dict[str, Any]]
    ) -> None:
        """Replace the branch rows of the given sessions with ``rows`` (idempotent derive).

        The whole table is rewritten with deterministically ordered rows and freshly numbered
        ``branch_id``s (1..N), so running the derivation twice - even for a single session in a
        multi-session trace - yields a byte-identical table.
        """
        keep = [
            dict(r)
            for r in self.conn.execute("SELECT * FROM branches").fetchall()
            if r["session_id"] not in set(session_ids)
        ]
        merged = keep + [dict(r) for r in rows]
        merged.sort(
            key=lambda r: (
                r.get("lineage_id") or "main",
                r.get("session_id") or "",
                r.get("seq") if r.get("seq") is not None else -1,
                r.get("step_id") or "",
                r.get("file_path") or "",
                r.get("qualified_name") or "",
                r.get("kind") or "",
            )
        )
        self.conn.execute("DELETE FROM branches")
        self.conn.executemany(
            """
            INSERT INTO branches
                (branch_id, session_id, step_id, seq, file_path, qualified_name, kind,
                 survival_ratio, superseded_by_step_id, abandoned_content, lineage_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    i,
                    r.get("session_id"),
                    r.get("step_id"),
                    r.get("seq"),
                    r.get("file_path"),
                    r.get("qualified_name") or "",
                    r.get("kind"),
                    r.get("survival_ratio"),
                    r.get("superseded_by_step_id"),
                    r.get("abandoned_content"),
                    r.get("lineage_id") or "main",
                )
                for i, r in enumerate(merged, 1)
            ],
        )
        self.conn.commit()

    def branch_session_ids(self) -> list[str]:
        """Session ids that already have derived branch rows."""
        rows = self.conn.execute(
            "SELECT DISTINCT session_id FROM branches ORDER BY session_id"
        ).fetchall()
        return [r["session_id"] for r in rows]

    def branches_for_step(self, step_id: str) -> list[dict[str, Any]]:
        """Branch rows for one step, each carrying the superseding step's seq (if any)."""
        rows = self.conn.execute(
            """
            SELECT b.*, s2.seq AS superseded_by_seq
            FROM branches b
            LEFT JOIN steps s2 ON s2.step_id = b.superseded_by_step_id
            WHERE b.step_id = ?
            ORDER BY b.branch_id
            """,
            (step_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def list_branches(
        self,
        target: Optional[str] = None,
        *,
        lineage: Optional["LineageInfo"] = None,
    ) -> list[dict[str, Any]]:
        """Every branch row (optionally filtered to a file path or qualified name), joined with
        its step's prompt/reasoning and the superseding step's seq.

        When ``lineage`` is set, only rows whose step is visible on that lineage are returned.
        """
        sql = """
            SELECT b.*, s.prompt AS prompt, s.reasoning_text AS reasoning_text,
                   s.author AS author, s2.seq AS superseded_by_seq
            FROM branches b
            LEFT JOIN steps s ON s.step_id = b.step_id
            LEFT JOIN steps s2 ON s2.step_id = b.superseded_by_step_id
        """
        clauses: list[str] = []
        params: list[Any] = []
        if target:
            clauses.append("(b.file_path = ? OR b.qualified_name = ?)")
            params.extend([target, target])
        if lineage is not None:
            vis_sql, vis_params = self._visible_clause(lineage, alias="s")
            clauses.append(vis_sql)
            params.extend(vis_params)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY b.branch_id"
        rows = self.conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def important_step_ids(
        self, *, lineage: Optional["LineageInfo"] = None
    ) -> set[str]:
        """Steps where the path forked: any abandoned or error_retry branch row, any step that
        superseded an earlier attempt, or any step that touched a human-locked node.

        When ``lineage`` is set, only steps visible on that lineage are considered.
        """
        out: set[str] = set()
        for r in self.conn.execute(
            "SELECT DISTINCT step_id FROM branches WHERE kind IN ('abandoned', 'error_retry')"
        ).fetchall():
            out.add(r["step_id"])
        for r in self.conn.execute(
            """
            SELECT DISTINCT superseded_by_step_id AS sid FROM branches
            WHERE superseded_by_step_id IS NOT NULL
            """
        ).fetchall():
            out.add(r["sid"])
        if lineage is not None:
            lock_sql = """
                SELECT DISTINCT nl.step_id AS sid
                FROM node_links nl
                JOIN node_signatures ns ON ns.qualified_name = nl.qualified_name
                WHERE ns.locked = 1 AND ns.lineage_id = ?
            """
            lock_params: tuple[Any, ...] = (lineage.lineage_id,)
        else:
            lock_sql = """
                SELECT DISTINCT nl.step_id AS sid
                FROM node_links nl
                JOIN node_signatures ns ON ns.qualified_name = nl.qualified_name
                WHERE ns.locked = 1
            """
            lock_params = ()
        for r in self.conn.execute(lock_sql, lock_params).fetchall():
            out.add(r["sid"])
        if lineage is not None:
            visible_ids = {s["step_id"] for s in self.list_steps(lineage=lineage)}
            out &= visible_ids
        return out

    # --- multi-repo import / registry ---------------------------------
    def list_imported_repos(self) -> list[dict[str, Any]]:
        """Every registered imported repo (name, paths, mode)."""
        rows = self.conn.execute(
            "SELECT * FROM imported_repos ORDER BY name"
        ).fetchall()
        return [dict(r) for r in rows]

    def readonly_qualified_names(self) -> set[str]:
        """Qualified names that belong to a read-only import and must never be modified."""
        rows = self.conn.execute(
            """
            SELECT DISTINCT qualified_name FROM node_links
            WHERE source_repo IN (SELECT name FROM imported_repos WHERE mode = 'read_only')
            """
        ).fetchall()
        return {r["qualified_name"] for r in rows}

    # --- human-edit provenance / lock ---------------------------------
    def human_locked_qualified_names(self, lineage_id: str = "main") -> set[str]:
        """Qualified names a human wrote and locked on ``lineage_id``."""
        rows = self.conn.execute(
            """
            SELECT qualified_name FROM node_signatures
            WHERE locked = 1 AND author = 'human' AND lineage_id = ?
            """,
            (lineage_id or "main",),
        ).fetchall()
        return {r["qualified_name"] for r in rows}

    def locked_nodes(self, lineage_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Every locked human-written node (qualified_name, file_path, label, last_step_id)."""
        if lineage_id is None:
            rows = self.conn.execute(
                """
                SELECT qualified_name, file_path, label, last_step_id, lineage_id
                FROM node_signatures
                WHERE locked = 1 AND author = 'human'
                ORDER BY lineage_id, file_path, qualified_name
                """
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT qualified_name, file_path, label, last_step_id, lineage_id
                FROM node_signatures
                WHERE locked = 1 AND author = 'human' AND lineage_id = ?
                ORDER BY file_path, qualified_name
                """,
                (lineage_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def unlock_node(self, qualified_name: str, lineage_id: str = "main") -> bool:
        """Clear the lock on a node so later agent recording may overwrite it. Returns True if a
        locked node existed."""
        cur = self.conn.execute(
            """
            UPDATE node_signatures SET locked = 0
            WHERE qualified_name = ? AND lineage_id = ? AND locked = 1
            """,
            (qualified_name, lineage_id or "main"),
        )
        self.conn.commit()
        return cur.rowcount > 0

    def add_proposal(
        self,
        *,
        step_id: str,
        qualified_name: str,
        file_path: Optional[str],
        change_kind: Optional[str],
        author: str,
        prompt: Optional[str],
        reasoning_text: Optional[str],
        after_sha: Optional[str],
        created_at: str,
    ) -> None:
        """Store an agent's attempted change to a locked human node as a ``pending`` proposal.

        Idempotent on ``(step_id, qualified_name)``: re-recording the same step refreshes the
        proposal rather than duplicating it (unless the human already resolved it).
        """
        proposal_id = f"{step_id}::{qualified_name}"
        existing = self.conn.execute(
            "SELECT status FROM proposals WHERE proposal_id = ?", (proposal_id,)
        ).fetchone()
        # Leave a human-resolved proposal (accepted/rejected) alone on re-record.
        status = existing["status"] if existing else "pending"
        self.conn.execute(
            """
            INSERT INTO proposals
                (proposal_id, step_id, qualified_name, file_path, change_kind, author,
                 prompt, reasoning_text, after_sha, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(proposal_id) DO UPDATE SET
                file_path=excluded.file_path,
                change_kind=excluded.change_kind,
                author=excluded.author,
                prompt=excluded.prompt,
                reasoning_text=excluded.reasoning_text,
                after_sha=excluded.after_sha,
                created_at=excluded.created_at
            """,
            (
                proposal_id,
                step_id,
                qualified_name,
                file_path,
                change_kind,
                author,
                prompt,
                reasoning_text,
                after_sha,
                status,
                created_at,
            ),
        )
        self.conn.commit()

    def list_proposals(self, status: Optional[str] = None) -> list[dict[str, Any]]:
        """Proposals, optionally filtered by status (``pending`` / ``accepted`` / ``rejected``)."""
        if status:
            rows = self.conn.execute(
                "SELECT * FROM proposals WHERE status = ? ORDER BY created_at, proposal_id",
                (status,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM proposals ORDER BY created_at, proposal_id"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_proposal(self, proposal_id: str) -> Optional[dict[str, Any]]:
        """Return one proposal row by id, or None."""
        row = self.conn.execute(
            "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)
        ).fetchone()
        return dict(row) if row else None

    def set_proposal_status(self, proposal_id: str, status: str) -> bool:
        """Mark a proposal ``accepted`` or ``rejected``. Returns True if the proposal existed."""
        if status not in ("pending", "accepted", "rejected"):
            raise ValueError(f"status must be pending/accepted/rejected, got {status!r}")
        cur = self.conn.execute(
            "UPDATE proposals SET status = ? WHERE proposal_id = ?", (status, proposal_id)
        )
        self.conn.commit()
        return cur.rowcount > 0

    def import_repo(
        self,
        *,
        name: str,
        repo_root: str,
        other_trace_db_path: str,
        graph_db_path: Optional[str],
        mode: str,
        imported_at: str,
    ) -> dict[str, int]:
        """Merge another repo's reasoning graph into this trace, tagged with ``source_repo``.

        Copies the other repo's ``steps`` / ``node_links`` / ``co_change`` rows in, prefixing
        their ``step_id`` with ``<name>::`` so ids never collide and tagging every row with
        ``source_repo = name``. Re-importing the same name first clears its prior rows, so the
        operation is idempotent and an ``editable`` import can be refreshed. Returns counts.

        ``mode`` is ``'editable'`` or ``'read_only'``. When the other repo has no recorded
        history yet, only the registry row (and its graph DB pointer) is written, so the code
        graph can still be navigated.
        """
        if mode not in ("editable", "read_only"):
            raise ValueError(f"mode must be 'editable' or 'read_only', got {mode!r}")

        # Refresh: drop any previous import under this name first (idempotent / editable refresh).
        self._clear_imported(name)

        self.conn.execute(
            """
            INSERT INTO imported_repos (name, repo_root, trace_db_path, graph_db_path, mode, imported_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
                repo_root=excluded.repo_root,
                trace_db_path=excluded.trace_db_path,
                graph_db_path=excluded.graph_db_path,
                mode=excluded.mode,
                imported_at=excluded.imported_at
            """,
            (name, repo_root, other_trace_db_path, graph_db_path, mode, imported_at),
        )

        counts = {"steps": 0, "node_links": 0, "co_change": 0}
        if other_trace_db_path and Path(other_trace_db_path).is_file():
            self.conn.execute("ATTACH DATABASE ? AS src", (str(other_trace_db_path),))
            try:
                prefix = f"{name}::"
                # Only import the other repo's *own* rows (not data it in turn imported).
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO steps
                        (step_id, prompt, reasoning_text, timestamp, before_sha, after_sha,
                         changed_files, snapshot_path, raw_event, seq, source_repo)
                    SELECT ? || step_id, prompt, reasoning_text, timestamp, before_sha, after_sha,
                           changed_files, snapshot_path, raw_event, seq, ?
                    FROM src.steps
                    WHERE source_repo IS NULL
                    """,
                    (prefix, name),
                )
                counts["steps"] = self.conn.execute(
                    "SELECT COUNT(*) AS c FROM steps WHERE source_repo = ?", (name,)
                ).fetchone()["c"]

                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO node_links
                        (step_id, node_id, qualified_name, file_path, label, change_kind, source_repo)
                    SELECT ? || step_id, node_id, qualified_name, file_path, label, change_kind, ?
                    FROM src.node_links
                    WHERE source_repo IS NULL
                    """,
                    (prefix, name),
                )
                counts["node_links"] = self.conn.execute(
                    "SELECT COUNT(*) AS c FROM node_links WHERE source_repo = ?", (name,)
                ).fetchone()["c"]

                if self._src_has_table("co_change"):
                    self.conn.execute(
                        """
                        INSERT OR REPLACE INTO co_change
                            (qn_a, qn_b, count, last_step_id, last_seq, source_repo)
                        SELECT qn_a, qn_b, count, last_step_id, last_seq, ?
                        FROM src.co_change
                        WHERE source_repo IS NULL
                        """,
                        (name,),
                    )
                    counts["co_change"] = self.conn.execute(
                        "SELECT COUNT(*) AS c FROM co_change WHERE source_repo = ?", (name,)
                    ).fetchone()["c"]
                # Commit before DETACH: an open transaction keeps ``src`` locked and DETACH fails.
                self.conn.commit()
            finally:
                self.conn.execute("DETACH DATABASE src")

        self.conn.commit()
        return counts

    def _src_has_table(self, name: str) -> bool:
        row = self.conn.execute(
            "SELECT 1 FROM src.sqlite_master WHERE type='table' AND name=?", (name,)
        ).fetchone()
        return row is not None

    def _clear_imported(self, name: str) -> None:
        # Delete child rows (node_links) before parent rows (steps) so a re-import is safe even
        # on older DBs that still carry the node_links -> steps foreign key.
        self.conn.execute("DELETE FROM node_links WHERE source_repo = ?", (name,))
        self.conn.execute("DELETE FROM node_signatures WHERE source_repo = ?", (name,))
        self.conn.execute("DELETE FROM co_change WHERE source_repo = ?", (name,))
        self.conn.execute("DELETE FROM steps WHERE source_repo = ?", (name,))

    # --- queries (read side) ------------------------------------------
    def get_step(self, step_id: str) -> Optional[dict[str, Any]]:
        """Return one step row by id, or None."""
        row = self.conn.execute(
            "SELECT * FROM steps WHERE step_id = ?", (step_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_steps(
        self, *, lineage: Optional["LineageInfo"] = None
    ) -> list[dict[str, Any]]:
        """Local recorded steps ordered by monotonic ``seq`` (the version sequence).

        Imported steps (``source_repo`` set) are always excluded. When ``lineage`` is set,
        only steps visible on that lineage are returned (one-way visibility).
        """
        vis_sql, vis_params = self._visible_clause(lineage, alias="s")
        rows = self.conn.execute(
            f"SELECT s.* FROM steps s WHERE {vis_sql} ORDER BY s.seq",
            vis_params,
        ).fetchall()
        return [dict(r) for r in rows]

    def steps_for_lineage(self, lineage_id: str) -> list[dict[str, Any]]:
        """A lineage's *own* recorded steps (not its inherited ancestry), ordered by ``seq``."""
        rows = self.conn.execute(
            """
            SELECT * FROM steps
            WHERE lineage_id = ? AND source_repo IS NULL
            ORDER BY seq
            """,
            (lineage_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_step_by_seq(self, seq: int) -> Optional[dict[str, Any]]:
        """The local step row for a given version number (``steps.seq``), or None."""
        row = self.conn.execute(
            "SELECT * FROM steps WHERE seq = ? AND source_repo IS NULL", (seq,)
        ).fetchone()
        return dict(row) if row else None

    def link_counts(self, step_id: str) -> dict[str, int]:
        """Per-step node-link counts by change kind: ``{added, removed, changed}``."""
        rows = self.conn.execute(
            "SELECT change_kind, COUNT(*) AS c FROM node_links WHERE step_id = ? GROUP BY change_kind",
            (step_id,),
        ).fetchall()
        counts = {"added": 0, "removed": 0, "changed": 0}
        for r in rows:
            kind = r["change_kind"]
            if kind in counts:
                counts[kind] = int(r["c"])
        return counts

    def steps_for_file(
        self,
        file_path: str,
        *,
        lineage: Optional["LineageInfo"] = None,
    ) -> list[dict[str, Any]]:
        """Ordered steps that touched a given file (the file's reasoning log)."""
        from ..codegraph import normalize_path

        norm = normalize_path(file_path)
        vis_sql, vis_params = self._visible_clause(lineage, alias="s")
        rows = self.conn.execute(
            f"""
            SELECT DISTINCT s.*
            FROM steps s
            JOIN node_links nl ON nl.step_id = s.step_id
            WHERE nl.file_path = ? AND {vis_sql}
            ORDER BY s.seq
            """,
            (norm, *vis_params),
        ).fetchall()
        return [dict(r) for r in rows]

    def steps_for_qualified_name(
        self,
        qualified_name: str,
        *,
        lineage: Optional["LineageInfo"] = None,
    ) -> list[dict[str, Any]]:
        """Ordered steps that touched a given symbol (the symbol's reasoning log)."""
        vis_sql, vis_params = self._visible_clause(lineage, alias="s")
        rows = self.conn.execute(
            f"""
            SELECT DISTINCT s.*
            FROM steps s
            JOIN node_links nl ON nl.step_id = s.step_id
            WHERE nl.qualified_name = ? AND {vis_sql}
            ORDER BY s.seq
            """,
            (qualified_name, *vis_params),
        ).fetchall()
        return [dict(r) for r in rows]

    def links_for_step(self, step_id: str) -> list[dict[str, Any]]:
        # Left-join the current signature so callers can show whether a node is still locked
        # (the provenance ``author`` comes from the link row itself).
        """Return every ``node_links`` row for ``step_id``."""
        # node_signatures keeps one row per (qualified_name, lineage_id); after a branch merge a
        # symbol can have several signature rows, so aggregate the join or every link row would
        # be duplicated once per lineage.
        rows = self.conn.execute(
            """
            SELECT nl.*, COALESCE(MAX(ns.locked), 0) AS locked
            FROM node_links nl
            LEFT JOIN node_signatures ns ON ns.qualified_name = nl.qualified_name
            WHERE nl.step_id = ?
            GROUP BY nl.rowid
            ORDER BY nl.rowid
            """,
            (step_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def node_step_markers(
        self,
        qualified_name: str,
        *,
        lineage: Optional["LineageInfo"] = None,
    ) -> Optional[dict[str, Any]]:
        """Step-number markers for a single node, or None if it was never recorded.

        Returns ``{introduced_at_step, last_changed_at_step, touch_count}`` where the step
        numbers are the monotonic ``steps.seq`` values. ``introduced_at_step`` prefers the
        first step that linked the node with ``change_kind = 'added'`` and otherwise falls back
        to the earliest step that touched it.
        """
        vis_sql, vis_params = self._visible_clause(lineage, alias="s")
        rows = self.conn.execute(
            f"""
            SELECT s.seq AS seq, nl.change_kind AS change_kind
            FROM node_links nl
            JOIN steps s ON s.step_id = nl.step_id
            WHERE nl.qualified_name = ? AND {vis_sql}
            ORDER BY s.seq
            """,
            (qualified_name, *vis_params),
        ).fetchall()
        if not rows:
            return None
        seqs = [int(r["seq"]) for r in rows if r["seq"] is not None]
        if not seqs:
            return None
        added = [int(r["seq"]) for r in rows if r["change_kind"] == "added" and r["seq"] is not None]
        return {
            "introduced_at_step": added[0] if added else seqs[0],
            "last_changed_at_step": seqs[-1],
            "touch_count": len(seqs),
        }

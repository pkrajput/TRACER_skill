"""Tests for the post-session reconcile pass.

Scenario: an agent creates a brand-new symbol during a session, so it is recorded against the
stale graph with ``node_id = NULL`` and a synthesized qualified name. The repo is then
re-indexed with codebase-memory-mcp (simulated here by rebuilding the graph SQLite), and
``reconcile`` must:

- backfill the real ``node_id`` when the synthesized name matches the graph exactly,
- adopt the graph's canonical qualified name when the indexer named the symbol differently
  (rewriting node_links / node_signatures / co_change and preserving human locks),
- leave ambiguous matches untouched and report them,
- refuse to run against a graph older than the last recorded step unless forced.
"""

from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.config import TraceConfig
from codegraph_trace.models import Step
from codegraph_trace.recorder import Recorder
from codegraph_trace.reconcile import StaleGraphError, reconcile
from codegraph_trace.store.trace_db import TraceDB

# Unchanged module-level lines sit between add() and the appended multiply() so the two edits
# form separate diff hunks (a contiguous change would resolve to a single symbol).
CALC_V1 = "def add(a, b):\n    return a + b\n\n\nPRECISION = 2\n"
# add() changed to floats AND a brand-new multiply() (lines 8-9) in the same step.
CALC_V2 = (
    "def add(a, b):\n    return float(a) + float(b)\n\n\nPRECISION = 2\n"
    "\n\ndef multiply(a, b):\n    return a * b\n"
)

FRESH_TS = "2030-01-01T00:00:00+00:00"


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *args],
        cwd=str(repo),
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout


def _commit_file(repo: Path, rel: str, content: str, message: str) -> str:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", newline="\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD").strip()


def _build_graph(
    db_path: Path,
    nodes: list[tuple],
    edges: list[tuple],
    *,
    indexed_at: str,
    project: str = "scratch",
) -> None:
    """(Re)build a code graph in the schema codebase-memory-mcp produces."""
    if db_path.exists():
        db_path.unlink()
    conn = sqlite3.connect(db_path)
    conn.executescript(
        """
        CREATE TABLE projects (name TEXT, indexed_at TEXT, root_path TEXT);
        CREATE TABLE nodes (
            id INTEGER PRIMARY KEY, label TEXT, name TEXT, qualified_name TEXT,
            file_path TEXT, start_line INTEGER, end_line INTEGER
        );
        CREATE TABLE edges (source_id INTEGER, target_id INTEGER, type TEXT);
        """
    )
    conn.execute("INSERT INTO projects VALUES (?, ?, ?)", (project, indexed_at, "src"))
    conn.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?)", nodes)
    if edges:
        conn.executemany("INSERT INTO edges VALUES (?, ?, ?)", edges)
    conn.commit()
    conn.close()


_STALE_NODES = [
    (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
    (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
]
_STALE_EDGES = [(1, 2, "DEFINES")]


def _record_session(tmp_path: Path, *, author: str = "agent") -> TraceConfig:
    """One step that changes add() and creates multiply() against a stale graph.

    Returns the config; the recorded multiply link has ``node_id = NULL`` and the synthesized
    qualified name ``scratch.src.calc.multiply``.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    sha1 = _commit_file(repo, "src/calc.py", CALC_V1, "c1: add")

    graph_db = tmp_path / "graph.db"
    # The stale index predates multiply(); its timestamp is unparseable-old on purpose
    # elsewhere, but for recording it just needs to exist.
    _build_graph(graph_db, _STALE_NODES, _STALE_EDGES, indexed_at="2026-01-01T00:00:00+00:00")

    sha2 = _commit_file(repo, "src/calc.py", CALC_V2, "c2: float add + multiply")

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    step = Step(
        step_id="s2",
        prompt="float add and add multiply",
        reasoning_text="floats are safer; multiply is new",
        before_sha=sha1,
        after_sha=sha2,
        author=author,
    )
    with Recorder(config, enable_embeddings=False) as rec:
        result = rec.record_step(step)

    by_qn = {ln.node.qualified_name: ln for ln in result.linked_nodes}
    assert "scratch.src.calc.multiply" in by_qn
    assert by_qn["scratch.src.calc.multiply"].node.node_id is None
    return config


def _links(config: TraceConfig, qn: str) -> list[dict]:
    db = TraceDB(config.trace_db_path)
    try:
        rows = db.conn.execute(
            "SELECT * FROM node_links WHERE qualified_name = ?", (qn,)
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        db.close()


def test_backfill_node_id_after_reindex(tmp_path):
    config = _record_session(tmp_path)

    # Simulate the codebase-memory-mcp re-index: same names, multiply now has node id 3.
    _build_graph(
        config.graph_db_path,
        _STALE_NODES
        + [(3, "Function", "multiply", "scratch.src.calc.multiply", "src/calc.py", 8, 9)],
        _STALE_EDGES + [(1, 3, "DEFINES")],
        indexed_at=FRESH_TS,
    )

    result = reconcile(config, enable_embeddings=False)

    assert [o.qualified_name for o in result.backfilled] == ["scratch.src.calc.multiply"]
    assert result.backfilled[0].node_id == 3
    assert result.renamed == [] and result.unresolved == []
    assert result.steps_updated == 1

    rows = _links(config, "scratch.src.calc.multiply")
    assert len(rows) == 1
    assert rows[0]["node_id"] == 3

    # The signature now carries the graph's span and a real edge fingerprint, so the next
    # session's change classification compares against actual graph state.
    db = TraceDB(config.trace_db_path)
    try:
        sig = db.get_signature("scratch.src.calc.multiply")
    finally:
        db.close()
    assert (sig["start_line"], sig["end_line"]) == (8, 9)
    assert sig["edge_fingerprint"] != ""


def test_dry_run_reports_without_writing(tmp_path):
    config = _record_session(tmp_path)
    _build_graph(
        config.graph_db_path,
        _STALE_NODES
        + [(3, "Function", "multiply", "scratch.src.calc.multiply", "src/calc.py", 8, 9)],
        _STALE_EDGES,
        indexed_at=FRESH_TS,
    )

    result = reconcile(config, dry_run=True, enable_embeddings=False)

    assert result.dry_run is True
    assert [o.qualified_name for o in result.backfilled] == ["scratch.src.calc.multiply"]
    # Nothing was written.
    assert _links(config, "scratch.src.calc.multiply")[0]["node_id"] is None


def test_drift_rename_adopts_canonical_name(tmp_path):
    """The indexer named the new symbol differently than we synthesized it: the graph's
    qualified name wins, the trace is rewritten, and the human lock survives the rename."""
    config = _record_session(tmp_path, author="human")  # human step locks both symbols

    # Re-index under a different naming scheme (the indexer stripped the source root).
    _build_graph(
        config.graph_db_path,
        [
            (1, "File", "calc.py", "scratch2.calc", "src/calc.py", 0, 0),
            (2, "Function", "add", "scratch2.calc.add", "src/calc.py", 1, 2),
            (3, "Function", "multiply", "scratch2.calc.multiply", "src/calc.py", 8, 9),
        ],
        [(1, 2, "DEFINES"), (1, 3, "DEFINES")],
        indexed_at=FRESH_TS,
        project="scratch2",
    )

    result = reconcile(config, enable_embeddings=False)

    assert [o.qualified_name for o in result.renamed] == ["scratch.src.calc.multiply"]
    assert result.renamed[0].new_qualified_name == "scratch2.calc.multiply"
    assert result.renamed[0].node_id == 3
    assert result.backfilled == [] and result.unresolved == []

    # node_links carry the canonical name and the real id; the old name is gone.
    assert _links(config, "scratch.src.calc.multiply") == []
    rows = _links(config, "scratch2.calc.multiply")
    assert len(rows) == 1
    assert rows[0]["node_id"] == 3
    assert rows[0]["label"] == "Function"

    db = TraceDB(config.trace_db_path)
    try:
        # The signature moved to the canonical name, preserving the human lock/provenance.
        assert db.get_signature("scratch.src.calc.multiply") is None
        sig = db.get_signature("scratch2.calc.multiply")
        assert sig is not None
        assert sig["locked"] == 1
        assert sig["author"] == "human"
        assert "scratch2.calc.multiply" in db.human_locked_qualified_names()

        # The co-change pair was re-canonicalized to the new name (add + multiply were edited
        # in the same step).
        pairs = {
            (r["qn_a"], r["qn_b"], r["count"])
            for r in db.conn.execute("SELECT qn_a, qn_b, count FROM co_change").fetchall()
        }
        assert pairs == {("scratch.src.calc.add", "scratch2.calc.multiply", 1)}
        events = {
            (r["qn_a"], r["qn_b"])
            for r in db.conn.execute("SELECT qn_a, qn_b FROM co_change_events").fetchall()
        }
        assert events == {("scratch.src.calc.add", "scratch2.calc.multiply")}
    finally:
        db.close()


def test_ambiguous_candidates_left_unresolved(tmp_path):
    """Two same-named symbols in the file: reconcile must not guess, only report."""
    config = _record_session(tmp_path)

    _build_graph(
        config.graph_db_path,
        _STALE_NODES
        + [
            # Both candidates share the short name and overlap the recorded span (8-9).
            (3, "Function", "multiply", "scratch.src.calc.Alpha.multiply", "src/calc.py", 8, 9),
            (4, "Function", "multiply", "scratch.src.calc.Beta.multiply", "src/calc.py", 8, 10),
        ],
        _STALE_EDGES,
        indexed_at=FRESH_TS,
    )

    result = reconcile(config, enable_embeddings=False)

    assert result.backfilled == [] and result.renamed == []
    assert [o.qualified_name for o in result.unresolved] == ["scratch.src.calc.multiply"]
    assert "ambiguous" in result.unresolved[0].reason

    # Nothing was rewritten.
    rows = _links(config, "scratch.src.calc.multiply")
    assert len(rows) == 1
    assert rows[0]["node_id"] is None


def test_freshness_gate_refuses_stale_graph(tmp_path):
    """A graph indexed before the last recorded step is refused unless forced."""
    config = _record_session(tmp_path)

    # "Re-indexed" graph whose timestamp predates the recorded step.
    _build_graph(
        config.graph_db_path,
        _STALE_NODES,
        _STALE_EDGES,
        indexed_at="2020-01-01T00:00:00+00:00",
    )

    with pytest.raises(StaleGraphError) as excinfo:
        reconcile(config, enable_embeddings=False)
    # The error tells the user the exact MCP call to run.
    assert "index_repository" in str(excinfo.value)

    # --force proceeds (and, against this old graph, simply reports multiply unresolved).
    result = reconcile(config, force=True, enable_embeddings=False)
    assert [o.qualified_name for o in result.unresolved] == ["scratch.src.calc.multiply"]


def test_missing_graph_db_raises(tmp_path):
    config = _record_session(tmp_path)
    Path(config.graph_db_path).unlink()
    with pytest.raises(FileNotFoundError):
        reconcile(config, enable_embeddings=False)


def test_cli_reconcile_reports(tmp_path, capsys):
    from codegraph_trace.cli import main

    config = _record_session(tmp_path)
    _build_graph(
        config.graph_db_path,
        _STALE_NODES
        + [(3, "Function", "multiply", "scratch.src.calc.multiply", "src/calc.py", 8, 9)],
        _STALE_EDGES + [(1, 3, "DEFINES")],
        indexed_at=FRESH_TS,
    )

    rc = main(
        [
            "reconcile",
            "--repo",
            str(config.repo_root),
            "--graph-db",
            str(config.graph_db_path),
            "--no-embeddings",
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "scratch.src.calc.multiply" in out
    assert "node_id=3" in out
    assert _links(config, "scratch.src.calc.multiply")[0]["node_id"] == 3

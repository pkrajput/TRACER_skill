"""Shared symbol → file history lookup (Problems list + panel)."""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.config import TraceConfig
from codegraph_trace.models import Step
from codegraph_trace.panel import create_app
from codegraph_trace.query import TraceQuery, resolve_story
from codegraph_trace.recorder import Recorder
from codegraph_trace.store.trace_db import TraceDB


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


def _write(repo: Path, rel: str, content: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", newline="\n")


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD").strip()


def _tiny_graph(db_path: Path) -> None:
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
    conn.execute("INSERT INTO projects VALUES (?, ?, ?)", ("scratch", "now", "src"))
    conn.execute(
        "INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?)",
        (1, "File", "app.py", "scratch.src.app", "src/app.py", 0, 0),
    )
    conn.execute(
        "INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?)",
        (2, "Function", "main", "scratch.src.app.main", "src/app.py", 1, 2),
    )
    conn.execute("INSERT INTO edges VALUES (?, ?, ?)", (1, 2, "DEFINES"))
    conn.commit()
    conn.close()


@pytest.fixture
def file_only_session(tmp_path: Path) -> TraceConfig:
    """One recorded step linked at file level only (no per-symbol link for an extra QN)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/app.py", "def main():\n    return 1\n")
    sha = _commit(repo, "app")

    graph_db = tmp_path / "graph.db"
    _tiny_graph(graph_db)
    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(
            Step(
                step_id="s1",
                prompt="init",
                reasoning_text="first version of main",
                before_sha=None,
                after_sha=sha,
            )
        )
    return config


def test_resolve_story_symbol_hit(file_only_session: TraceConfig):
    with TraceQuery(file_only_session, enable_embeddings=False) as q:
        # main should be linked by the recorder via AST.
        story = resolve_story(q.db, "scratch.src.app.main")
    assert story.scope == "symbol"
    assert story.steps
    assert story.file_path == "src/app.py"


def test_resolve_story_symbol_miss_falls_back_to_file(file_only_session: TraceConfig):
    with TraceQuery(file_only_session, enable_embeddings=False) as q:
        story = resolve_story(
            q.db,
            "scratch.src.app.never_linked",
            file_path="src/app.py",
        )
    assert story.scope == "file"
    assert story.file_path == "src/app.py"
    assert story.steps
    assert "first version of main" in (story.steps[0].get("reasoning_text") or "")


def test_resolve_story_both_miss_scope_none(file_only_session: TraceConfig):
    with TraceQuery(file_only_session, enable_embeddings=False) as q:
        story = resolve_story(
            q.db,
            "scratch.other.missing",
            file_path="src/missing.py",
        )
    assert story.scope == "none"
    assert story.steps == []


def test_resolve_history_via_trace_query(file_only_session: TraceConfig):
    with TraceQuery(file_only_session, enable_embeddings=False) as q:
        hit = q.resolve_history("scratch.src.app.main")
        assert hit.scope == "symbol"
        assert hit.entries

        fb = q.resolve_history(
            "scratch.src.app.unrecorded_helper", file_path="src/app.py"
        )
        assert fb.scope == "file"
        assert fb.entries

        none = q.resolve_history("totally.missing.symbol", file_path="nope.py")
        assert none.scope == "none"
        assert none.entries == []


def test_panel_history_api_file_fallback(file_only_session: TraceConfig):
    app = create_app(file_only_session)
    app.testing = True
    client = app.test_client()
    raw = client.get(
        "/api/history?target=scratch.src.app.unrecorded_helper&file=src/app.py"
    )
    assert raw.status_code == 200
    data = json.loads(raw.get_data(as_text=True))
    assert data["scope"] == "file"
    assert data["file_path"] == "src/app.py"
    assert data["entries"]
    assert data["target"] == "scratch.src.app.unrecorded_helper"


def test_panel_history_api_none_scope(file_only_session: TraceConfig):
    app = create_app(file_only_session)
    app.testing = True
    client = app.test_client()
    data = json.loads(
        client.get("/api/history?target=scratch.none.here&file=ghost.py")
        .get_data(as_text=True)
    )
    assert data["scope"] == "none"
    assert data["entries"] == []


def test_panel_index_mentions_no_trace_empty_state(file_only_session: TraceConfig):
    app = create_app(file_only_session)
    app.testing = True
    html = app.test_client().get("/").get_data(as_text=True)
    assert "No trace data recorded for this symbol" in html
    assert "showing file history for" in html
    # Structure Decision history always forwards file (+ optional start_line).
    assert "&file=' + encodeURIComponent(filePath)" in html
    assert "start_line=" in html


def _rename_recorded_qn(db_path: Path, old: str, new: str) -> None:
    """Simulate project-prefix drift by rewriting recorded qualified names."""
    conn = sqlite3.connect(db_path)
    for table in ("node_links", "node_signatures", "branches", "proposals"):
        try:
            conn.execute(
                f"UPDATE {table} SET qualified_name = ? WHERE qualified_name = ?",
                (new, old),
            )
        except sqlite3.OperationalError:
            pass
    conn.commit()
    conn.close()


def test_resolve_story_aliases_prefix_drift(file_only_session: TraceConfig):
    """Graph QN with a new machine prefix still resolves to the recorded symbol story."""
    old = "scratch.src.app.main"
    drifted = "old-machine.scratch.src.app.main"
    graph_qn = "new-machine.scratch.src.app.main"
    _rename_recorded_qn(file_only_session.trace_db_path, old, drifted)

    with TraceQuery(file_only_session, enable_embeddings=False) as q:
        miss = resolve_story(q.db, graph_qn)
        assert miss.scope != "symbol"  # no file hint → cannot alias

        story = resolve_story(q.db, graph_qn, file_path="src/app.py")
        assert story.scope == "symbol"
        assert story.steps
        assert story.resolved_qualified_name == drifted
        assert story.target == graph_qn
        assert "first version of main" in (story.steps[0].get("reasoning_text") or "")

        # Exact recorded QN still wins without aliasing.
        exact = resolve_story(q.db, drifted)
        assert exact.scope == "symbol"
        assert exact.resolved_qualified_name is None


def test_resolve_story_ambiguous_short_name_no_alias(file_only_session: TraceConfig):
    """Two same-file symbols sharing a short name stay ambiguous without a span."""
    with TraceQuery(file_only_session, enable_embeddings=False) as q:
        db = q.db
        rows = db.conn.execute(
            "SELECT step_id FROM node_links LIMIT 1"
        ).fetchall()
        assert rows
        step_id = rows[0]["step_id"]
        for qn, lo, hi in (
            ("scratch.src.app.helper", 1, 2),
            ("scratch.src.other.helper", 10, 12),
        ):
            db.conn.execute(
                """
                INSERT OR REPLACE INTO node_links
                    (step_id, node_id, qualified_name, file_path, label, change_kind, author)
                VALUES (?, NULL, ?, ?, ?, ?, ?)
                """,
                (step_id, qn, "src/app.py", "Function", "changed", "human"),
            )
            db.upsert_signature(
                qn, "src/app.py", "Function", lo, hi, f"fp-{lo}", step_id, author="human"
            )
        db.conn.commit()

        # Both end with .helper; equal suffix score → no alias without a span.
        ambiguous = resolve_story(
            q.db,
            "new.prefix.helper",
            file_path="src/app.py",
        )
        assert ambiguous.scope == "file"
        assert ambiguous.resolved_qualified_name is None

        hit = resolve_story(
            q.db,
            "new.prefix.helper",
            file_path="src/app.py",
            start_line=10,
            end_line=12,
        )
        assert hit.scope == "symbol"
        assert hit.resolved_qualified_name == "scratch.src.other.helper"


def test_panel_history_api_prefix_drift(file_only_session: TraceConfig):
    old = "scratch.src.app.main"
    drifted = "Users-old.scratch.src.app.main"
    graph_qn = "C-Users-new.scratch.src.app.main"
    _rename_recorded_qn(file_only_session.trace_db_path, old, drifted)

    app = create_app(file_only_session)
    app.testing = True
    client = app.test_client()
    data = json.loads(
        client.get(
            f"/api/history?target={graph_qn}&file=src/app.py&start_line=1"
        ).get_data(as_text=True)
    )
    assert data["scope"] == "symbol"
    assert data["target"] == graph_qn
    assert data["resolved_qualified_name"] == drifted
    assert data["entries"]


def test_structure_marks_recorded_despite_prefix_drift(
    file_only_session: TraceConfig, tmp_path: Path
):
    """Structure overlay aliases graph QNs onto recorded ones for teal badges."""
    old = "scratch.src.app.main"
    drifted = "Users-old.scratch.src.app.main"
    graph_qn = "C-Users-new.scratch.src.app.main"
    _rename_recorded_qn(file_only_session.trace_db_path, old, drifted)

    # Re-index-style graph uses the new machine prefix for the same symbol.
    graph_db = tmp_path / "graph-new.db"
    conn = sqlite3.connect(graph_db)
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
    conn.execute(
        "INSERT INTO projects VALUES (?, ?, ?)", ("C-Users-new", "now", "src")
    )
    conn.execute(
        "INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?)",
        (1, "File", "app.py", "C-Users-new.scratch.src.app", "src/app.py", 0, 0),
    )
    conn.execute(
        "INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?)",
        (2, "Function", "main", graph_qn, "src/app.py", 1, 2),
    )
    conn.commit()
    conn.close()

    config = TraceConfig(
        repo_root=file_only_session.repo_root,
        graph_db_path=graph_db,
        trace_dir=file_only_session.trace_dir,
        embedding_model="hash",
    )
    app = create_app(config)
    app.testing = True
    data = json.loads(app.test_client().get("/api/structure").get_data(as_text=True))
    files = {f["file_path"]: f for f in data["files"]}
    syms = {s["qualified_name"]: s for s in files["src/app.py"]["symbols"]}
    assert graph_qn in syms
    assert syms[graph_qn]["recorded"] is True
    assert syms[graph_qn]["touch_count"] >= 1

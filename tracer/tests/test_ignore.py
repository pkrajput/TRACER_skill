"""Exclude .codegraph-trace/ from source attribution even when tracked."""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.config import TraceConfig
from codegraph_trace.ignore import (
    ensure_gitignore,
    ensure_trace_ignored,
    is_trace_path,
)
from codegraph_trace.models import Step
from codegraph_trace.panel import create_app
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


@pytest.mark.parametrize(
    "path,expected",
    [
        (".codegraph-trace/trace.db", True),
        (".codegraph-trace/snapshots/abc.json", True),
        (".codegraph-trace-openhands/conv/events/e.json", True),
        (".codegraph-trace", True),
        ("./.codegraph-trace/foo", True),
        (".codegraph-trace\\snapshots\\x.json", True),
        ("src/app.py", False),
        ("codegraph-trace/not-ours", False),
    ],
)
def test_is_trace_path(path: str, expected: bool):
    assert is_trace_path(path) is expected


def test_ensure_gitignore_appends_and_is_idempotent(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    assert ensure_gitignore(repo) is True
    text = (repo / ".gitignore").read_text(encoding="utf-8")
    assert ".codegraph-trace/" in text
    assert ".codegraph-trace-openhands/" in text
    assert ensure_gitignore(repo) is False
    assert (repo / ".gitignore").read_text(encoding="utf-8") == text


def test_tracked_trace_dir_not_attributed(tmp_path: Path):
    """Even when .codegraph-trace/ is committed, record_step must not link it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/app.py", "def main():\n    return 1\n")
    # Deliberately commit the recording layer's own output as if it were source.
    _write(repo, ".codegraph-trace/snapshots/seed.json", '{"seed": true}\n')
    before = _commit(repo, "seed with tracked trace dir")

    _write(repo, "src/app.py", "def main():\n    return 2\n")
    _write(repo, ".codegraph-trace/snapshots/seed.json", '{"seed": false}\n')
    after = _commit(repo, "app change plus trace snapshot")

    graph_db = tmp_path / "graph.db"
    _tiny_graph(graph_db)
    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")

    with Recorder(config, enable_embeddings=False) as rec:
        result = rec.record_step(
            Step(
                step_id="s1",
                prompt="bump main",
                reasoning_text="return 2",
                before_sha=before,
                after_sha=after,
            )
        )

    assert all(not is_trace_path(f) for f in result.changed_files)
    assert "src/app.py" in result.changed_files
    assert all(not is_trace_path(ln.node.file_path or "") for ln in result.linked_nodes)

    db = TraceDB(config.trace_db_path)
    try:
        links = db.conn.execute(
            "SELECT file_path FROM node_links WHERE step_id = ?", ("s1",)
        ).fetchall()
        assert links
        assert all(not is_trace_path(r["file_path"] or "") for r in links)
        rows = db.conn.execute("SELECT qn_a, qn_b FROM co_change").fetchall()
        for r in rows:
            assert ".codegraph-trace" not in (r["qn_a"] or "")
            assert ".codegraph-trace" not in (r["qn_b"] or "")
    finally:
        db.close()


def test_panel_hides_polluted_trace_paths(tmp_path: Path):
    """Historical DB rows under .codegraph-trace/ must not appear in panel APIs."""
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
                reasoning_text="first",
                before_sha=None,
                after_sha=sha,
            )
        )

    # Plant polluted historical attribution as if an older recorder had linked the snapshot.
    db = TraceDB(config.trace_db_path)
    try:
        db.conn.execute(
            """
            UPDATE steps SET changed_files = ?
            WHERE step_id = 's1'
            """,
            ("src/app.py,.codegraph-trace/snapshots/seed.json",),
        )
        db.conn.execute(
            """
            INSERT INTO node_links
              (step_id, node_id, qualified_name, file_path, change_kind, author)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "s1",
                None,
                "file::.codegraph-trace/snapshots/seed.json",
                ".codegraph-trace/snapshots/seed.json",
                "changed",
                "agent",
            ),
        )
        db.conn.commit()
    finally:
        db.close()

    app = create_app(config)
    app.testing = True
    client = app.test_client()

    files = json.loads(client.get("/api/files").get_data(as_text=True))["files"]
    paths = {f["file_path"] for f in files}
    assert "src/app.py" in paths
    assert not any(is_trace_path(p) for p in paths)

    nodes = json.loads(client.get("/api/nodes").get_data(as_text=True))["nodes"]
    assert not any(is_trace_path(n.get("file_path") or "") for n in nodes)
    assert not any(
        is_trace_path((n.get("qualified_name") or "").removeprefix("file::"))
        for n in nodes
    )

    step = json.loads(client.get("/api/step?seq=1").get_data(as_text=True))
    assert "src/app.py" in step["step"]["changed_files"]
    assert all(not is_trace_path(f) for f in step["step"]["changed_files"])
    assert all(not is_trace_path(n.get("file_path") or "") for n in step["nodes"])


def test_ensure_trace_ignored_writes_gitignore(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    ensure_trace_ignored(repo)
    text = (repo / ".gitignore").read_text(encoding="utf-8")
    assert ".codegraph-trace/" in text

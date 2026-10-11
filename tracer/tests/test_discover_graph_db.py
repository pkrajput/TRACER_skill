"""Code-map discovery must never pick another project's database."""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest

from codegraph_trace.cli import main
from codegraph_trace.config import (
    GraphDbSetupError,
    TraceConfig,
    canonical_repo_path,
    discover_graph_db,
    graph_db_match_status,
    graph_db_setup_message,
    resolve_graph_db,
)


def _write_graph(db_path: Path, *, name: str, root_path: str) -> None:
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
    conn.execute(
        "INSERT INTO projects VALUES (?, ?, ?)",
        (name, "now", root_path),
    )
    conn.commit()
    conn.close()


def test_canonical_repo_path_normalizes_slashes_and_case():
    a = canonical_repo_path("C:/Users/Demo/Repo")
    b = canonical_repo_path(r"C:\Users\Demo\Repo")
    assert a == b
    assert a.endswith("users/demo/repo") or "users/demo/repo" in a


def test_discover_skips_wrong_project_cache_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    repo = tmp_path / "North"
    repo.mkdir()
    other = tmp_path / "Other"
    other.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setenv("CBM_CACHE_DIR", str(cache))
    monkeypatch.delenv("CODEGRAPH_DB", raising=False)

    # Alphabetically first — the old buggy discovery would return this.
    wrong = cache / "A-Other.db"
    right = cache / "Z-North.db"
    _write_graph(wrong, name="Other", root_path=str(other.resolve()).replace("\\", "/"))
    _write_graph(right, name="North", root_path=str(repo.resolve()).replace("\\", "/"))

    found = discover_graph_db(repo)
    assert found == right
    assert graph_db_match_status(wrong, repo) == "mismatch"
    assert graph_db_match_status(right, repo) == "match"


def test_discover_returns_none_when_only_wrong_projects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo = tmp_path / "North"
    repo.mkdir()
    other = tmp_path / "Other"
    other.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setenv("CBM_CACHE_DIR", str(cache))
    monkeypatch.delenv("CODEGRAPH_DB", raising=False)

    _write_graph(
        cache / "A-Other.db",
        name="Other",
        root_path=str(other.resolve()).replace("\\", "/"),
    )

    assert discover_graph_db(repo) is None
    with pytest.raises(GraphDbSetupError) as exc:
        resolve_graph_db(repo, require=True)
    assert "No code-map database found" in str(exc.value)
    assert "index_repository" in graph_db_setup_message(repo)


def test_env_codegraph_db_wrong_project_is_ignored(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    repo = tmp_path / "North"
    repo.mkdir()
    other = tmp_path / "Other"
    other.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setenv("CBM_CACHE_DIR", str(cache))

    wrong = cache / "wrong.db"
    _write_graph(wrong, name="Other", root_path=str(other.resolve()).replace("\\", "/"))
    monkeypatch.setenv("CODEGRAPH_DB", str(wrong))

    assert discover_graph_db(repo) is None


def test_explicit_mismatch_raises(tmp_path: Path):
    repo = tmp_path / "North"
    repo.mkdir()
    other = tmp_path / "Other"
    other.mkdir()
    wrong = tmp_path / "wrong.db"
    _write_graph(wrong, name="Other", root_path=str(other.resolve()).replace("\\", "/"))

    with pytest.raises(GraphDbSetupError):
        TraceConfig(repo_root=repo, graph_db_path=wrong, embedding_model="hash")


def test_synthetic_relative_root_path_allowed_when_explicit(tmp_path: Path):
    """Unit-test graphs often use root_path='src'; treat as unknown, allow explicit."""
    repo = tmp_path / "repo"
    repo.mkdir()
    db = tmp_path / "graph.db"
    _write_graph(db, name="scratch", root_path="src")
    assert graph_db_match_status(db, repo) == "unknown"
    cfg = TraceConfig(repo_root=repo, graph_db_path=db, embedding_model="hash")
    assert cfg.graph_db_path == db


def test_resolve_graph_db_cli_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    repo = tmp_path / "North"
    repo.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setenv("CBM_CACHE_DIR", str(cache))
    monkeypatch.delenv("CODEGRAPH_DB", raising=False)

    right = cache / "North.db"
    _write_graph(right, name="North", root_path=str(repo.resolve()).replace("\\", "/"))

    rc = main(["resolve-graph-db", "--repo", str(repo), "--json"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True
    assert Path(data["graph_db"]) == right


def test_resolve_graph_db_cli_setup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    repo = tmp_path / "North"
    repo.mkdir()
    cache = tmp_path / "cache"
    cache.mkdir()
    monkeypatch.setenv("CBM_CACHE_DIR", str(cache))
    monkeypatch.delenv("CODEGRAPH_DB", raising=False)

    rc = main(["resolve-graph-db", "--repo", str(repo), "--json"])
    assert rc == 2
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is False
    assert data["graph_db"] is None
    assert "No code-map database found" in data["error"]

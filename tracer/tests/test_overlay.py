"""Tests for the editor-overlay CLI commands (Part 3 hover/gutter data).

- ``overlay <file> --json``: every recorded symbol in a file with its span, provenance
  and last reasoning - one call per open editor file.
- ``symbol-at <file> --line N --json``: the innermost recorded symbol at a cursor line
  (graph spans first, recorded signature spans as the fallback).
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.cli import main
from codegraph_trace.config import TraceConfig
from codegraph_trace.models import Step
from codegraph_trace.recorder import Recorder

CALC_V1 = "def add(a, b):\n    return a + b\n"
CALC_V2 = CALC_V1 + "\n\ndef better_helper():\n    return 2\n"


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


def _stale_graph(db_path: Path) -> None:
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
    conn.execute("INSERT INTO projects VALUES (?, ?, ?)", ("scratch", "2026", "src"))
    conn.executemany(
        "INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
            (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
        ],
    )
    conn.execute("INSERT INTO edges VALUES (?, ?, ?)", (1, 2, "DEFINES"))
    conn.commit()
    conn.close()


@pytest.fixture
def session(tmp_path: Path) -> TraceConfig:
    """Two recorded steps over src/calc.py: add() then better_helper() (a new symbol the
    stale graph does not know, so its span comes from the live AST / signatures)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)
    sha1 = _commit(repo, "step1: add")
    _write(repo, "src/calc.py", CALC_V2)
    sha2 = _commit(repo, "step2: better_helper")

    graph_db = tmp_path / "graph.db"
    _stale_graph(graph_db)

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(step_id="oh-conv1-1", prompt="create add",
                             reasoning_text="write the add function",
                             before_sha=None, after_sha=sha1))
        rec.record_step(Step(step_id="oh-conv1-2", prompt="add a helper",
                             reasoning_text="add better_helper for the new case",
                             before_sha=sha1, after_sha=sha2))
    return config


def _run_json(args: list[str], capsys) -> dict:
    rc = main(args)
    assert rc == 0
    return json.loads(capsys.readouterr().out)


def test_overlay_lists_recorded_symbols_with_reasoning(session, capsys):
    out = _run_json(
        ["overlay", "src/calc.py", "--json",
         "--repo", str(session.repo_root), "--graph-db", str(session.graph_db_path)],
        capsys,
    )
    assert out["file"] == "src/calc.py"
    by_qn = {s["qualified_name"]: s for s in out["symbols"]}

    add = by_qn["scratch.src.calc.add"]
    assert add["start_line"] == 1
    assert add["author"] == "agent"
    assert add["locked"] is False
    assert add["last_seq"] == 1
    assert add["last_reasoning"] == "write the add function"

    helper = by_qn["scratch.src.calc.better_helper"]
    assert helper["start_line"] > 2  # live-AST span, not folded into add()
    assert helper["last_seq"] == 2
    assert helper["last_reasoning"] == "add better_helper for the new case"


def test_overlay_text_mode_and_missing_file(session, capsys):
    rc = main(["overlay", "src/calc.py",
               "--repo", str(session.repo_root), "--graph-db", str(session.graph_db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "scratch.src.calc.add" in out

    rc = main(["overlay", "src/nope.py",
               "--repo", str(session.repo_root), "--graph-db", str(session.graph_db_path)])
    assert rc == 0
    assert "No recorded symbols" in capsys.readouterr().out


def test_symbol_at_resolves_graph_and_signature_spans(session, capsys):
    # Line 1 is add(): the stale graph knows this span.
    out = _run_json(
        ["symbol-at", "src/calc.py", "--line", "1", "--json",
         "--repo", str(session.repo_root), "--graph-db", str(session.graph_db_path)],
        capsys,
    )
    assert out["qualified_name"] == "scratch.src.calc.add"

    # better_helper() is new: absent from the stale graph, resolved from the recorded
    # signature span instead.
    out = _run_json(
        ["symbol-at", "src/calc.py", "--line", "5", "--json",
         "--repo", str(session.repo_root), "--graph-db", str(session.graph_db_path)],
        capsys,
    )
    assert out["qualified_name"] == "scratch.src.calc.better_helper"

    # A line inside no recorded symbol reports null.
    out = _run_json(
        ["symbol-at", "src/calc.py", "--line", "3", "--json",
         "--repo", str(session.repo_root), "--graph-db", str(session.graph_db_path)],
        capsys,
    )
    assert out["qualified_name"] is None

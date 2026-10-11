"""Tests for ``symbol-content``: one symbol's text at a recorded point in time.

Powers the editor's per-symbol restore (a WorkspaceEdit over just the symbol's span,
instead of checking out a whole version). Covers:

- the text of a symbol as of an earlier step (``--at-seq``), sliced from git via the
  live AST (same approach as the branch derivation);
- the dead code of an abandoned attempt (``--branch-id``);
- the current working-tree span (present vs deleted symbol);
- selector validation (exactly one of --at-seq / --branch-id).
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.branches import derive_branches
from codegraph_trace.cli import main
from codegraph_trace.config import TraceConfig
from codegraph_trace.models import Step
from codegraph_trace.recorder import Recorder
from codegraph_trace.store.trace_db import TraceDB

CALC_V1 = "def add(a, b):\n    return a + b\n"
CALC_V2 = CALC_V1 + "\n\ndef helper():\n    return 1\n"
CALC_V3 = CALC_V1 + "\n\ndef better_helper():\n    return 2\n"


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
    conn.commit()
    conn.close()


@pytest.fixture
def session(tmp_path: Path) -> TraceConfig:
    """3-step session: step 2 adds helper(), step 3 deletes and replaces it."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    p = repo / "src/calc.py"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(CALC_V1, encoding="utf-8", newline="\n")
    sha1 = _commit(repo, "step1")
    p.write_text(CALC_V2, encoding="utf-8", newline="\n")
    sha2 = _commit(repo, "step2")
    p.write_text(CALC_V3, encoding="utf-8", newline="\n")
    sha3 = _commit(repo, "step3")

    graph_db = tmp_path / "graph.db"
    _stale_graph(graph_db)
    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(step_id="oh-conv1-1", prompt="p1", reasoning_text="r1",
                             before_sha=None, after_sha=sha1))
        rec.record_step(Step(step_id="oh-conv1-2", prompt="p2", reasoning_text="r2",
                             before_sha=sha1, after_sha=sha2))
        rec.record_step(Step(step_id="oh-conv1-3", prompt="p3", reasoning_text="r3",
                             before_sha=sha2, after_sha=sha3))
    derive_branches(config)
    return config


def _run_json(args: list[str], capsys) -> dict:
    rc = main(args)
    assert rc == 0
    return json.loads(capsys.readouterr().out)


def _common(config: TraceConfig) -> list[str]:
    return ["--repo", str(config.repo_root), "--graph-db", str(config.graph_db_path)]


def test_at_seq_of_a_deleted_symbol(session: TraceConfig, capsys):
    """helper() existed at step 2 and is gone from the working tree at step 3."""
    out = _run_json(
        ["symbol-content", "src/calc.py", "scratch.src.calc.helper",
         "--at-seq", "2", "--json", *_common(session)],
        capsys,
    )
    assert "def helper():" in out["historical"]["content"]
    assert out["historical"]["source_seq"] == 2
    assert out["historical"]["source"] == "git"
    assert out["current"]["exists"] is False  # deleted at step 3


def test_at_seq_of_a_live_symbol(session: TraceConfig, capsys):
    out = _run_json(
        ["symbol-content", "src/calc.py", "scratch.src.calc.better_helper",
         "--at-seq", "3", "--json", *_common(session)],
        capsys,
    )
    assert "def better_helper():" in out["historical"]["content"]
    cur = out["current"]
    assert cur["exists"] is True
    assert cur["start_line"] == 5  # CALC_V3: add L1-2, blanks, better_helper L5-6
    assert cur["end_line"] == 6


def test_branch_id_returns_abandoned_content(session: TraceConfig, capsys):
    db = TraceDB(session.trace_db_path)
    try:
        row = db.conn.execute(
            "SELECT branch_id FROM branches "
            "WHERE kind = 'abandoned' AND qualified_name != ''"
        ).fetchone()
    finally:
        db.close()
    assert row is not None

    out = _run_json(
        ["symbol-content", "src/calc.py", "scratch.src.calc.helper",
         "--branch-id", str(row["branch_id"]), "--json", *_common(session)],
        capsys,
    )
    assert "def helper():" in out["historical"]["content"]
    assert out["historical"]["source"] == "branch"
    assert out["historical"]["kind"] == "abandoned"
    assert out["current"]["exists"] is False


def test_selector_validation(session: TraceConfig, capsys):
    # Neither selector, and both selectors, are rejected.
    rc = main(["symbol-content", "src/calc.py", "scratch.src.calc.helper",
               "--json", *_common(session)])
    assert rc == 1
    capsys.readouterr()
    rc = main(["symbol-content", "src/calc.py", "scratch.src.calc.helper",
               "--at-seq", "2", "--branch-id", "1", "--json", *_common(session)])
    assert rc == 1
    capsys.readouterr()
    # An unknown branch id fails cleanly too.
    rc = main(["symbol-content", "src/calc.py", "scratch.src.calc.helper",
               "--branch-id", "99999", "--json", *_common(session)])
    assert rc == 1

"""The decision ledger (branches table), derived deterministically from steps + git.

Acceptance checks from the spec:

- Synthetic: a 3-step session where step 2 adds a function and step 3 deletes and replaces
  it yields exactly one abandoned symbol row for step 2, superseded by step 3.
- Idempotency: running derive twice gives a byte-identical table.
- error_retry: an error observation followed by an action on the same file in a step's raw
  event trail yields an error_retry row.
- The ledger is joined back onto the spine: `history` prints the branch markers and
  `branches show --json` emits machine-readable rows.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.branches import derive_branches, session_for_step_id
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


def _write(repo: Path, rel: str, content: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8", newline="\n")


def _commit(repo: Path, message: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)
    return _git(repo, "rev-parse", "HEAD").strip()


def _stale_graph(db_path: Path, nodes: list[tuple], edges: list[tuple]) -> None:
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
    conn.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?)", nodes)
    if edges:
        conn.executemany("INSERT INTO edges VALUES (?, ?, ?)", edges)
    conn.commit()
    conn.close()


@pytest.fixture
def three_step_session(tmp_path: Path):
    """A 3-step session: step 1 creates add(), step 2 adds helper(), step 3 deletes helper()
    and replaces it with better_helper(). helper() is the abandoned branch."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)
    sha1 = _commit(repo, "step1: add")
    _write(repo, "src/calc.py", CALC_V2)
    sha2 = _commit(repo, "step2: helper")
    _write(repo, "src/calc.py", CALC_V3)
    sha3 = _commit(repo, "step3: replace helper")

    graph_db = tmp_path / "graph.db"
    _stale_graph(
        graph_db,
        nodes=[
            (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
            (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
        ],
        edges=[(1, 2, "DEFINES")],
    )

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(step_id="oh-conv1-1", prompt="create add",
                             reasoning_text="write add", before_sha=None, after_sha=sha1))
        rec.record_step(Step(step_id="oh-conv1-2", prompt="add a helper",
                             reasoning_text="first helper attempt",
                             before_sha=sha1, after_sha=sha2))
        rec.record_step(Step(step_id="oh-conv1-3", prompt="improve the helper",
                             reasoning_text="replace helper with better_helper",
                             before_sha=sha2, after_sha=sha3))
    return config, repo, (sha1, sha2, sha3)


def _dump_branches(config: TraceConfig) -> list[tuple]:
    db = TraceDB(config.trace_db_path)
    try:
        return [tuple(r) for r in db.conn.execute("SELECT * FROM branches ORDER BY branch_id")]
    finally:
        db.close()


def test_session_id_parsing():
    assert session_for_step_id("oh-conv1-5") == "conv1"
    # Conversation ids may contain hyphens; the trailing event id never does.
    assert session_for_step_id("oh-a1b2-c3d4-17") == "a1b2-c3d4"
    assert session_for_step_id("oh-conv-n3") == "conv"
    # Live V1 sessions use a hyphenated UUID as the event id; every step of the same
    # conversation must land in the same session.
    assert session_for_step_id(
        "oh-538cfabda6f54214b21ee34204be684e-9bd092fe-d460-4c83-a862-7238da59aef1"
    ) == "538cfabda6f54214b21ee34204be684e"
    # Manually recorded steps form their own session.
    assert session_for_step_id("my-manual-edit!") == "manual"
    assert session_for_step_id("s2") == "manual"


def test_abandoned_function_detected_and_superseded(three_step_session):
    config, repo, shas = three_step_session
    result = derive_branches(config)
    assert result.total_rows > 0

    db = TraceDB(config.trace_db_path)
    try:
        # Exactly one abandoned symbol row: helper(), added at step 2.
        rows = db.conn.execute(
            "SELECT * FROM branches WHERE kind = 'abandoned' AND qualified_name != ''"
        ).fetchall()
        assert len(rows) == 1
        row = rows[0]
        assert row["step_id"] == "oh-conv1-2"
        assert row["session_id"] == "conv1"
        assert row["seq"] == 2
        assert row["qualified_name"] == "scratch.src.calc.helper"
        assert row["file_path"] == "src/calc.py"
        # Superseded by step 3, the replacement.
        assert row["superseded_by_step_id"] == "oh-conv1-3"
        # The dead code text itself is preserved.
        assert "def helper():" in row["abandoned_content"]
        assert row["survival_ratio"] == 0.0

        # Step 2's file-level row is abandoned too (everything it added is gone at FINAL).
        file_row = db.conn.execute(
            "SELECT * FROM branches WHERE kind = 'abandoned' AND qualified_name = ''"
        ).fetchone()
        assert file_row is not None
        assert file_row["step_id"] == "oh-conv1-2"
        assert file_row["superseded_by_step_id"] == "oh-conv1-3"

        # Steps 1 and 3 added code that survives to the session's final state.
        survived_steps = {
            r["step_id"]
            for r in db.conn.execute(
                "SELECT DISTINCT step_id FROM branches WHERE kind = 'survived'"
            )
        }
        assert {"oh-conv1-1", "oh-conv1-3"} <= survived_steps
        assert "oh-conv1-2" not in survived_steps

        # Step 2 is a decision point; step 3 is the superseder (also important).
        important = db.important_step_ids()
        assert "oh-conv1-2" in important
        assert "oh-conv1-3" in important
        assert "oh-conv1-1" not in important
    finally:
        db.close()


def test_derive_is_idempotent(three_step_session):
    config, repo, shas = three_step_session
    derive_branches(config)
    first = _dump_branches(config)
    derive_branches(config)
    second = _dump_branches(config)
    assert first == second
    assert first  # non-empty: the comparison is meaningful


def test_derive_single_session_filter(three_step_session):
    config, repo, shas = three_step_session
    result = derive_branches(config, session="conv1")
    assert set(result.sessions) == {"conv1"}
    assert result.sessions["conv1"] > 0
    # A non-existent session derives nothing (and leaves the table alone).
    empty = derive_branches(config, session="nope")
    assert empty.sessions == {}
    assert _dump_branches(config)  # conv1 rows still present


def test_error_retry_rows(tmp_path):
    """An error observation followed by an action on the same file in a step's raw event
    trail yields one error_retry row for that step."""
    repo = tmp_path / "repo-err"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)
    sha1 = _commit(repo, "c1")
    _write(repo, "src/calc.py", CALC_V1 + "\n\ndef fixed():\n    return 3\n")
    sha2 = _commit(repo, "c2: fix after failure")

    graph_db = tmp_path / "graph.db"
    _stale_graph(
        graph_db,
        nodes=[
            (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
            (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
        ],
        edges=[(1, 2, "DEFINES")],
    )

    raw = [
        {"kind": "ActionEvent", "action": "run", "args": {"command": "pytest"}},
        {
            "kind": "ObservationEvent",
            "content": "Traceback (most recent call last):\n  ...\nNameError: fixed",
        },
        {"kind": "ActionEvent", "action": "edit", "args": {"path": "src/calc.py"}},
    ]
    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(step_id="oh-errconv-1", prompt="fix the test",
                             reasoning_text="retry after the traceback",
                             before_sha=sha1, after_sha=sha2, raw_event=raw))

    derive_branches(config)

    db = TraceDB(config.trace_db_path)
    try:
        rows = db.conn.execute(
            "SELECT * FROM branches WHERE kind = 'error_retry'"
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["step_id"] == "oh-errconv-1"
        assert rows[0]["file_path"] == "src/calc.py"
        assert rows[0]["qualified_name"] == ""
        # The error_retry row is in addition to the survived/abandoned rows.
        other = db.conn.execute(
            "SELECT COUNT(*) AS c FROM branches WHERE kind != 'error_retry'"
        ).fetchone()
        assert other["c"] > 0
        # An error retry marks the step as a decision point.
        assert "oh-errconv-1" in db.important_step_ids()
    finally:
        db.close()


def test_cli_derive_and_show(three_step_session, capsys):
    from codegraph_trace.cli import main

    config, repo, shas = three_step_session
    rc = main(["branches", "derive", "--repo", str(repo),
               "--graph-db", str(config.graph_db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "branch row(s)" in out
    assert "conv1" in out

    rc = main(["branches", "show", "--json", "--repo", str(repo),
               "--graph-db", str(config.graph_db_path)])
    assert rc == 0
    rows = json.loads(capsys.readouterr().out)
    assert any(
        r["kind"] == "abandoned" and r["qualified_name"] == "scratch.src.calc.helper"
        for r in rows
    )
    # Rows carry the step's reasoning and the rule-based importance marker for the plugin.
    abandoned = next(r for r in rows if r["qualified_name"] == "scratch.src.calc.helper")
    assert abandoned["reasoning_text"] == "first helper attempt"
    assert abandoned["important"] is True
    assert abandoned["superseded_by_seq"] == 3

    # Human-readable variant, filtered to the symbol.
    rc = main(["branches", "show", "scratch.src.calc.helper", "--repo", str(repo),
               "--graph-db", str(config.graph_db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "abandoned" in out
    assert "replaced by step 3" in out
    assert "def helper():" in out


def test_history_shows_branch_markers(three_step_session, capsys):
    from codegraph_trace.cli import main

    config, repo, shas = three_step_session
    derive_branches(config)

    rc = main(["history", "scratch.src.calc.helper", "--repo", str(repo),
               "--graph-db", str(config.graph_db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "[abandoned - superseded by step 3]" in out

    # A surviving symbol reads [survived].
    rc = main(["history", "scratch.src.calc.better_helper", "--repo", str(repo),
               "--graph-db", str(config.graph_db_path)])
    assert rc == 0
    assert "[survived]" in capsys.readouterr().out


def test_versions_tags_decision_steps(three_step_session, capsys):
    from codegraph_trace.cli import main

    config, repo, shas = three_step_session
    derive_branches(config)

    rc = main(["versions", "--repo", str(repo), "--graph-db", str(config.graph_db_path)])
    assert rc == 0
    out = capsys.readouterr().out
    lines = [ln for ln in out.splitlines() if ln.strip().startswith(("1 ", "2 ", "3 "))]
    by_seq = {int(ln.split()[0]): ln for ln in lines}
    assert "[decision]" not in by_seq[1]
    assert "[decision]" in by_seq[2]  # the abandoned attempt
    assert "[decision]" in by_seq[3]  # the superseding replacement

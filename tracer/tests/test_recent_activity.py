"""No-target `history` recent-activity view."""

from __future__ import annotations

from pathlib import Path

from codegraph_trace.config import TraceConfig
from codegraph_trace.query import HistoryEntry, TraceQuery, format_recent_activity
from codegraph_trace.store.trace_db import TraceDB


def _seed_steps(db: TraceDB, n: int) -> None:
    for i in range(1, n + 1):
        db.conn.execute(
            "INSERT INTO steps (step_id, prompt, reasoning_text, timestamp, seq, author) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (f"s{i}", "p", f"reasoning for step {i}\nsecond line", f"t{i}", i,
             "human" if i == n else "agent"),
        )
        db.conn.execute(
            "INSERT INTO node_links (step_id, qualified_name, file_path, change_kind) "
            "VALUES (?, ?, ?, ?)",
            (f"s{i}", f"repo.js.app.fn{i}", "js/app.js", "changed"),
        )
    db.conn.commit()


def _config(tmp_path: Path) -> TraceConfig:
    repo = tmp_path / "repo"
    (repo / ".codegraph-trace").mkdir(parents=True)
    return TraceConfig(repo_root=repo)


# -- recent activity (history with no target) ------------------------------


def test_recent_activity_returns_newest_first(tmp_path):
    config = _config(tmp_path)
    db = TraceDB(config.trace_dir / "trace.db")
    _seed_steps(db, 14)
    db.conn.close()
    with TraceQuery(config, enable_embeddings=False) as q:
        entries, total = q.recent_activity(limit=10)
    assert total == 14
    assert [e.seq for e in entries] == list(range(14, 4, -1))
    assert entries[0].step_id == "s14"
    assert entries[0].nodes and entries[0].nodes[0]["file_path"] == "js/app.js"


def test_format_recent_activity_output():
    entries = [
        HistoryEntry(
            step_id="human-17-draw-status", timestamp="t", before_sha=None,
            after_sha="f1589f2d52aa", prompt="",
            reasoning_text="Name the draw outcome in the status line.\nsecond line ignored",
            nodes=[{"qualified_name": "repo.js.chess.Chess",
                    "file_path": "js/chess.js", "change_kind": "changed",
                    "author": "human"}],
            seq=17, author="human",
        )
    ]
    out = format_recent_activity(entries, 17)
    assert "last 1 of 17" in out
    assert "step#17 human-17-draw-status" in out
    assert "[human]" in out
    assert "Name the draw outcome in the status line." in out
    assert "second line ignored" not in out  # summary view: first line only
    assert "files: js/chess.js" in out
    assert "~ changed (1): Chess [human-written]" in out
    assert "codegraph-trace history <target>" in out


def test_format_recent_activity_empty():
    assert "No trace data" in format_recent_activity([], 0)

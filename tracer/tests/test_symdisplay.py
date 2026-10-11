"""Readable "objects touched" rendering for symbols a step touched."""

from __future__ import annotations

from codegraph_trace import symdisplay
from codegraph_trace.query import format_touched_nodes
from codegraph_trace.store.trace_db import TraceDB

QN = "Users-prateek.rajput-Documents-epsilonAI-TRACER-e2e_demo-game.js.chess"


# -- symdisplay -----------------------------------------------------------


def test_short_symbol_name_strips_repo_prefix():
    assert symdisplay.short_symbol_name(f"{QN}.Chess.clear", "js/chess.js") == "Chess.clear"
    assert (
        symdisplay.short_symbol_name(f"{QN}.Chess.generate_moves.add_move", "js/chess.js")
        == "Chess.generate_moves.add_move"
    )


def test_short_symbol_name_special_cases():
    # Whole-file nodes read as the file path, not "__file__".
    assert symdisplay.short_symbol_name(f"{QN}.__file__", "js/chess.js") == "js/chess.js"
    # file:: pseudo-nodes keep their path.
    assert symdisplay.short_symbol_name("file::.gitignore", None) == ".gitignore"
    # File-level node whose qualified name IS the module (index.html).
    assert symdisplay.short_symbol_name("some-repo.index", "index.html") == "index.html"
    # CSS selectors survive the module strip.
    css = "some-repo.css.style..side-btn:hover"
    assert symdisplay.short_symbol_name(css, "css/style.css") == ".side-btn:hover"
    # No file hint: fall back to the last two segments.
    assert symdisplay.short_symbol_name(f"{QN}.Chess.clear", None) == "Chess.clear"


def test_summarize_groups_and_dedupes():
    nodes = [
        {"qualified_name": f"{QN}.Chess.clear", "file_path": "js/chess.js", "change_kind": "added"},
        # Duplicate row (as produced by the old lineage join fan-out): merged, locked wins.
        {
            "qualified_name": f"{QN}.Chess.clear",
            "file_path": "js/chess.js",
            "change_kind": "added",
            "locked": 1,
        },
        {
            "qualified_name": f"{QN}.Chess.reset",
            "file_path": "js/chess.js",
            "change_kind": "changed",
            "author": "human",
        },
        {"qualified_name": f"{QN}.Chess.perft", "file_path": "js/chess.js", "change_kind": "removed"},
    ]
    groups = symdisplay.summarize_touched_nodes(nodes)
    assert [k for k, _ in groups] == ["added", "changed", "removed"]
    by_kind = dict(groups)
    assert by_kind["added"] == ["Chess.clear [locked]"]
    assert by_kind["changed"] == ["Chess.reset [human-written]"]
    assert by_kind["removed"] == ["Chess.perft"]


def test_format_touched_nodes_wraps_and_colors():
    nodes = [
        {"qualified_name": f"{QN}.Chess.m{i}", "file_path": "js/chess.js", "change_kind": "added"}
        for i in range(30)
    ]
    plain = format_touched_nodes(nodes)
    assert plain[0].lstrip().startswith("+ added (30): ")
    assert all(len(line) <= 100 for line in plain)
    assert "\033[" not in "".join(plain)
    colored = format_touched_nodes(nodes, color=True)
    assert colored[0].startswith("\033[32m")


# -- links_for_step lineage fan-out regression ----------------------------


def test_links_for_step_not_duplicated_by_lineage_rows(tmp_path):
    db = TraceDB(tmp_path / "trace.db")
    db.conn.execute(
        "INSERT INTO steps (step_id, prompt, reasoning_text, timestamp, seq) "
        "VALUES ('s1', 'p', 'r', 't', 1)"
    )
    db.conn.execute(
        "INSERT INTO node_links (step_id, qualified_name, file_path, change_kind) "
        "VALUES ('s1', 'repo.js.a.fn', 'js/a.js', 'changed')"
    )
    # Two signature rows for the same symbol (main + a merged branch lineage).
    for lineage, locked in (("main", 0), ("feature-x", 1)):
        db.conn.execute(
            "INSERT INTO node_signatures (qualified_name, file_path, lineage_id, locked) "
            "VALUES ('repo.js.a.fn', 'js/a.js', ?, ?)",
            (lineage, locked),
        )
    db.conn.commit()
    links = db.links_for_step("s1")
    assert len(links) == 1
    assert links[0]["qualified_name"] == "repo.js.a.fn"
    assert links[0]["locked"] == 1  # strongest lock survives the aggregation

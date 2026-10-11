"""End-to-end test: drive a deterministic, offline OpenHands session through the recorder.

A fixture ``events.jsonl`` is replayed over a scratch git repo (one commit per step) against a
small synthetic code graph. We assert that:

- each changed file accumulates an ordered story (node_links per step),
- a reformat-only commit adds no node links (and is reported as skipped),
- a snapshot JSON exists per commit, with empty deltas for the reformat step,
- per-file and per-symbol histories come back in order,
- re-recording is idempotent,
- (when ChromaDB is available) one reasoning embedding exists per substantive step.
"""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.adapters.openhands import OpenHandsAdapter
from codegraph_trace.models import EXPOSED_COT, NARRATION, TOOL_THOUGHT
from codegraph_trace.config import TraceConfig
from codegraph_trace.gitdiff import list_commits
from codegraph_trace.recorder import Recorder, replay_over_commits
from codegraph_trace.query import TraceQuery

FIXTURE = Path(__file__).parent / "fixtures" / "openhands_events.jsonl"
FIXTURE_V1 = Path(__file__).parent / "fixtures" / "openhands_v1"

# File contents at each step/commit. Index i corresponds to the i-th agent step.
CALC_V1 = "def add(a, b):\n    return a + b\n"
CALC_V2 = "def add(a, b):\n    return a + b\n\n\ndef subtract(a, b):\n    return a - b\n"
CALC_V3 = "def add(a, b):\n  return a + b\n\n\ndef subtract(a, b):\n  return a - b\n"
CALC_V4 = "def add(a, b):\n    return float(a) + float(b)\n\n\ndef subtract(a, b):\n  return a - b\n"
UTIL_V1 = "def helper():\n    return 1\n"


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


def _commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", message)


def _build_repo(repo: Path) -> None:
    # One commit per agent action, matching the per-action steps from the fixture.
    _git(repo, "init")
    # Step 1: create calc.py with add().
    _write(repo, "src/calc.py", CALC_V1)
    _commit(repo, "step1: add()")
    # Step 2: append subtract().
    _write(repo, "src/calc.py", CALC_V2)
    _commit(repo, "step2: subtract()")
    # Step 3: reformat (whitespace only).
    _write(repo, "src/calc.py", CALC_V3)
    _commit(repo, "step3: reformat")
    # Step 4: float add().
    _write(repo, "src/calc.py", CALC_V4)
    _commit(repo, "step4: float add")
    # Step 5: new util.py with helper() (its own action/commit).
    _write(repo, "src/util.py", UTIL_V1)
    _commit(repo, "step5: util helper")


def _build_graph_db(db_path: Path) -> None:
    """A tiny synthetic code graph mirroring the scratch repo's final state."""
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
        "INSERT INTO projects VALUES (?, ?, ?)", ("scratch", "2026-06-18", "src")
    )
    nodes = [
        (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
        (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
        (3, "Function", "subtract", "scratch.src.calc.subtract", "src/calc.py", 5, 6),
        (4, "File", "util.py", "scratch.src.util", "src/util.py", 0, 0),
        (5, "Function", "helper", "scratch.src.util.helper", "src/util.py", 1, 2),
    ]
    conn.executemany("INSERT INTO nodes VALUES (?, ?, ?, ?, ?, ?, ?)", nodes)
    # DEFINES edges file -> function (exercises edge_fingerprint).
    conn.executemany(
        "INSERT INTO edges VALUES (?, ?, ?)",
        [(1, 2, "DEFINES"), (1, 3, "DEFINES"), (4, 5, "DEFINES")],
    )
    conn.commit()
    conn.close()


@pytest.fixture
def session(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _build_repo(repo)

    graph_db = tmp_path / "graph.db"
    _build_graph_db(graph_db)

    config = TraceConfig(
        repo_root=repo,
        graph_db_path=graph_db,
        embedding_model="hash",
    )
    return config


def _replay(config: TraceConfig):
    adapter = OpenHandsAdapter(FIXTURE)
    steps = list(adapter.steps())
    shas = list_commits(config.repo_root, max_count=len(steps))
    rec = Recorder(config, enable_embeddings=True)
    results = replay_over_commits(rec, steps, shas)
    has_chroma = rec.chroma is not None
    chroma_count = rec.chroma.count() if has_chroma else 0
    rec.close()
    return steps, shas, results, has_chroma, chroma_count


def test_adapter_yields_per_action_steps():
    steps = list(OpenHandsAdapter(FIXTURE).steps())
    # One step per agent action: create add, add subtract, reformat, float add, add util.
    assert len(steps) == 5
    assert steps[0].prompt == "Create a calculator module with an add function."
    # Reasoning combines the agent narration and the action's own thought.
    assert "add(a, b)" in steps[0].reasoning_text
    assert "foundation" in steps[0].reasoning_text
    # Raw events are preserved verbatim.
    assert steps[0].raw_event and isinstance(steps[0].raw_event, list)
    # The 5th step is the standalone util.py edit.
    assert steps[4].prompt == "Make add handle floats and add a helper util."
    assert "helper()" in steps[4].reasoning_text


def test_adapter_reads_v1_events_directory():
    """The adapter parses the real OpenHands V1 layout: a directory of event-*.json files
    with the typed MessageEvent / ActionEvent schema."""
    steps = list(OpenHandsAdapter(FIXTURE_V1).steps())
    assert len(steps) == 2

    # Step 1: prompt from the user MessageEvent; reasoning from the agent MessageEvent + the
    # ActionEvent thought.
    assert steps[0].prompt == "Create a calculator module with an add function."
    assert "add(a, b)" in steps[0].reasoning_text
    assert "initial add implementation" in steps[0].reasoning_text

    # Step 2 starts from an ActionEvent (no separate agent message) and folds its thought +
    # reasoning_content.
    assert steps[1].prompt == "Now add a subtract function."
    assert "subtract(a, b)" in steps[1].reasoning_text
    assert "together" in steps[1].reasoning_text


def test_adapter_tags_reasoning_provenance():
    """Each reasoning fragment is provenance-tagged: agent messages are narration, tool-call
    thoughts are tool_thought, and provider-returned reasoning_content is exposed_cot. The
    flat reasoning_text is exactly the segment texts joined - same content, two shapes."""
    steps = list(OpenHandsAdapter(FIXTURE_V1).steps())

    # Step 1: agent MessageEvent narration + the ActionEvent's thought (no reasoning_content).
    assert [s.provenance for s in steps[0].reasoning_segments] == [NARRATION, TOOL_THOUGHT]
    assert "add(a, b)" in steps[0].reasoning_segments[0].text
    assert "initial add implementation" in steps[0].reasoning_segments[1].text

    # Step 2: the ActionEvent carries both a thought and provider reasoning_content.
    assert [s.provenance for s in steps[1].reasoning_segments] == [TOOL_THOUGHT, EXPOSED_COT]
    assert "subtract(a, b)" in steps[1].reasoning_segments[0].text
    assert steps[1].reasoning_segments[1].text == "Keeping the two operations together."

    # The flat blob and the segments carry the same content.
    for step in steps:
        assert step.reasoning_text == "\n\n".join(s.text for s in step.reasoning_segments)


def test_reasoning_segments_persisted(session):
    """Segments survive the round trip into trace.db as provenance-tagged JSON."""
    config = session
    _replay(config)

    conn = sqlite3.connect(config.repo_root / ".codegraph-trace" / "trace.db")
    rows = conn.execute(
        "SELECT reasoning_text, reasoning_segments FROM steps ORDER BY seq"
    ).fetchall()
    conn.close()

    assert rows, "replay recorded no steps"
    for reasoning_text, segments_json in rows:
        assert segments_json, "recorded step is missing reasoning_segments"
        segments = json.loads(segments_json)
        assert all(s["provenance"] in (NARRATION, TOOL_THOUGHT, EXPOSED_COT) for s in segments)
        # Every segment's text is contained in the flat blob (folded steps concatenate).
        assert all(s["text"] in reasoning_text for s in segments)


def test_recording_builds_per_file_story(session):
    config = session
    steps, shas, results, _, _ = _replay(config)

    assert len(results) == 5
    # Step 3 is the reformat step: no node links, flagged as skipped.
    assert results[2].skipped_reformat is True
    assert results[2].linked_nodes == []

    with TraceQuery(config, enable_embeddings=False) as q:
        calc_hist = q.get_file_history("src/calc.py")
        # add (step1), subtract (step2), float-add (step4): the reformat step is absent.
        assert [e.after_sha for e in calc_hist] == [shas[0], shas[1], shas[3]]

        add_hist = q.get_node_history("scratch.src.calc.add")
        assert [e.after_sha for e in add_hist] == [shas[0], shas[3]]
        assert add_hist[0].nodes[0]["change_kind"] == "added"
        assert add_hist[1].nodes[0]["change_kind"] == "changed"

        sub_hist = q.get_node_history("scratch.src.calc.subtract")
        assert [e.after_sha for e in sub_hist] == [shas[1]]

        # util.py / helper() are now their own action/commit (step 5).
        util_hist = q.get_file_history("src/util.py")
        assert [e.after_sha for e in util_hist] == [shas[4]]
        helper_hist = q.get_node_history("scratch.src.util.helper")
        assert [e.after_sha for e in helper_hist] == [shas[4]]


def test_snapshots_written_per_commit(session):
    config = session
    steps, shas, results, _, _ = _replay(config)

    for sha in shas:
        snap_file = config.snapshots_dir / f"{sha}.json"
        assert snap_file.is_file(), f"missing snapshot for {sha}"

    # The reformat commit's snapshot has empty node deltas.
    reformat_snap = json.loads(
        (config.snapshots_dir / f"{shas[2]}.json").read_text(encoding="utf-8")
    )
    assert reformat_snap["nodes"] == {"added": [], "removed": [], "changed": []}

    # Step 1 records add as an added node.
    first_snap = json.loads(
        (config.snapshots_dir / f"{shas[0]}.json").read_text(encoding="utf-8")
    )
    assert "scratch.src.calc.add" in first_snap["nodes"]["added"]


def test_step_numbering_surfaced(session):
    config = session
    steps, shas, results, _, _ = _replay(config)

    # Snapshots carry the monotonic step number.
    first_snap = json.loads(
        (config.snapshots_dir / f"{shas[0]}.json").read_text(encoding="utf-8")
    )
    assert first_snap["step_seq"] == 1
    last_snap = json.loads(
        (config.snapshots_dir / f"{shas[4]}.json").read_text(encoding="utf-8")
    )
    assert last_snap["step_seq"] == 5

    with TraceQuery(config, enable_embeddings=False) as q:
        # add() was introduced at step 1 and last changed at step 4 (float add).
        markers = q.get_node_markers("scratch.src.calc.add")
        assert markers["introduced_at_step"] == 1
        assert markers["last_changed_at_step"] == 4
        assert markers["touch_count"] == 2
        # helper() only appeared at step 5 (its own action/commit).
        helper = q.get_node_markers("scratch.src.util.helper")
        assert helper["introduced_at_step"] == 5
        assert helper["last_changed_at_step"] == 5


def test_recording_is_idempotent(session):
    config = session
    _replay(config)
    # Record a second time over the same commits; counts must not grow.
    steps, shas, results, _, _ = _replay(config)

    with TraceQuery(config, enable_embeddings=False) as q:
        rows = q.db.conn.execute("SELECT COUNT(*) AS c FROM steps").fetchone()
        assert rows["c"] == 5
        links = q.db.conn.execute("SELECT COUNT(*) AS c FROM node_links").fetchone()
        # step1: add; step2: subtract; step4: add; step5: helper => 4 links total.
        assert links["c"] == 4


def test_node_links_store_int_id_and_qualified_name(session):
    config = session
    _replay(config)
    with TraceQuery(config, enable_embeddings=False) as q:
        row = q.db.conn.execute(
            "SELECT node_id, qualified_name FROM node_links WHERE qualified_name = ?",
            ("scratch.src.calc.add",),
        ).fetchone()
        assert row is not None
        assert row["node_id"] == 2  # durable integer id from the synthetic graph
        assert row["qualified_name"] == "scratch.src.calc.add"


def test_versions_listing(session):
    config = session
    steps, shas, results, _, _ = _replay(config)

    with TraceQuery(config, enable_embeddings=False) as q:
        versions = q.list_versions()
        # One version per recorded step (the reformat step is still a version, with no delta).
        assert [v.seq for v in versions] == [1, 2, 3, 4, 5]
        assert [v.after_sha for v in versions] == shas
        reformat = versions[2]
        assert (reformat.added, reformat.changed, reformat.removed) == (0, 0, 0)
        # Step 1 introduced add() as an added node.
        assert versions[0].added == 1
        assert q.get_version(4).after_sha == shas[3]
        assert q.get_version(99) is None


def test_goto_restores_commit(session):
    from codegraph_trace import gitdiff
    from codegraph_trace.cli import main

    config = session
    steps, shas, results, _, _ = _replay(config)
    repo = config.repo_root

    origin = gitdiff.current_ref(repo)
    assert gitdiff.working_tree_clean(repo) is True

    try:
        rc = main(["goto", "1", "--repo", str(repo)])
        assert rc == 0
        # Code is restored to version 1's commit content.
        assert (repo / "src" / "calc.py").read_text(encoding="utf-8") == CALC_V1
        # The trace itself is untouched (non-destructive restore).
        with TraceQuery(config, enable_embeddings=False) as q:
            count = q.db.conn.execute("SELECT COUNT(*) AS c FROM steps").fetchone()["c"]
            assert count == 5
    finally:
        # Leave the repo back on its original ref for any later use.
        if origin:
            gitdiff.checkout(repo, origin)


def test_format_history_shows_full_reasoning():
    from codegraph_trace.query import HistoryEntry, format_history

    long_reasoning = "A" * 2000 + " END_MARKER"
    entry = HistoryEntry(
        step_id="s1",
        timestamp="t",
        before_sha=None,
        after_sha="deadbeef",
        prompt="short prompt",
        reasoning_text=long_reasoning,
        nodes=[],
        seq=1,
    )
    out = format_history([entry], "src/calc.py")
    # The full reasoning is present and never truncated with an ellipsis.
    assert long_reasoning in out
    assert "..." not in out


def test_empty_diff_step_merges_into_previous(session):
    from codegraph_trace.models import Step
    from codegraph_trace.recorder import merge_empty_diff_steps

    config = session
    shas = list_commits(config.repo_root, max_count=5)

    # Step "a" creates calc.py (a real code change); step "b" is a trailing summary that touches
    # nothing (before == after, so its diff is empty).
    a = Step(step_id="a", prompt="p", reasoning_text="DID THE WORK",
             before_sha=None, after_sha=shas[0])
    b = Step(step_id="b", prompt="p", reasoning_text="JUST A SUMMARY",
             before_sha=shas[0], after_sha=shas[0])

    merged = merge_empty_diff_steps(config, [a, b])

    assert [s.step_id for s in merged] == ["a"]
    assert "DID THE WORK" in merged[0].reasoning_text
    assert "JUST A SUMMARY" in merged[0].reasoning_text


def test_leading_empty_diff_step_carries_forward(session):
    from codegraph_trace.models import Step
    from codegraph_trace.recorder import merge_empty_diff_steps

    config = session
    shas = list_commits(config.repo_root, max_count=5)

    # A leading no-change step (no previous to merge into) folds forward into the first real
    # step. Its before == after so the diff is empty; the real step changes code (commit 0 -> 1).
    lead = Step(step_id="lead", prompt="p", reasoning_text="PLANNING",
                before_sha=shas[0], after_sha=shas[0])
    real = Step(step_id="real", prompt="p", reasoning_text="EDIT",
                before_sha=shas[0], after_sha=shas[1])

    merged = merge_empty_diff_steps(config, [lead, real])

    assert [s.step_id for s in merged] == ["real"]
    assert "PLANNING" in merged[0].reasoning_text
    assert "EDIT" in merged[0].reasoning_text


def test_all_empty_session_collapses_to_one(session):
    from codegraph_trace.models import Step
    from codegraph_trace.recorder import merge_empty_diff_steps

    config = session
    shas = list_commits(config.repo_root, max_count=5)
    a = Step(
        step_id="a", prompt="p1", reasoning_text="LOOK AROUND",
        before_sha=shas[0], after_sha=shas[0],
        raw_event=[{"id": "e1"}],
    )
    b = Step(
        step_id="b", prompt="p2", reasoning_text="STILL THINKING",
        before_sha=shas[0], after_sha=shas[0],
        raw_event=[{"id": "e2"}],
    )
    c = Step(
        step_id="c", prompt="p3", reasoning_text="GIVE UP",
        before_sha=shas[0], after_sha=shas[0],
        raw_event=[{"id": "e3"}],
    )

    merged = merge_empty_diff_steps(config, [a, b, c])

    assert len(merged) == 1
    assert "LOOK AROUND" in merged[0].reasoning_text
    assert "STILL THINKING" in merged[0].reasoning_text
    assert "GIVE UP" in merged[0].reasoning_text
    assert [e["id"] for e in merged[0].raw_event] == ["e1", "e2", "e3"]


def test_multi_empty_then_edit_merges_cumulatively(session):
    from codegraph_trace.models import Step
    from codegraph_trace.recorder import merge_empty_diff_steps

    config = session
    shas = list_commits(config.repo_root, max_count=5)
    e1 = Step(step_id="e1", prompt="p", reasoning_text="PLAN1",
              before_sha=shas[0], after_sha=shas[0], raw_event=[{"id": "a"}])
    e2 = Step(step_id="e2", prompt="p", reasoning_text="PLAN2",
              before_sha=shas[0], after_sha=shas[0], raw_event=[{"id": "b"}])
    real = Step(step_id="real", prompt="do it", reasoning_text="EDIT",
                before_sha=shas[0], after_sha=shas[1], raw_event=[{"id": "c"}])

    merged = merge_empty_diff_steps(config, [e1, e2, real])

    assert [s.step_id for s in merged] == ["real"]
    assert merged[0].prompt == "do it"
    assert merged[0].before_sha == shas[0]
    assert merged[0].after_sha == shas[1]
    assert "PLAN1" in merged[0].reasoning_text
    assert "PLAN2" in merged[0].reasoning_text
    assert "EDIT" in merged[0].reasoning_text
    assert [e["id"] for e in merged[0].raw_event] == ["a", "b", "c"]


def test_gitignore_only_not_a_boundary_until_source_changes(tmp_path: Path):
    from codegraph_trace.models import Step
    from codegraph_trace.recorder import merge_empty_diff_steps

    repo = tmp_path / "gi_repo"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)
    _commit(repo, "base: calc")

    _write(repo, ".gitignore", "*.pyc\n")
    _commit(repo, "meta: gitignore")

    _write(repo, "src/calc.py", CALC_V2)
    _commit(repo, "code: subtract")

    shas = list_commits(repo)
    assert len(shas) == 3
    base, gi_sha, code_sha = shas

    graph_db = tmp_path / "gi_graph.db"
    _build_graph_db(graph_db)
    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")

    alone = merge_empty_diff_steps(
        config,
        [Step(step_id="gi", prompt="ignore", reasoning_text="TWEAK IGNORE",
              before_sha=base, after_sha=gi_sha)],
    )
    assert len(alone) == 1
    assert alone[0].step_id == "gi"

    merged = merge_empty_diff_steps(
        config,
        [
            Step(step_id="gi", prompt="ignore", reasoning_text="TWEAK IGNORE",
                 before_sha=base, after_sha=gi_sha),
            Step(step_id="code", prompt="edit", reasoning_text="ADD SUBTRACT",
                 before_sha=gi_sha, after_sha=code_sha),
        ],
    )
    assert [s.step_id for s in merged] == ["code"]
    assert merged[0].before_sha == base
    assert merged[0].after_sha == code_sha
    assert "TWEAK IGNORE" in merged[0].reasoning_text
    assert "ADD SUBTRACT" in merged[0].reasoning_text


def _stale_graph(db_path: Path, nodes: list[tuple], edges: list[tuple]) -> None:
    """Build a code graph that reflects an EARLIER state of the repo (a stale index)."""
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


def test_new_symbol_gets_its_own_node_against_stale_graph(tmp_path):
    """A brand-new function the agent adds must be recorded as its own node, not folded into a
    neighbouring symbol or the file node, even though the graph was indexed before it existed."""
    from codegraph_trace.models import Step

    repo = tmp_path / "repo2"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)  # only add() exists
    _commit(repo, "c1: add")
    sha1 = _git(repo, "rev-parse", "HEAD").strip()

    # Stale graph: indexed when only add() existed (no multiply yet).
    graph_db = tmp_path / "stale.db"
    _stale_graph(
        graph_db,
        nodes=[
            (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
            (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
        ],
        edges=[(1, 2, "DEFINES")],
    )

    # Agent appends a brand-new multiply() (lines 5-6).
    calc_new = CALC_V1 + "\n\ndef multiply(a, b):\n    return a * b\n"
    _write(repo, "src/calc.py", calc_new)
    _commit(repo, "c2: multiply")
    sha2 = _git(repo, "rev-parse", "HEAD").strip()

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    step = Step(
        step_id="s2", prompt="add multiply", reasoning_text="multiply two numbers",
        before_sha=sha1, after_sha=sha2,
    )
    with Recorder(config, enable_embeddings=False) as rec:
        result = rec.record_step(step)

    by_qn = {ln.node.qualified_name: ln for ln in result.linked_nodes}
    # multiply is recorded as its own node with the codebase-memory-consistent qualified_name.
    assert "scratch.src.calc.multiply" in by_qn
    multiply = by_qn["scratch.src.calc.multiply"]
    assert multiply.change_kind == "added"
    assert multiply.node.node_id is None  # synthesized: not in the stale graph yet
    assert multiply.node.label == "Function"
    # It is NOT misattributed to add() or swallowed by the file node.
    assert "scratch.src.calc.add" not in by_qn
    assert all(not qn.startswith("file::") for qn in by_qn)


def test_new_symbol_not_falsely_removed_on_next_step(tmp_path):
    """Removal detection must consult the post-step source, not the stale graph.

    A new symbol recorded via live AST is missing from the stale graph; the next step touching
    the same file must NOT flag it as removed (and must not delete its signature)."""
    from codegraph_trace.models import Step

    repo = tmp_path / "repo-noremove"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)  # only add() exists
    _commit(repo, "c1: add")
    sha1 = _git(repo, "rev-parse", "HEAD").strip()

    # Stale graph: knows only add(); multiply() is never in it.
    graph_db = tmp_path / "stale.db"
    _stale_graph(
        graph_db,
        nodes=[
            (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
            (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
        ],
        edges=[(1, 2, "DEFINES")],
    )

    _write(repo, "src/calc.py", CALC_V1 + "\n\ndef multiply(a, b):\n    return a * b\n")
    _commit(repo, "c2: multiply")
    sha2 = _git(repo, "rev-parse", "HEAD").strip()
    # A later step edits the same file again (multiply still present).
    _write(
        repo, "src/calc.py",
        CALC_V1 + "\n\ndef multiply(a, b):\n    return a * b * 1\n",
    )
    _commit(repo, "c3: tweak multiply")
    sha3 = _git(repo, "rev-parse", "HEAD").strip()

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(step_id="s2", prompt="p", reasoning_text="r",
                             before_sha=sha1, after_sha=sha2))
        result = rec.record_step(Step(step_id="s3", prompt="p", reasoning_text="r",
                                      before_sha=sha2, after_sha=sha3))

    # multiply is linked as changed - never as removed.
    kinds = {ln.node.qualified_name: ln.change_kind for ln in result.linked_nodes}
    assert kinds.get("scratch.src.calc.multiply") == "changed"

    with TraceQuery(config, enable_embeddings=False) as q:
        rows = q.db.conn.execute(
            "SELECT change_kind FROM node_links WHERE qualified_name = ?",
            ("scratch.src.calc.multiply",),
        ).fetchall()
        assert all(r["change_kind"] != "removed" for r in rows)
        # The signature survives so future edits classify as 'changed', not 'added' again.
        assert q.db.get_signature("scratch.src.calc.multiply") is not None


def test_deleted_symbol_detected_against_stale_graph(tmp_path):
    """A genuinely deleted symbol is flagged removed even though the stale graph still has it."""
    from codegraph_trace.models import Step

    repo = tmp_path / "repo-remove"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)  # add() only
    _commit(repo, "c1: add")
    sha1 = _git(repo, "rev-parse", "HEAD").strip()

    graph_db = tmp_path / "stale.db"
    _stale_graph(
        graph_db,
        nodes=[
            (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
            (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
            (3, "Function", "subtract", "scratch.src.calc.subtract", "src/calc.py", 5, 6),
        ],
        edges=[(1, 2, "DEFINES"), (1, 3, "DEFINES")],
    )

    # subtract() is added in its own step, then deleted; the graph still contains it.
    _write(repo, "src/calc.py", CALC_V2)
    _commit(repo, "c2: subtract")
    sha2 = _git(repo, "rev-parse", "HEAD").strip()
    _write(repo, "src/calc.py", CALC_V1)
    _commit(repo, "c3: drop subtract")
    sha3 = _git(repo, "rev-parse", "HEAD").strip()

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(step_id="s1", prompt="p", reasoning_text="r",
                             before_sha=None, after_sha=sha1))
        rec.record_step(Step(step_id="s2", prompt="p", reasoning_text="r",
                             before_sha=sha1, after_sha=sha2))
        result = rec.record_step(Step(step_id="s3", prompt="p", reasoning_text="r",
                                      before_sha=sha2, after_sha=sha3))

    kinds = {ln.node.qualified_name: ln.change_kind for ln in result.linked_nodes}
    assert kinds.get("scratch.src.calc.subtract") == "removed"

    with TraceQuery(config, enable_embeddings=False) as q:
        # The removed node's signature is gone; add()'s survives.
        assert q.db.get_signature("scratch.src.calc.subtract") is None
        assert q.db.get_signature("scratch.src.calc.add") is not None


def test_added_method_nests_under_class(tmp_path):
    """A new method is attributed to ``Class.method`` (the most specific symbol), not the class."""
    from codegraph_trace.models import Step

    repo = tmp_path / "repo3"
    repo.mkdir()
    _git(repo, "init")
    cls_v1 = "class Calc:\n    def add(self, a, b):\n        return a + b\n"
    _write(repo, "src/shapes.py", cls_v1)
    _commit(repo, "c1: class")
    sha1 = _git(repo, "rev-parse", "HEAD").strip()

    graph_db = tmp_path / "stale.db"
    _stale_graph(
        graph_db,
        nodes=[
            (1, "File", "shapes.py", "scratch.src.shapes", "src/shapes.py", 0, 0),
            (2, "Class", "Calc", "scratch.src.shapes.Calc", "src/shapes.py", 1, 3),
            (3, "Method", "add", "scratch.src.shapes.Calc.add", "src/shapes.py", 2, 3),
        ],
        edges=[(1, 2, "DEFINES"), (2, 3, "DEFINES")],
    )

    # Agent adds a new mul() method (lines 5-6).
    cls_v2 = cls_v1 + "\n    def mul(self, a, b):\n        return a * b\n"
    _write(repo, "src/shapes.py", cls_v2)
    _commit(repo, "c2: method")
    sha2 = _git(repo, "rev-parse", "HEAD").strip()

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    step = Step(
        step_id="s2", prompt="add mul method", reasoning_text="multiply method",
        before_sha=sha1, after_sha=sha2,
    )
    with Recorder(config, enable_embeddings=False) as rec:
        result = rec.record_step(step)

    by_qn = {ln.node.qualified_name: ln for ln in result.linked_nodes}
    assert "scratch.src.shapes.Calc.mul" in by_qn
    mul = by_qn["scratch.src.shapes.Calc.mul"]
    assert mul.change_kind == "added"
    assert mul.node.label == "Method"


def _record_new_symbol(tmp_path, *, rel, v1, v2, nodes, edges):
    """Helper: commit ``v1`` (only old symbols), build a stale graph, commit ``v2`` (adds a new
    symbol), record the step, and return the recorded LinkedNodes by qualified_name."""
    from codegraph_trace.models import Step

    repo = tmp_path / "r"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, rel, v1)
    _commit(repo, "c1")
    sha1 = _git(repo, "rev-parse", "HEAD").strip()

    graph_db = tmp_path / "stale.db"
    _stale_graph(graph_db, nodes=nodes, edges=edges)

    _write(repo, rel, v2)
    _commit(repo, "c2")
    sha2 = _git(repo, "rev-parse", "HEAD").strip()

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    step = Step(step_id="s2", prompt="add symbol", reasoning_text="why", before_sha=sha1, after_sha=sha2)
    with Recorder(config, enable_embeddings=False) as rec:
        result = rec.record_step(step)
    return {ln.node.qualified_name: ln for ln in result.linked_nodes}


def test_one_hunk_spanning_two_new_functions_links_both(tmp_path):
    """Two sibling functions appended in ONE contiguous edit (a single --unified=0 hunk) must
    each get their own node, not just the smallest overlapping one."""
    v2 = CALC_V1 + "\n\ndef multiply(a, b):\n    return a * b\n\n\ndef power(a, b):\n    return a ** b\n"
    by_qn = _record_new_symbol(
        tmp_path, rel="src/calc.py", v1=CALC_V1, v2=v2,
        nodes=[
            (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
            (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
        ],
        edges=[(1, 2, "DEFINES")],
    )
    assert "scratch.src.calc.multiply" in by_qn
    assert "scratch.src.calc.power" in by_qn
    for qn in ("scratch.src.calc.multiply", "scratch.src.calc.power"):
        assert by_qn[qn].change_kind == "added"
        assert by_qn[qn].node.label == "Function"
        assert by_qn[qn].node.node_id is None
    # Neither add() nor the file node is dragged in.
    assert "scratch.src.calc.add" not in by_qn
    assert all(not qn.startswith("file::") for qn in by_qn)


def test_stale_graph_hunk_spanning_two_symbols_links_both(tmp_path):
    """The stale-graph fallback path (unsupported language) also splits a multi-symbol hunk."""
    from codegraph_trace.codegraph import CodeGraph

    graph_db = tmp_path / "g.db"
    _stale_graph(
        graph_db,
        nodes=[
            (1, "File", "conf.toml", "scratch.conf", "conf.toml", 0, 0),
            (2, "Resource", "alpha", "scratch.conf.alpha", "conf.toml", 1, 4),
            (3, "Resource", "beta", "scratch.conf.beta", "conf.toml", 6, 9),
        ],
        edges=[],
    )
    with CodeGraph(graph_db) as g:
        nodes = g.resolve_nodes("conf.toml", [(2, 8)])  # one hunk spanning both resources
    qns = {n.qualified_name for n in nodes}
    assert qns == {"scratch.conf.alpha", "scratch.conf.beta"}


def test_symbols_for_range_prefers_method_over_class():
    """The innermost filter still attributes a method hunk to Class.method, not the class."""
    from codegraph_trace.ast_symbols import extract_symbols, symbols_for_range

    source = (
        "class Calc:\n"
        "    def add(self, a, b):\n"
        "        return a + b\n"
        "\n"
        "    def mul(self, a, b):\n"
        "        return a * b\n"
    )
    syms = extract_symbols(source, language="python")
    # A hunk on mul (with its separator blank line) -> only Calc.mul.
    assert [s.dotted_suffix for s in symbols_for_range(syms, 4, 6)] == ["Calc.mul"]
    # A hunk spanning both methods -> both, still not the class.
    assert [s.dotted_suffix for s in symbols_for_range(syms, 2, 6)] == ["Calc.add", "Calc.mul"]


def test_new_javascript_function_gets_its_own_node(tmp_path):
    from codegraph_trace import ast_symbols

    if not ast_symbols.treesitter_available("javascript"):
        pytest.skip("tree-sitter-javascript not installed")

    v1 = "export function add(a, b) {\n  return a + b;\n}\n"
    v2 = v1 + "\nexport function multiply(a, b) {\n  return a * b;\n}\n"
    by_qn = _record_new_symbol(
        tmp_path, rel="src/calc.js", v1=v1, v2=v2,
        nodes=[
            (1, "File", "calc.js", "scratch.src.calc", "src/calc.js", 0, 0),
            (2, "Function", "add", "scratch.src.calc.add", "src/calc.js", 1, 3),
        ],
        edges=[(1, 2, "DEFINES")],
    )
    assert "scratch.src.calc.multiply" in by_qn
    assert by_qn["scratch.src.calc.multiply"].change_kind == "added"
    assert by_qn["scratch.src.calc.multiply"].node.label == "Function"
    assert "scratch.src.calc.add" not in by_qn
    assert all(not qn.startswith("file::") for qn in by_qn)


def test_new_java_method_nests_under_class(tmp_path):
    from codegraph_trace import ast_symbols

    if not ast_symbols.treesitter_available("java"):
        pytest.skip("tree-sitter-java not installed")

    v1 = "class Calc {\n    int add(int a, int b) {\n        return a + b;\n    }\n}\n"
    v2 = (
        "class Calc {\n    int add(int a, int b) {\n        return a + b;\n    }\n\n"
        "    int mul(int a, int b) {\n        return a * b;\n    }\n}\n"
    )
    by_qn = _record_new_symbol(
        tmp_path, rel="Calc.java", v1=v1, v2=v2,
        nodes=[
            (1, "File", "Calc.java", "scratch.Calc", "Calc.java", 0, 0),
            (2, "Class", "Calc", "scratch.Calc.Calc", "Calc.java", 1, 5),
            (3, "Method", "add", "scratch.Calc.Calc.add", "Calc.java", 2, 4),
        ],
        edges=[(1, 2, "DEFINES"), (2, 3, "DEFINES")],
    )
    assert "scratch.Calc.Calc.mul" in by_qn
    assert by_qn["scratch.Calc.Calc.mul"].change_kind == "added"
    assert by_qn["scratch.Calc.Calc.mul"].node.label == "Method"


def test_new_css_rule_gets_its_own_node(tmp_path):
    from codegraph_trace import ast_symbols

    if not ast_symbols.treesitter_available("css"):
        pytest.skip("tree-sitter-css not installed")

    v1 = ".btn {\n  color: red;\n}\n"
    v2 = v1 + "\n.card {\n  padding: 8px;\n}\n"
    by_qn = _record_new_symbol(
        tmp_path, rel="styles/main.css", v1=v1, v2=v2,
        nodes=[
            (1, "File", "main.css", "scratch.styles.main", "styles/main.css", 0, 0),
            (2, "Rule", ".btn", "scratch.styles.main..btn", "styles/main.css", 1, 3),
        ],
        edges=[],
    )
    # The new .card rule is recorded as its own node (not folded into .btn or the file node).
    card = [ln for qn, ln in by_qn.items() if qn.endswith(".card")]
    assert card, f"expected a .card rule node, got {list(by_qn)}"
    assert card[0].change_kind == "added"
    assert card[0].node.label == "Rule"


def test_readonly_import_is_not_mutated_by_recording(tmp_path):
    """A read-only import's nodes can be read but never modified by subsequent recording, so the
    other repo's history stays intact even if a local edit resolves to the same qualified_name."""
    from codegraph_trace.models import Step
    from codegraph_trace.store.trace_db import TraceDB

    # --- Repo B: records reasoning for libb.lib.shared ---
    repo_b = tmp_path / "libB"
    repo_b.mkdir()
    _git(repo_b, "init")
    _write(repo_b, "lib.py", "def shared():\n    return 42\n")
    _commit(repo_b, "b1")
    cb1 = _git(repo_b, "rev-parse", "HEAD").strip()
    graph_b = tmp_path / "B.db"
    _stale_graph(
        graph_b,
        nodes=[
            (1, "File", "lib.py", "libb.lib", "lib.py", 0, 0),
            (2, "Function", "shared", "libb.lib.shared", "lib.py", 1, 2),
        ],
        edges=[(1, 2, "DEFINES")],
    )
    # The project name for B's graph must be 'libb' for the qualified_name to match.
    conn = sqlite3.connect(graph_b)
    conn.execute("UPDATE projects SET name = 'libb'")
    conn.commit()
    conn.close()
    config_b = TraceConfig(repo_root=repo_b, graph_db_path=graph_b, embedding_model="hash")
    with Recorder(config_b, enable_embeddings=False) as rec:
        rec.record_step(Step(
            step_id="b-why", prompt="add shared", reasoning_text="B's ORIGINAL REASONING",
            before_sha=None, after_sha=cb1,
        ))

    # --- Repo A: imports B read-only, then locally creates a lib.py that resolves to the SAME
    # qualified_name (libb.lib.shared) to exercise the guard. ---
    repo_a = tmp_path / "appA"
    repo_a.mkdir()
    _git(repo_a, "init")
    _write(repo_a, "seed.py", "x = 1\n")
    _commit(repo_a, "a0")
    graph_a = tmp_path / "A.db"
    # A's graph maps lib.py to the module 'libb.lib' (an overlap) so a local edit there resolves
    # to libb.lib.shared - which belongs to the read-only import.
    _stale_graph(
        graph_a,
        nodes=[(1, "File", "lib.py", "libb.lib", "lib.py", 0, 0)],
        edges=[],
    )
    conn = sqlite3.connect(graph_a)
    conn.execute("UPDATE projects SET name = 'libb'")
    conn.commit()
    conn.close()
    config_a = TraceConfig(repo_root=repo_a, graph_db_path=graph_a, embedding_model="hash")

    db_a = TraceDB(config_a.trace_db_path)
    try:
        db_a.import_repo(
            name="libB", repo_root=str(repo_b),
            other_trace_db_path=str(config_b.trace_db_path),
            graph_db_path=str(graph_b), mode="read_only", imported_at="t",
        )
        ro = db_a.readonly_qualified_names()
    finally:
        db_a.close()
    assert "libb.lib.shared" in ro

    # A creates lib.py with shared() -> resolves to libb.lib.shared, which is read-only.
    _write(repo_a, "lib.py", "def shared():\n    return 999\n")
    _commit(repo_a, "a1: local shared")
    ca1 = _git(repo_a, "rev-parse", "HEAD").strip()
    ca0 = _git(repo_a, "rev-list", "--max-count=1", "HEAD~1").strip()

    with Recorder(config_a, enable_embeddings=False) as rec:
        result = rec.record_step(Step(
            step_id="a-collide", prompt="local shared", reasoning_text="A's LOCAL EDIT",
            before_sha=ca0, after_sha=ca1,
        ))

    # The guard dropped the read-only node: A's step linked nothing to libb.lib.shared.
    assert all(ln.node.qualified_name != "libb.lib.shared" for ln in result.linked_nodes)

    # B's original imported reasoning for that node is intact.
    db_a = TraceDB(config_a.trace_db_path)
    try:
        rows = db_a.conn.execute(
            "SELECT step_id, source_repo FROM node_links WHERE qualified_name = ?",
            ("libb.lib.shared",),
        ).fetchall()
    finally:
        db_a.close()
    assert len(rows) == 1
    assert rows[0]["step_id"] == "libB::b-why"
    assert rows[0]["source_repo"] == "libB"


def _human_lock_repo(tmp_path):
    """A repo where a human first writes calc.add(), recorded human-written + locked.

    Returns ``(config, repo, sha_human, sha_agent)`` where ``sha_agent`` is a later commit in
    which an agent edits the same function (not yet recorded).
    """
    from codegraph_trace.models import Step

    repo = tmp_path / "humanrepo"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)  # human writes add()
    _commit(repo, "h1: human add")
    sha_human = _git(repo, "rev-parse", "HEAD").strip()

    graph_db = tmp_path / "graph.db"
    _stale_graph(
        graph_db,
        nodes=[
            (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
            (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
        ],
        edges=[(1, 2, "DEFINES")],
    )

    # Agent later changes add() to use floats (committed but not yet recorded).
    _write(repo, "src/calc.py", "def add(a, b):\n    return float(a) + float(b)\n")
    _commit(repo, "a1: agent float add")
    sha_agent = _git(repo, "rev-parse", "HEAD").strip()

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")

    # Record the human edit (author=human) -> tags + locks scratch.src.calc.add.
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(
            step_id="human-add", prompt="write add", reasoning_text="human wrote add",
            before_sha=None, after_sha=sha_human, author="human",
        ))
    return config, repo, sha_human, sha_agent


def test_human_edit_is_tagged_and_locked(tmp_path):
    config, repo, sha_human, _ = _human_lock_repo(tmp_path)
    with TraceQuery(config, enable_embeddings=False) as q:
        step = q.db.get_step("human-add")
        assert step["author"] == "human"

        link = q.db.conn.execute(
            "SELECT author FROM node_links WHERE qualified_name = ?",
            ("scratch.src.calc.add",),
        ).fetchone()
        assert link["author"] == "human"

        sig = q.db.get_signature("scratch.src.calc.add")
        assert sig["author"] == "human"
        assert sig["locked"] == 1

        assert "scratch.src.calc.add" in q.db.human_locked_qualified_names()


def test_agent_edit_to_locked_node_becomes_a_proposal(tmp_path):
    from codegraph_trace.models import Step

    config, repo, sha_human, sha_agent = _human_lock_repo(tmp_path)

    # Agent tries to change the locked add(): must not overwrite, must record a proposal.
    with Recorder(config, enable_embeddings=False) as rec:
        result = rec.record_step(Step(
            step_id="agent-edit", prompt="use floats", reasoning_text="agent float change",
            before_sha=sha_human, after_sha=sha_agent, author="agent",
        ))

    # The agent's link to the locked node was dropped.
    assert all(ln.node.qualified_name != "scratch.src.calc.add" for ln in result.linked_nodes)
    assert "scratch.src.calc.add" in result.proposed_nodes

    with TraceQuery(config, enable_embeddings=False) as q:
        # The human record is intact: still exactly one link, authored by the human step.
        rows = q.db.conn.execute(
            "SELECT step_id, author FROM node_links WHERE qualified_name = ?",
            ("scratch.src.calc.add",),
        ).fetchall()
        assert len(rows) == 1
        assert rows[0]["step_id"] == "human-add"
        assert rows[0]["author"] == "human"

        # The node is still human-written and locked.
        sig = q.db.get_signature("scratch.src.calc.add")
        assert sig["author"] == "human"
        assert sig["locked"] == 1

        # A pending proposal captured the agent's attempted change.
        proposals = q.db.list_proposals(status="pending")
        assert len(proposals) == 1
        assert proposals[0]["qualified_name"] == "scratch.src.calc.add"
        assert proposals[0]["author"] == "agent"
        assert proposals[0]["proposal_id"] == "agent-edit::scratch.src.calc.add"


def test_reject_keeps_node_locked(tmp_path):
    from codegraph_trace.cli import main
    from codegraph_trace.models import Step

    config, repo, sha_human, sha_agent = _human_lock_repo(tmp_path)
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(
            step_id="agent-edit", prompt="use floats", reasoning_text="agent float change",
            before_sha=sha_human, after_sha=sha_agent, author="agent",
        ))

    rc = main(["proposals", "--reject", "agent-edit::scratch.src.calc.add", "--repo", str(repo),
               "--graph-db", str(config.graph_db_path)])
    assert rc == 0

    with TraceQuery(config, enable_embeddings=False) as q:
        sig = q.db.get_signature("scratch.src.calc.add")
        assert sig["locked"] == 1  # still locked: the human's original is kept
        assert q.db.list_proposals(status="rejected")[0]["qualified_name"] == "scratch.src.calc.add"

    # Re-recording the agent step still cannot overwrite the locked node.
    with Recorder(config, enable_embeddings=False) as rec:
        result = rec.record_step(Step(
            step_id="agent-edit2", prompt="use floats again", reasoning_text="retry",
            before_sha=sha_human, after_sha=sha_agent, author="agent",
        ))
    assert "scratch.src.calc.add" in result.proposed_nodes


def test_accept_unlocks_so_agent_change_records(tmp_path):
    from codegraph_trace.cli import main
    from codegraph_trace.models import Step

    config, repo, sha_human, sha_agent = _human_lock_repo(tmp_path)
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(
            step_id="agent-edit", prompt="use floats", reasoning_text="agent float change",
            before_sha=sha_human, after_sha=sha_agent, author="agent",
        ))

    rc = main(["proposals", "--accept", "agent-edit::scratch.src.calc.add", "--repo", str(repo),
               "--graph-db", str(config.graph_db_path)])
    assert rc == 0

    with TraceQuery(config, enable_embeddings=False) as q:
        sig = q.db.get_signature("scratch.src.calc.add")
        assert sig["locked"] == 0  # unlocked by the human's acceptance
        assert q.db.list_proposals(status="accepted")[0]["qualified_name"] == "scratch.src.calc.add"

    # Now a fresh agent recording can apply the change (a new Recorder reloads the lock set).
    with Recorder(config, enable_embeddings=False) as rec:
        result = rec.record_step(Step(
            step_id="agent-edit2", prompt="use floats", reasoning_text="agent change applied",
            before_sha=sha_human, after_sha=sha_agent, author="agent",
        ))
    by_qn = {ln.node.qualified_name: ln for ln in result.linked_nodes}
    assert "scratch.src.calc.add" in by_qn
    assert result.proposed_nodes == []

    with TraceQuery(config, enable_embeddings=False) as q:
        # The agent step is now linked to the (formerly locked) node, authored by the agent.
        rows = q.db.conn.execute(
            "SELECT step_id, author FROM node_links WHERE qualified_name = ? ORDER BY step_id",
            ("scratch.src.calc.add",),
        ).fetchall()
        step_ids = {r["step_id"] for r in rows}
        assert "agent-edit2" in step_ids
        assert any(r["step_id"] == "agent-edit2" and r["author"] == "agent" for r in rows)


def test_embeddings_present_when_chroma_available(session):
    config = session
    steps, shas, results, has_chroma, chroma_count = _replay(config)
    if not has_chroma:
        pytest.skip("chromadb not installed in this environment")
    # Substantive steps are 1, 2, 4, 5 (the reformat step embeds nothing).
    assert chroma_count == 4

    with TraceQuery(config, enable_embeddings=True) as q:
        hits = q.semantic_search("subtract function", k=3)
        assert any("subtract" in (h.get("reasoning_text") or "").lower() for h in hits)

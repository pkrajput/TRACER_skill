"""Tests for the graph-narrowed query funnel."""

from __future__ import annotations

import sqlite3
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.adapters.openhands import OpenHandsAdapter
from codegraph_trace.config import TraceConfig
from codegraph_trace.gitdiff import list_commits
from codegraph_trace.recorder import Recorder, replay_over_commits

from codegraph_query.config import QueryConfig
from codegraph_query.funnel import ReasoningFunnel
from codegraph_query.graph_nav import GraphNavigator
from codegraph_query.ranker import StepRanker
from codegraph_query.trace_reader import TraceReader

FIXTURE = Path(__file__).resolve().parents[2] / "tests" / "fixtures" / "openhands_events.jsonl"

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
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)
    _commit(repo, "step1")
    _write(repo, "src/calc.py", CALC_V2)
    _commit(repo, "step2")
    _write(repo, "src/calc.py", CALC_V3)
    _commit(repo, "step3")
    _write(repo, "src/calc.py", CALC_V4)
    _write(repo, "src/util.py", UTIL_V1)
    _commit(repo, "step4")


def _build_graph_db(db_path: Path) -> None:
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
    nodes = [
        (1, "File", "calc.py", "scratch.src.calc", "src/calc.py", 0, 0),
        (2, "Function", "add", "scratch.src.calc.add", "src/calc.py", 1, 2),
        (3, "Function", "subtract", "scratch.src.calc.subtract", "src/calc.py", 5, 6),
        (4, "File", "util.py", "scratch.src.util", "src/util.py", 0, 0),
        (5, "Function", "helper", "scratch.src.util.helper", "src/util.py", 1, 2),
    ]
    conn.executemany("INSERT INTO nodes VALUES (?,?,?,?,?,?,?)", nodes)
    conn.executemany(
        "INSERT INTO edges VALUES (?,?,?)",
        [(1, 2, "DEFINES"), (1, 3, "DEFINES"), (4, 5, "DEFINES"), (2, 3, "CALLS")],
    )
    conn.commit()
    conn.close()


@pytest.fixture()
def recorded_env(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _build_repo(repo)
    graph_db = tmp_path / "graph.db"
    _build_graph_db(graph_db)

    steps = list(OpenHandsAdapter(FIXTURE).steps())
    shas = list_commits(repo, max_count=len(steps))
    config = TraceConfig(
        repo_root=repo,
        graph_db_path=graph_db,
        embedding_model="hash",
    )
    with Recorder(config, enable_embeddings=False) as rec:
        replay_over_commits(rec, steps, shas)

    return repo, graph_db


def test_funnel_gathers_reasoning_via_node_links(recorded_env):
    repo, graph_db = recorded_env
    qconfig = QueryConfig(
        repo_root=repo,
        graph_db_path=graph_db,
        embedding_model="hash",
        neighbour_hops=1,
        top_k=3,
    )
    with ReasoningFunnel(qconfig) as funnel:
        result = funnel.query(
            "Why was subtract added to calc?",
            anchor="scratch.src.calc.subtract",
            use_llm=False,
        )

    assert result.anchors
    assert result.candidates, "expected steps linked via node_links"
    assert result.ranked, "expected ranked reasoning"
    assert "subtract" in result.answer.lower() or "step" in result.answer.lower()


def test_ranker_prefers_relevant_step(recorded_env):
    repo, graph_db = recorded_env
    qconfig = QueryConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    with TraceReader(qconfig.trace_db_path) as reader:
        candidates = reader.steps_for_neighbourhood(
            ["scratch.src.calc.subtract", "scratch.src.calc.add"],
            ["src/calc.py"],
        )
    ranker = StepRanker("hash")
    ranked = ranker.rank("add subtract function implementation", candidates, top_k=2)
    assert ranked
    joined = " ".join(r.candidate.prompt.lower() for r in ranked)
    assert "subtract" in joined or "add" in joined


def test_funnel_uses_co_change_matrix(tmp_path: Path):
    """A symbol co-edited with the anchor (but not a graph neighbour) is pulled into retrieval
    via the co-change matrix, surfacing reasoning that the graph walk alone would miss."""
    from codegraph_trace.models import Step

    repo = tmp_path / "ccrepo"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "a.py", "def alpha():\n    return 1\n")
    _write(repo, "b.py", "def beta():\n    return 2\n")
    _commit(repo, "c1: alpha and beta together")
    c1 = _git(repo, "rev-parse", "HEAD").strip()
    _write(repo, "b.py", "def beta():\n    return 22\n")
    _commit(repo, "c2: beta solo")
    c2 = _git(repo, "rev-parse", "HEAD").strip()

    graph_db = tmp_path / "cc.db"
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
    conn.execute("INSERT INTO projects VALUES (?, ?, ?)", ("proj", "2026", "."))
    conn.executemany(
        "INSERT INTO nodes VALUES (?,?,?,?,?,?,?)",
        [
            (1, "File", "a.py", "proj.a", "a.py", 0, 0),
            (2, "Function", "alpha", "proj.a.alpha", "a.py", 1, 2),
            (3, "File", "b.py", "proj.b", "b.py", 0, 0),
            (4, "Function", "beta", "proj.b.beta", "b.py", 1, 2),
        ],
    )
    # DEFINES edges only; no edge connects alpha and beta, so beta is NOT a graph neighbour.
    conn.executemany(
        "INSERT INTO edges VALUES (?,?,?)", [(1, 2, "DEFINES"), (3, 4, "DEFINES")]
    )
    conn.commit()
    conn.close()

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(Step(
            step_id="s1", prompt="add alpha and beta",
            reasoning_text="ALPHA AND BETA TOGETHER", before_sha=None, after_sha=c1,
        ))
        rec.record_step(Step(
            step_id="s2", prompt="tweak beta",
            reasoning_text="BETA SOLO EDIT", before_sha=c1, after_sha=c2,
        ))

    qconfig = QueryConfig(
        repo_root=repo, graph_db_path=graph_db, embedding_model="hash",
        neighbour_hops=1, top_k=5,
    )
    with ReasoningFunnel(qconfig) as funnel:
        result = funnel.query("why did alpha change", anchor="proj.a.alpha", use_llm=False)

    # beta was edited alongside alpha (step s1), so the matrix surfaces it.
    assert "proj.b.beta" in result.meta.get("co_changed", [])
    # And beta's solo-edit reasoning (step s2) is retrieved, which the graph walk alone misses.
    reasons = " ".join(c.reasoning_text for c in result.candidates)
    assert "BETA SOLO EDIT" in reasons


def test_co_change_matrix_is_idempotent(tmp_path: Path):
    """Re-recording the same step must not double-count co-change entries."""
    from codegraph_trace.models import Step

    repo = tmp_path / "ccrepo2"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "a.py", "def alpha():\n    return 1\n")
    _write(repo, "b.py", "def beta():\n    return 2\n")
    _commit(repo, "c1")
    c1 = _git(repo, "rev-parse", "HEAD").strip()

    graph_db = tmp_path / "cc2.db"
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
    conn.execute("INSERT INTO projects VALUES (?, ?, ?)", ("proj", "2026", "."))
    conn.executemany(
        "INSERT INTO nodes VALUES (?,?,?,?,?,?,?)",
        [
            (1, "File", "a.py", "proj.a", "a.py", 0, 0),
            (2, "Function", "alpha", "proj.a.alpha", "a.py", 1, 2),
            (3, "File", "b.py", "proj.b", "b.py", 0, 0),
            (4, "Function", "beta", "proj.b.beta", "b.py", 1, 2),
        ],
    )
    conn.commit()
    conn.close()

    config = TraceConfig(repo_root=repo, graph_db_path=graph_db, embedding_model="hash")
    step = Step(step_id="s1", prompt="p", reasoning_text="r", before_sha=None, after_sha=c1)
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(step)
        rec.record_step(step)  # re-record the same step

    from codegraph_trace.store.trace_db import TraceDB

    db = TraceDB(config.trace_db_path)
    try:
        partners = db.co_changed("proj.a.alpha")
        assert partners == [("proj.b.beta", 1)]  # count stays 1, not 2
    finally:
        db.close()


def _simple_graph(db_path: Path, project: str, nodes: list[tuple], edges: list[tuple]) -> None:
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
    conn.execute("INSERT INTO projects VALUES (?, ?, ?)", (project, "2026", "."))
    conn.executemany("INSERT INTO nodes VALUES (?,?,?,?,?,?,?)", nodes)
    if edges:
        conn.executemany("INSERT INTO edges VALUES (?,?,?)", edges)
    conn.commit()
    conn.close()


def test_imported_repo_reasoning_is_queryable(tmp_path: Path):
    """After importing repo B (read-only), a query in repo A can anchor on B's symbol and read
    why it was written - the cross-repo reasoning is merged and retrievable by qualified_name."""
    from codegraph_trace.models import Step
    from codegraph_trace.store.trace_db import TraceDB

    # --- Repo B (a library; the read-only source of reasoning) ---
    repo_b = tmp_path / "libB"
    repo_b.mkdir()
    _git(repo_b, "init")
    _write(repo_b, "lib.py", "def shared():\n    return 42\n")
    _commit(repo_b, "b1: shared")
    cb1 = _git(repo_b, "rev-parse", "HEAD").strip()
    graph_b = tmp_path / "B.db"
    _simple_graph(
        graph_b, "libb",
        nodes=[
            (1, "File", "lib.py", "libb.lib", "lib.py", 0, 0),
            (2, "Function", "shared", "libb.lib.shared", "lib.py", 1, 2),
        ],
        edges=[(1, 2, "DEFINES")],
    )
    config_b = TraceConfig(repo_root=repo_b, graph_db_path=graph_b, embedding_model="hash")
    with Recorder(config_b, enable_embeddings=False) as rec:
        rec.record_step(Step(
            step_id="b-why", prompt="add shared",
            reasoning_text="SHARED RETURNS THE ANSWER 42 ON PURPOSE",
            before_sha=None, after_sha=cb1,
        ))

    # --- Repo A (the app; imports B) ---
    repo_a = tmp_path / "appA"
    repo_a.mkdir()
    _git(repo_a, "init")
    _write(repo_a, "app.py", "def main():\n    return 1\n")
    _commit(repo_a, "a1: main")
    ca1 = _git(repo_a, "rev-parse", "HEAD").strip()
    graph_a = tmp_path / "A.db"
    _simple_graph(
        graph_a, "appa",
        nodes=[
            (1, "File", "app.py", "appa.app", "app.py", 0, 0),
            (2, "Function", "main", "appa.app.main", "app.py", 1, 2),
        ],
        edges=[(1, 2, "DEFINES")],
    )
    config_a = TraceConfig(repo_root=repo_a, graph_db_path=graph_a, embedding_model="hash")
    with Recorder(config_a, enable_embeddings=False) as rec:
        rec.record_step(Step(
            step_id="a-why", prompt="add main", reasoning_text="MAIN IS THE ENTRY POINT",
            before_sha=None, after_sha=ca1,
        ))

    db_a = TraceDB(config_a.trace_db_path)
    try:
        counts = db_a.import_repo(
            name="libB", repo_root=str(repo_b),
            other_trace_db_path=str(config_b.trace_db_path),
            graph_db_path=str(graph_b), mode="read_only", imported_at="t",
        )
    finally:
        db_a.close()
    assert counts["steps"] >= 1 and counts["node_links"] >= 1

    qconfig = QueryConfig(
        repo_root=repo_a, graph_db_path=graph_a, embedding_model="hash",
        neighbour_hops=1, top_k=5,
    )
    with ReasoningFunnel(qconfig) as funnel:
        result = funnel.query(
            "why does shared return that value", anchor="libb.lib.shared", use_llm=False
        )

    assert result.anchors, "anchor in the imported repo's graph should resolve"
    reasons = " ".join(c.reasoning_text for c in result.candidates)
    assert "SHARED RETURNS THE ANSWER 42 ON PURPOSE" in reasons


class _FakeNumpyEmbeddingFunction:
    """Mimics chroma's SentenceTransformerEmbeddingFunction: called with a LIST of texts,
    returns one numpy float32 vector per text. This is the shape that broke the ranker before
    (a bare-string call embedded per-character and numpy arrays tripped truthiness checks)."""

    DIM = 64

    def __call__(self, input):  # noqa: A002 - chroma API
        import hashlib

        import numpy as np

        out = []
        for text in input:
            vec = np.zeros(self.DIM, dtype="float32")
            for tok in (text or "").lower().split():
                h = int(hashlib.md5(tok.encode("utf-8")).hexdigest(), 16)
                vec[h % self.DIM] += 1.0
            out.append(vec)
        return out


def test_ranker_handles_numpy_embedding_function(monkeypatch):
    """Regression: a real (non-hash) embedding function returns numpy vectors. The ranker must
    embed the whole text and score without raising 'truth value of an array is ambiguous'."""
    from codegraph_query import ranker as ranker_mod
    from codegraph_query.models import ReasoningCandidate

    monkeypatch.setattr(
        ranker_mod, "build_embedding_function", lambda model: _FakeNumpyEmbeddingFunction()
    )
    ranker = ranker_mod.StepRanker("all-MiniLM-L6-v2")  # non-hash -> the previously-broken path

    candidates = [
        ReasoningCandidate(
            step_id="s1", prompt="add subtract function to calc",
            reasoning_text="implement subtract helper", timestamp="t1",
            before_sha=None, after_sha=None, linked_qualified_names=[], linked_files=[],
        ),
        ReasoningCandidate(
            step_id="s2", prompt="unrelated whitespace formatting cleanup",
            reasoning_text="reformat only", timestamp="t2",
            before_sha=None, after_sha=None, linked_qualified_names=[], linked_files=[],
        ),
    ]
    ranked = ranker.rank("why was subtract added", candidates, top_k=2)

    assert ranked, "ranking must succeed with a numpy-returning embedding function"
    assert all(isinstance(r.score, float) for r in ranked)
    assert ranked[0].candidate.step_id == "s1"  # the relevant step ranks first


def test_graph_nav_explicit_anchor(recorded_env):
    _, graph_db = recorded_env
    from codegraph_trace.codegraph import CodeGraph

    with CodeGraph(graph_db) as graph:
        nav = GraphNavigator(graph)
        anchors = nav.find_anchors("", explicit="scratch.src.calc.add")
        assert len(anchors) == 1
        assert anchors[0].node.qualified_name.endswith(".add")
        hood = nav.neighbourhood([anchors[0].node], hops=1)
        qnames = {n.qualified_name for n in hood}
        assert "scratch.src.calc.add" in qnames
        assert "scratch.src.calc.subtract" in qnames  # CALLS edge

"""Panel API tests for the Part 3 visual layer.

The Flask panel gained two read-only endpoints for the timeline strip and the zoomed
decision view:

- ``/api/versions``       - the global step spine with the rule-based decision marker.
- ``/api/branch-detail``  - one decision zoomed in: the abandoned attempt (dead code +
  reasoning) next to the code that won (the superseding step's content + reasoning).

Everything runs offline over the same synthetic 3-step session used by the branches tests:
step 2 adds ``helper()``, step 3 deletes it and adds ``better_helper()``.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("flask")

from codegraph_trace.branches import derive_branches
from codegraph_trace.config import TraceConfig
from codegraph_trace.models import Step
from codegraph_trace.panel import create_app
from codegraph_trace.recorder import Recorder
from codegraph_trace.store.trace_db import TraceDB

CALC_V1 = "def add(a, b):\n    return a + b\n"
CALC_V2 = CALC_V1 + "\n\ndef helper():\n    return 1\n"
CALC_V3 = CALC_V1 + "\n\ndef better_helper():\n    return 2\n"
# A second file so the repo-wide branch payload spans multiple files: its first draft
# (step 2) is fully replaced in step 3.
UTIL_V2 = "def tmp_util():\n    return 0\n"
UTIL_V3 = "def final_util():\n    return 9\n"


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
            (3, "File", "util.py", "scratch.src.util", "src/util.py", 0, 0),
            (4, "Function", "tmp_util", "scratch.src.util.tmp_util", "src/util.py", 1, 2),
        ],
    )
    conn.executemany(
        "INSERT INTO edges VALUES (?, ?, ?)",
        [
            (1, 2, "DEFINES"),
            (3, 4, "DEFINES"),
            # The cross-file "connector": add() calls tmp_util().
            (2, 4, "CALLS"),
        ],
    )
    conn.commit()
    conn.close()


@pytest.fixture(autouse=True)
def isolated_tracer_home(tmp_path: Path, monkeypatch) -> None:
    """The review surface reads the sync session — never the developer's real one."""
    monkeypatch.setenv("TRACER_HOME", str(tmp_path / "tracer-home"))


@pytest.fixture
def session(tmp_path: Path) -> TraceConfig:
    """3-step session: step 2's helper() is abandoned, superseded by step 3."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _write(repo, "src/calc.py", CALC_V1)
    sha1 = _commit(repo, "step1: add")
    _write(repo, "src/calc.py", CALC_V2)
    _write(repo, "src/util.py", UTIL_V2)
    sha2 = _commit(repo, "step2: helper")
    _write(repo, "src/calc.py", CALC_V3)
    _write(repo, "src/util.py", UTIL_V3)
    sha3 = _commit(repo, "step3: replace helper")

    graph_db = tmp_path / "graph.db"
    _stale_graph(graph_db)

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
    derive_branches(config)
    return config


@pytest.fixture
def client(session: TraceConfig):
    app = create_app(session)
    app.testing = True
    return app.test_client()


def _get_json(client, url: str) -> dict:
    resp = client.get(url)
    assert resp.status_code == 200
    return json.loads(resp.get_data(as_text=True))


def test_index_serves_the_timeline_page(client):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    # The Part 3 sections are baked into the page script.
    assert "timeline" in html
    assert "renderDecisionView" in html
    assert "api/branch-detail" in html
    assert "rollback/step-" in html


def test_api_versions_spine_with_decision_marker(client):
    data = _get_json(client, "/api/versions")
    versions = data["versions"]
    assert [v["seq"] for v in versions] == [1, 2, 3]
    by_seq = {v["seq"]: v for v in versions}
    # Step 2 (abandoned attempt) and step 3 (the superseder) are decision points; step 1
    # is plain forward motion.
    assert by_seq[1]["important"] is False
    assert by_seq[2]["important"] is True
    assert by_seq[3]["important"] is True
    assert "oh-conv1-2" in data["important_step_ids"]
    assert "oh-conv1-3" in data["important_step_ids"]
    # The fields the timeline strip renders from.
    assert by_seq[2]["prompt"] == "add a helper"
    assert by_seq[2]["after_sha"]


def test_api_branch_detail_dead_code_vs_winner(session: TraceConfig, client):
    db = TraceDB(session.trace_db_path)
    try:
        row = db.conn.execute(
            "SELECT branch_id FROM branches "
            "WHERE kind = 'abandoned' AND qualified_name != '' "
            "AND file_path = 'src/calc.py'"
        ).fetchone()
    finally:
        db.close()
    assert row is not None

    data = _get_json(client, f"/api/branch-detail?branch_id={row['branch_id']}")
    assert data["kind"] == "abandoned"
    assert data["qualified_name"] == "scratch.src.calc.helper"
    # The decision view's breadcrumb trail (repo / file / symbol / decision) needs these.
    assert data["file_path"] == "src/calc.py"

    # The dead side: the abandoned code and the step's own reasoning.
    assert "def helper():" in data["abandoned"]["content"]
    assert data["abandoned"]["reasoning_text"] == "first helper attempt"
    assert data["abandoned"]["seq"] == 2

    # The winning side: the superseding step's symbol content and reasoning.
    assert data["surviving"] is not None
    assert "def better_helper():" in data["surviving"]["content"]
    assert "def helper():" not in data["surviving"]["content"]
    assert data["surviving"]["seq"] == 3
    assert data["surviving"]["reasoning_text"] == "replace helper with better_helper"


def test_api_branch_detail_rejects_bad_ids(client):
    assert "error" in _get_json(client, "/api/branch-detail")
    assert "error" in _get_json(client, "/api/branch-detail?branch_id=abc")
    assert "error" in _get_json(client, "/api/branch-detail?branch_id=999999")


def test_api_files_repo_zoom(client):
    data = _get_json(client, "/api/files")
    files = {f["file_path"]: f for f in data["files"]}
    assert "src/calc.py" in files
    f = files["src/calc.py"]
    assert f["touch_count"] == 3            # all three steps touched the file
    assert f["symbol_count"] >= 2           # add, helper, better_helper
    assert f["decision_step_count"] == 2    # step 2 (abandoned) + step 3 (superseder)
    assert f["branch_kinds"].get("abandoned", 0) >= 1
    assert f["branch_kinds"].get("survived", 0) >= 1


def test_api_step_zoom(client):
    data = _get_json(client, "/api/step?seq=2")
    assert data["step"]["step_id"] == "oh-conv1-2"
    assert data["step"]["seq"] == 2
    assert data["step"]["prompt"] == "add a helper"
    assert data["step"]["important"] is True
    assert data["step"]["author"] in ("agent", None)
    assert any(n["qualified_name"] == "scratch.src.calc.helper" for n in data["nodes"])
    assert any(b["kind"] == "abandoned" for b in data["branches"])

    assert "error" in _get_json(client, "/api/step?seq=999")
    assert "error" in _get_json(client, "/api/step")
    assert "error" in _get_json(client, "/api/step?seq=abc")


def test_api_branches_repo_wide(client):
    """No ?target= returns every branch row - the repo-level decision tree's data."""
    data = _get_json(client, "/api/branches")
    rows = data["rows"]
    assert {r["file_path"] for r in rows} >= {"src/calc.py", "src/util.py"}
    abandoned = [r for r in rows if r["kind"] == "abandoned"]
    assert abandoned
    # A removed-and-replaced attempt carries the joining edge to its replacement.
    assert any(r["superseded_by_seq"] == 3 for r in abandoned)
    # The fields the tree renders from.
    assert all("seq" in r and "important" in r and "qualified_name" in r for r in rows)


def test_index_decision_zoom_level(client):
    """The page routes ?branch=<id> to a navigable one-decision view."""
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    # URL parsing and routing for the deepest zoom level.
    assert "params.get('branch')" in html
    assert "if (branchParam) return decisionView(content, branchParam);" in html
    assert "async function decisionView" in html
    # The ledger's zoom button is the only direct navigation; branch boxes open
    # the inline panel, which links to the page instead.
    assert html.count("location.search = '?branch=' + r.branch_id;") == 1
    assert "page.href = '?branch=' + row.branch_id;" in html
    # The tree keeps the surrounding run visible: context nodes + gap compression.
    assert "spine-node.context" in html
    assert "did not touch this target" in html


def test_index_tree_first_with_on_demand_detail(client):
    """Feedback 3.3: the tree is primary; detail opens on click, no ledger dump."""
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    # The on-demand detail panel and its two entry points.
    assert "decision-detail" in html
    assert "function showStepDetail" in html
    assert "async function showBranchDetail" in html
    # Tree clicks open a panel rather than navigating away.
    assert "showStepDetail(seq);" in html
    assert "g.addEventListener('click', () => showBranchDetail(r));" in html
    # The full ledger is collapsed behind a toggle by default.
    assert "let ledgerOpen = false;" in html
    assert "ledgerOpen ? 'Hide' : 'Show all'" in html


def test_index_repo_view_defaults_to_decision_tree(client):
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    # Dual landing: decisions tab body still owns the repo-wide tree.
    decisions = html.split("async function renderDecisionsTab", 1)[1]
    decisions = decisions.split("async function renderStructureTab", 1)[0]
    assert "api/branches" in decisions
    assert "addDecisionSections" in decisions
    assert "renderDecisionView" in decisions
    assert "Repository decision tree" in decisions
    # Default landing tab is decisions (structure only when ?view=structure or legacy ?structure).
    assert "? 'structure' : 'decisions'" in html


def test_index_dual_landing_tabs(client):
    """Feedback section 2: Decision tree and Code structure are equal landing peers."""
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "async function repoLanding" in html
    assert "async function renderDecisionsTab" in html
    assert "async function renderStructureTab" in html
    assert "landing-tab" in html
    assert "'Decision tree'" in html
    assert "'Code structure'" in html
    # Structure layouts: the self-shaping force graph (Cytoscape.js + fCoSE,
    # default) and the radial tree. The file-boxes layout and the
    # non-functional reset-view chip were removed.
    assert "struct-viewport" in html
    assert "reset view" not in html
    assert "fcose" in html
    assert "drawGraph" in html
    assert "drawRadial" in html
    assert "file boxes" not in html
    assert "forceLayout" not in html
    # Both ?view=structure and legacy ?structure= open the structure tab via landing.
    assert "return repoLanding(content);" in html
    assert "if (structureParam) return structureView" not in html
    # Nested pages still reach structure as a peer landing tab.
    assert "a.href = '?view=structure';" in html
    assert "'?view=structure&focus=' + encodeURIComponent(focus)" in html


def test_api_structure(client):
    """Repository -> files -> symbols + relationships, with the trace overlay."""
    data = _get_json(client, "/api/structure")
    files = {f["file_path"]: f for f in data["files"]}
    assert {"src/calc.py", "src/util.py"} <= set(files)

    calc_syms = {s["qualified_name"]: s for s in files["src/calc.py"]["symbols"]}
    assert "scratch.src.calc.add" in calc_syms
    add = calc_syms["scratch.src.calc.add"]
    assert add["label"] == "Function"
    # add() was written in step 1, so the trace overlay marks it recorded.
    assert add["recorded"] is True
    assert add["touch_count"] >= 1
    assert files["src/calc.py"]["recorded"] is True
    # Working-tree AST fills symbols the stale graph omitted (feedback 3.4).
    assert "scratch.src.calc.better_helper" in calc_syms
    assert calc_syms["scratch.src.calc.better_helper"]["label"] == "Function"
    util_syms = {s["qualified_name"]: s for s in files["src/util.py"]["symbols"]}
    assert "scratch.src.util.final_util" in util_syms

    # The connector between the two parts is visible as a cross-file edge.
    edges = data["edges"]
    calls = [e for e in edges if e["type"] == "CALLS"]
    assert calls and calls[0]["cross_file"] is True
    assert calls[0]["source_qn"] == "scratch.src.calc.add"
    assert calls[0]["target_qn"] == "scratch.src.util.tmp_util"
    # Hierarchy edges stay out - the file boxes already show containment.
    assert all(e["type"] not in ("DEFINES", "DEFINES_METHOD", "CONTAINS_FILE",
                                 "CONTAINS_FOLDER") for e in edges)


def test_api_structure_reference_fill(session: TraceConfig, client):
    """Files the graph leaves unconnected gain a REFERENCES edge from working-tree text.

    ``build.sh`` runs ``src/calc.py`` but carries no language-level import, so the
    indexer records no edge for it; the panel fills one in so the file does not
    float disconnected. Pairs that already have a graph edge (calc <-> util CALLS)
    must not receive a synthetic duplicate.
    """
    repo = Path(session.repo_root)
    _write(repo, "build.sh", "#!/bin/sh\npython3 src/calc.py \"$@\"\n")
    conn = sqlite3.connect(session.graph_db_path)
    conn.execute(
        "INSERT INTO nodes VALUES (9, 'File', 'build.sh', 'scratch.build', 'build.sh', 0, 0)"
    )
    conn.commit()
    conn.close()

    data = _get_json(client, "/api/structure")
    refs = [e for e in data["edges"] if e["type"] == "REFERENCES"]
    assert any(
        e["source_file"] == "build.sh"
        and e["target_file"] == "src/calc.py"
        and e["cross_file"] is True
        for e in refs
    )
    assert not any(
        {e["source_file"], e["target_file"]} == {"src/calc.py", "src/util.py"}
        for e in refs
    )


def test_api_structure_without_graph_db(session: TraceConfig, tmp_path: Path):
    from codegraph_trace.config import TraceConfig as TC

    config = TC(repo_root=session.repo_root, graph_db_path=tmp_path / "missing.db",
                embedding_model="hash")
    app = create_app(config)
    app.testing = True
    data = json.loads(app.test_client().get("/api/structure").get_data(as_text=True))
    assert "error" in data


def test_index_structure_view(client):
    """Structure is a landing tab; deep links and legacy ?structure= still work."""
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "params.has('structure')" in html
    assert "async function renderStructureTab" in html
    assert "function structureLink" in html
    assert "'?view=structure&focus=' + encodeURIComponent(focus)" in html
    assert "function openToViewButton" in html
    assert "Open to view" in html
    assert "api/file-content" in html
    assert "showSymbolActions" in html
    assert "Decision history" in html


def test_api_file_content_latest(client):
    """Open to view: latest working-tree (or HEAD) source, with optional symbol span."""
    data = _get_json(client, "/api/file-content?file=src/calc.py")
    assert "error" not in data
    assert "def add" in data["content"]
    assert data["file"] == "src/calc.py"
    assert data["source"] in ("working_tree", "head")

    spanned = _get_json(
        client, "/api/file-content?file=src/calc.py&node=scratch.src.calc.add"
    )
    assert "error" not in spanned
    assert spanned["start_line"] >= 1
    assert spanned["end_line"] >= spanned["start_line"]


def test_api_file_content_missing(client):
    data = _get_json(client, "/api/file-content")
    assert "error" in data
    data = _get_json(client, "/api/file-content?file=no/such/file.py")
    assert "error" in data


def test_index_short_names_and_author_legend(client):
    """Feedback 3.5: short display names, no repeated human badges, one legend."""
    resp = client.get("/")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "function displayName" in html
    assert "function authorDot" in html
    # No per-row human / human-written text badges.
    assert "tag('human'" not in html
    assert "tag('human-written'" not in html
    # The author meaning is stated once next to the filter chips.
    assert "\\u25CF = human-written" in html


def test_api_versions_carry_author(client):
    data = _get_json(client, "/api/versions")
    assert all("author" in v for v in data["versions"])


def test_api_findings_absent_then_saved(session: TraceConfig, client):
    # No saved report: an empty, well-formed payload (the filter simply has no data).
    data = _get_json(client, "/api/findings")
    assert data["findings_total"] == 0
    assert data["rows"] == []
    assert data["saved"] is False

    # A saved report (what `flag --save` writes) is served verbatim plus saved=True.
    report = {
        "findings_total": 1,
        "rows": [{"check_id": "rule.x", "path": "src/calc.py",
                  "symbol": "scratch.src.calc.add"}],
    }
    (session.trace_dir / "findings-report.json").write_text(
        json.dumps(report), encoding="utf-8"
    )
    data = _get_json(client, "/api/findings")
    assert data["saved"] is True
    assert data["findings_total"] == 1
    assert data["rows"][0]["symbol"] == "scratch.src.calc.add"


# -- change review surface --------------------------------------------------


def _seed_review(session: TraceConfig, **overrides) -> None:
    from codegraph_trace.sync import review

    unit = review.ReviewUnit(
        unit_id="oh-conv1-3",
        seq=3,
        author="teammate",
        commit_message="step3: replace helper",
        files=["src/calc.py"],
        symbols=[{"qualified_name": "scratch.src.calc.better_helper",
                  "file_path": "src/calc.py", "change_kind": "added"}],
        related_seqs=[2],
        diff="diff --git a/src/calc.py b/src/calc.py\n-    return 1\n+    return 2\n",
    )
    for key, value in overrides.items():
        setattr(unit, key, value)
    review.write_ledger(
        session.trace_dir / review.REVIEW_FILENAME,
        review.ReviewLedger(units=[unit], known_step_ids=["oh-conv1-1"], seeded=True),
    )


def _login(monkeypatch, tmp_path: Path, username: str, role: str) -> None:
    from codegraph_trace.sync.state import LocalState, Session

    home = tmp_path / f"tracer-{username}"
    monkeypatch.setenv("TRACER_HOME", str(home))
    LocalState(home=home).save_session(
        Session(entity="EpsilonAI", username=username, role=role, token="t",
                expires_at="2099-01-01T00:00:00+00:00")
    )


def test_api_review_is_empty_and_clear_without_a_ledger(client):
    data = _get_json(client, "/api/review")
    assert data["pending"] == [] and data["rejected"] == []
    assert data["highlight"] == {"files": [], "symbols": [], "seqs": []}
    assert data["clear"] is True
    assert data["viewer"]["can_decide"] is False


def test_api_review_lights_up_the_changed_entities(session, client, monkeypatch, tmp_path):
    _login(monkeypatch, tmp_path, "prateek", "admin")
    _seed_review(session)
    data = _get_json(client, "/api/review")
    assert data["viewer"] == {"username": "prateek", "role": "admin", "can_decide": True}
    assert data["highlight"]["files"] == ["src/calc.py"]
    assert data["highlight"]["symbols"] == ["scratch.src.calc.better_helper"]
    assert data["highlight"]["seqs"] == [2, 3]  # the new node and the one it lands on
    unit = data["pending"][0]
    assert unit["commit_message"] == "step3: replace helper"
    assert "+    return 2" in unit["diff"]
    assert data["clear"] is False


def test_api_review_hides_your_own_change(session, client, monkeypatch, tmp_path):
    _login(monkeypatch, tmp_path, "teammate", "user")
    _seed_review(session)
    data = _get_json(client, "/api/review")
    assert data["pending"] == []
    assert data["highlight"]["files"] == []


def test_api_review_offers_no_verdict_to_a_plain_user(session, client, monkeypatch, tmp_path):
    _login(monkeypatch, tmp_path, "mani", "user")
    _seed_review(session)
    data = _get_json(client, "/api/review")
    assert len(data["pending"]) == 1          # same four things
    assert data["viewer"]["can_decide"] is False  # no accept/reject
    resp = client.post("/api/review/decide",
                       json={"unit_id": "oh-conv1-3", "verdict": "accepted"})
    assert resp.status_code == 403


def test_api_review_decide_records_the_verdict(session, client, monkeypatch, tmp_path):
    from codegraph_trace.sync import review

    _login(monkeypatch, tmp_path, "prateek", "admin")
    _seed_review(session)
    resp = client.post("/api/review/decide",
                       json={"unit_id": "oh-conv1-3", "verdict": "rejected"})
    assert resp.status_code == 200
    assert json.loads(resp.get_data(as_text=True))["status"] == "rejected"
    ledger = review.read_ledger(session.trace_dir / review.REVIEW_FILENAME)
    assert ledger.get("oh-conv1-3").decided_by == "prateek"

    bad = client.post("/api/review/decide", json={"unit_id": "nope", "verdict": "accepted"})
    assert bad.status_code == 400


def test_api_review_shows_the_author_their_rejected_change(session, client, monkeypatch, tmp_path):
    from codegraph_trace.sync import review

    _login(monkeypatch, tmp_path, "teammate", "user")
    _seed_review(session, status=review.REJECTED, decided_by="prateek",
                 decided_at="2026-07-30T10:00:00+00:00")
    data = _get_json(client, "/api/review")
    assert [u["unit_id"] for u in data["rejected"]] == ["oh-conv1-3"]
    assert data["highlight"]["files"] == []  # the author sees the diff, nothing else


def test_page_has_the_review_surface_and_no_pull_banner(client):
    html = client.get("/").get_data(as_text=True)
    assert "api/review" in html
    assert "openDiffPanel" in html
    assert "diff-drawer" in html
    # The old verbose watermark banner is gone for good.
    assert "last-pull" not in html
    assert "new-banner" not in html
    assert "Mark seen" not in html

"""Branch-aware development lineages: create, record, one-way visibility, per-lineage ledger."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codegraph_trace.branches import derive_branches
from codegraph_trace.config import TraceConfig
from codegraph_trace.ignore import ensure_trace_ignored
from codegraph_trace.lineage import (
    UnregisteredLineageError,
    create_lineage,
    resolve_lineage,
)
from codegraph_trace.models import Step
from codegraph_trace.query import TraceQuery
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


def _record(
    config: TraceConfig,
    step_id: str,
    before: str | None,
    after: str,
    *,
    lineage_id: str = "main",
    prompt: str = "",
) -> None:
    step = Step(
        step_id=step_id,
        prompt=prompt or step_id,
        reasoning_text=f"reasoning for {step_id}",
        before_sha=before,
        after_sha=after,
        author="human",
        lineage_id=lineage_id,
    )
    with Recorder(config, enable_embeddings=False) as rec:
        rec.record_step(step)


@pytest.fixture
def lined_repo(tmp_path: Path):
    """Repo with three main-line recorded steps, ready to fork."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "checkout", "-b", "main")
    # Keep the trace store out of git so lineage checkouts never fight over trace.db.
    ensure_trace_ignored(repo)
    _git(repo, "add", ".gitignore")
    _git(repo, "commit", "-m", "ignore trace dir")

    shas = []
    for i, body in enumerate(
        [
            "def a():\n    return 1\n",
            "def a():\n    return 1\n\ndef b():\n    return 2\n",
            "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef c():\n    return 3\n",
        ],
        start=1,
    ):
        _write(repo, "app.py", body)
        sha = _commit(repo, f"step{i}")
        shas.append(sha)

    config = TraceConfig(repo_root=repo, embedding_model="hash")
    config.ensure_dirs()
    before = None
    for i, sha in enumerate(shas, start=1):
        _record(config, f"main-{i}", before, sha, lineage_id="main", prompt=f"main step {i}")
        before = sha

    return repo, config, shas


def test_branch_create_records_fork_point(lined_repo):
    repo, config, shas = lined_repo
    db = TraceDB(config.trace_db_path)
    try:
        info = create_lineage(
            db, name="feat", from_seq=2, repo_root=repo, checkout=True
        )
    finally:
        db.close()

    assert info.lineage_id == "feat"
    assert info.base_seq == 2
    assert info.base_commit == shas[1]
    assert info.git_ref == "feat"
    assert _git(repo, "branch", "--show-current").strip() == "feat"

    db = TraceDB(config.trace_db_path)
    try:
        row = db.get_lineage("feat")
        assert row is not None
        assert row.base_step_id == "main-2"
    finally:
        db.close()


def test_one_way_visibility_main_hides_feature(lined_repo):
    repo, config, shas = lined_repo
    db = TraceDB(config.trace_db_path)
    try:
        create_lineage(db, name="feat", from_seq=2, repo_root=repo, checkout=True)
    finally:
        db.close()

    # Record a step on the feature lineage.
    _write(repo, "app.py", "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef feat():\n    return 9\n")
    feat_sha = _commit(repo, "feat work")
    _record(config, "feat-1", shas[1], feat_sha, lineage_id="feat", prompt="feature work")

    # Continue on main after the fork.
    _git(repo, "checkout", "main")
    _write(
        repo,
        "app.py",
        "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef c():\n    return 3\n\ndef d():\n    return 4\n",
    )
    main4 = _commit(repo, "main continues")
    _record(config, "main-4", shas[2], main4, lineage_id="main", prompt="main continues")

    with TraceQuery(config, enable_embeddings=False) as q:
        # On main: only main steps; no feat-1.
        main_lineage = resolve_lineage(q.db, repo)
        assert main_lineage.lineage_id == "main"
        main_steps = q.db.list_steps(lineage=main_lineage)
        ids = [s["step_id"] for s in main_steps]
        assert ids == ["main-1", "main-2", "main-3", "main-4"]
        assert "feat-1" not in ids

        hist = q.get_file_history("app.py")
        assert [e.step_id for e in hist] == ids

    # On feat: ancestry through fork (seq<=2) plus feat steps; not main-3/main-4.
    _git(repo, "checkout", "feat")
    with TraceQuery(config, enable_embeddings=False) as q:
        feat_lineage = resolve_lineage(q.db, repo)
        assert feat_lineage.lineage_id == "feat"
        feat_steps = q.db.list_steps(lineage=feat_lineage)
        ids = [s["step_id"] for s in feat_steps]
        assert ids == ["main-1", "main-2", "feat-1"]
        assert "main-3" not in ids
        assert "main-4" not in ids


def test_unregistered_branch_refuses_record(lined_repo):
    repo, config, _shas = lined_repo
    _git(repo, "checkout", "-b", "rogue")
    _write(repo, "app.py", "def a():\n    return 99\n")
    sha = _commit(repo, "rogue")

    step = Step(
        step_id="rogue-1",
        prompt="rogue",
        reasoning_text="should fail",
        before_sha=None,
        after_sha=sha,
        author="human",
        # Default main → recorder resolves from HEAD and must refuse.
        lineage_id="main",
    )
    with Recorder(config, enable_embeddings=False) as rec:
        with pytest.raises(UnregisteredLineageError):
            rec.record_step(step)

    # Main stays clean.
    with TraceQuery(config, enable_embeddings=False) as q:
        ids = [s["step_id"] for s in q.db.list_steps()]
        assert "rogue-1" not in ids


def test_decision_ledger_scoped_per_lineage(lined_repo):
    repo, config, shas = lined_repo
    db = TraceDB(config.trace_db_path)
    try:
        create_lineage(db, name="feat", from_seq=2, repo_root=repo, checkout=True)
    finally:
        db.close()

    # On feat: add then abandon a helper (two steps) so derive yields abandoned on feat only.
    _write(repo, "app.py", "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef tmp():\n    return 0\n")
    sha_a = _commit(repo, "feat add tmp")
    _record(config, "feat-a", shas[1], sha_a, lineage_id="feat")

    _write(repo, "app.py", "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef win():\n    return 1\n")
    sha_b = _commit(repo, "feat replace tmp")
    _record(config, "feat-b", sha_a, sha_b, lineage_id="feat")

    derive_branches(config)

    _git(repo, "checkout", "main")
    with TraceQuery(config, enable_embeddings=False) as q:
        main_rows = q.db.list_branches(lineage=q.active_lineage())
        # Main ledger must not include feat session abandonments.
        assert all(
            (r.get("lineage_id") or "main") == "main" for r in main_rows
        )
        assert not any(r["step_id"].startswith("feat-") for r in main_rows)

    _git(repo, "checkout", "feat")
    with TraceQuery(config, enable_embeddings=False) as q:
        feat_rows = q.db.list_branches(lineage=q.active_lineage())
        feat_only = [r for r in feat_rows if (r.get("lineage_id") or "") == "feat"]
        assert feat_only, "expected decision-ledger rows on the feature lineage"
        assert any(r["kind"] in ("abandoned", "revised") for r in feat_only)


def test_cli_branch_create_and_list(lined_repo):
    from codegraph_trace.cli import main

    repo, _config, _shas = lined_repo
    assert (
        main(
            [
                "branch",
                "create",
                "feat-cli",
                "--from",
                "2",
                "--repo",
                str(repo),
                "--no-checkout",
            ]
        )
        == 0
    )
    assert main(["branch", "list", "--repo", str(repo), "--json"]) == 0

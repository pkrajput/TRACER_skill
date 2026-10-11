"""Lineage merge: fold a feature branch into main, anchored at the fork point, idempotently."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codegraph_trace.branches import derive_branches
from codegraph_trace.config import TraceConfig
from codegraph_trace.ignore import ensure_trace_ignored
from codegraph_trace.lineage import (
    LineageError,
    create_lineage,
    merge_lineage,
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
def forked_repo(tmp_path: Path):
    """Main with three steps, a 'feat' lineage forked at seq 2 with two steps (one abandoned
    attempt), and one more main step after the fork."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "checkout", "-b", "main")
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
        shas.append(_commit(repo, f"step{i}"))

    config = TraceConfig(repo_root=repo, embedding_model="hash")
    config.ensure_dirs()
    before = None
    for i, sha in enumerate(shas, start=1):
        _record(config, f"main-{i}", before, sha, lineage_id="main", prompt=f"main step {i}")
        before = sha

    db = TraceDB(config.trace_db_path)
    try:
        create_lineage(db, name="feat", from_seq=2, repo_root=repo, checkout=True)
    finally:
        db.close()

    # Main keeps moving after the fork.
    _git(repo, "checkout", "main")
    _write(
        repo,
        "app.py",
        "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef c():\n    return 3\n\ndef d():\n    return 4\n",
    )
    main4 = _commit(repo, "main continues")
    _record(config, "main-4", shas[2], main4, lineage_id="main", prompt="main continues")

    # feat: add a temp helper, then replace it (abandoned attempt -> ledger rows).
    _git(repo, "checkout", "feat")
    _write(repo, "app.py", "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef tmp():\n    return 0\n")
    sha_a = _commit(repo, "feat add tmp")
    _record(config, "feat-1", shas[1], sha_a, lineage_id="feat", prompt="feat tries tmp")

    _write(repo, "app.py", "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef win():\n    return 1\n")
    sha_b = _commit(repo, "feat replace tmp")
    _record(config, "feat-2", sha_a, sha_b, lineage_id="feat", prompt="feat lands win")

    derive_branches(config)
    _git(repo, "checkout", "main")
    return repo, config, shas


def _merge(config: TraceConfig, name: str = "feat"):
    db = TraceDB(config.trace_db_path)
    try:
        return merge_lineage(db, name=name)
    finally:
        db.close()


def test_merge_folds_steps_into_main_at_fork_point(forked_repo):
    repo, config, _shas = forked_repo

    # Before the merge, one-way visibility hides the feature from main.
    with TraceQuery(config, enable_embeddings=False) as q:
        ids = [s["step_id"] for s in q.db.list_steps(lineage=resolve_lineage(q.db, repo))]
        assert ids == ["main-1", "main-2", "main-3", "main-4"]

    result = _merge(config)
    assert not result.already_merged
    assert result.steps_folded == 2
    assert result.lineage.status == "merged"
    assert result.lineage.merged_at

    with TraceQuery(config, enable_embeddings=False) as q:
        lineage = resolve_lineage(q.db, repo)
        assert lineage.lineage_id == "main"
        steps = q.db.list_steps(lineage=lineage)
        ids = [s["step_id"] for s in steps]
        # seq order: the branch's history sits after its fork point (seq 2), where recorded.
        assert ids == ["main-1", "main-2", "main-3", "main-4", "feat-1", "feat-2"]
        seqs = [s["seq"] for s in steps]
        assert seqs == sorted(seqs)
        # Provenance survives: merged steps still carry their lineage_id.
        by_id = {s["step_id"]: s for s in steps}
        assert by_id["feat-1"]["lineage_id"] == "feat"

        # File history on main now tells the branch's story too.
        hist = q.get_file_history("app.py")
        assert "feat-2" in [e.step_id for e in hist]


def test_merge_folds_decision_rows_into_main(forked_repo):
    repo, config, _shas = forked_repo
    _merge(config)

    _git(repo, "checkout", "main")
    with TraceQuery(config, enable_embeddings=False) as q:
        rows = q.db.list_branches(lineage=q.active_lineage())
        feat_rows = [r for r in rows if (r.get("lineage_id") or "") == "feat"]
        assert feat_rows, "merged branch's ledger rows must be visible on main"
        assert any(r["kind"] in ("abandoned", "revised") for r in feat_rows)


def test_merge_twice_is_idempotent(forked_repo):
    repo, config, _shas = forked_repo
    first = _merge(config)
    assert not first.already_merged

    def snapshot():
        with TraceQuery(config, enable_embeddings=False) as q:
            lineage = resolve_lineage(q.db, repo)
            steps = [(s["step_id"], s["seq"]) for s in q.db.list_steps(lineage=lineage)]
            ledger = [
                (r["step_id"], r["file_path"], r["qualified_name"], r["kind"])
                for r in q.db.list_branches(lineage=lineage)
            ]
        return steps, ledger

    before = snapshot()
    second = _merge(config)
    assert second.already_merged
    assert second.signatures_folded == 0
    assert snapshot() == before  # nothing duplicated, nothing moved


def test_merge_folds_signatures_into_main(forked_repo):
    _repo, config, _shas = forked_repo
    result = _merge(config)
    assert result.signatures_folded > 0

    db = TraceDB(config.trace_db_path)
    try:
        rows = db.conn.execute(
            "SELECT last_step_id FROM node_signatures WHERE lineage_id = 'main'"
        ).fetchall()
    finally:
        db.close()
    assert any(r["last_step_id"].startswith("feat-") for r in rows)


def test_record_on_merged_lineage_refused(forked_repo):
    repo, config, shas = forked_repo
    _merge(config)

    _git(repo, "checkout", "feat")
    _write(repo, "app.py", "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef late():\n    return 5\n")
    sha = _commit(repo, "late work")
    step = Step(
        step_id="feat-late",
        prompt="too late",
        reasoning_text="the branch is closed",
        before_sha=shas[1],
        after_sha=sha,
        author="human",
        lineage_id="feat",
    )
    with Recorder(config, enable_embeddings=False) as rec:
        with pytest.raises(LineageError):
            rec.record_step(step)


def test_merge_refuses_main_and_unknown(forked_repo):
    _repo, config, _shas = forked_repo
    db = TraceDB(config.trace_db_path)
    try:
        with pytest.raises(LineageError):
            merge_lineage(db, name="main")
        with pytest.raises(LineageError):
            merge_lineage(db, name="nope")
    finally:
        db.close()


def test_cli_branch_merge(forked_repo):
    from codegraph_trace.cli import main

    repo, _config, _shas = forked_repo
    assert main(["branch", "merge", "feat", "--repo", str(repo)]) == 0
    # Second run is a clean no-op.
    assert main(["branch", "merge", "feat", "--repo", str(repo), "--json"]) == 0

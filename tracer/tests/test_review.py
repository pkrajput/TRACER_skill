"""The review surface: one command bundling a branch's diff, reasoning log and decision ledger."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.config import TraceConfig
from codegraph_trace.ignore import ensure_trace_ignored
from codegraph_trace.lineage import LineageError, create_lineage
from codegraph_trace.models import Step
from codegraph_trace.recorder import Recorder
from codegraph_trace.review import build_review, format_review
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
def review_repo(tmp_path: Path):
    """Main with two steps and a 'feat' lineage with an abandoned attempt plus a keeper."""
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

    _write(repo, "app.py", "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef tmp():\n    return 0\n")
    sha_a = _commit(repo, "feat add tmp")
    _record(config, "feat-1", shas[1], sha_a, lineage_id="feat", prompt="try a temp helper")

    _write(repo, "app.py", "def a():\n    return 1\n\ndef b():\n    return 2\n\ndef win():\n    return 1\n")
    sha_b = _commit(repo, "feat replace tmp")
    _record(config, "feat-2", sha_a, sha_b, lineage_id="feat", prompt="replace tmp with win")

    return repo, config, shas


def test_review_bundle_has_all_three_sections(review_repo):
    _repo, config, _shas = review_repo
    bundle = build_review(config, lineage_name="feat")

    # Code diff: fork point -> branch tip shows the final state, not the abandoned attempt.
    assert bundle.base_commit is not None
    assert bundle.tip_commit is not None
    assert "def win():" in bundle.diff_text
    assert [f["file_path"] for f in bundle.diff_files] == ["app.py"]

    # Reasoning log: the branch's own steps only, in order, with prompts and node links.
    assert [s["step_id"] for s in bundle.steps] == ["feat-1", "feat-2"]
    assert bundle.steps[0]["prompt"] == "try a temp helper"
    assert all(s["nodes"] for s in bundle.steps)

    # Decision ledger: derived on the fly; the tmp attempt did not survive.
    assert bundle.decisions, "expected decision rows for the branch"
    assert all(r["lineage_id"] == "feat" for r in bundle.decisions)
    assert any(r["kind"] in ("abandoned", "revised") for r in bundle.decisions)


def test_review_text_is_readable(review_repo):
    _repo, config, _shas = review_repo
    text = format_review(build_review(config, lineage_name="feat"))
    assert "Review: lineage 'feat'" in text
    assert "=== Code diff" in text
    assert "=== Reasoning log" in text
    assert "=== Decision ledger" in text
    assert "def win():" in text
    assert "try a temp helper" in text


def test_review_json_is_machine_consumable(review_repo, capsys):
    from codegraph_trace.cli import main

    repo, _config, _shas = review_repo
    assert main(["review", "feat", "--repo", str(repo), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["lineage"]["lineage_id"] == "feat"
    assert "def win():" in out["diff"]["text"]
    assert [s["step_id"] for s in out["steps"]] == ["feat-1", "feat-2"]
    assert out["decisions"]
    assert "important_step_ids" in out


def test_review_refuses_main(review_repo):
    _repo, config, _shas = review_repo
    with pytest.raises(LineageError):
        build_review(config, lineage_name="main")


def test_review_still_works_after_merge(review_repo):
    from codegraph_trace.lineage import merge_lineage

    _repo, config, _shas = review_repo
    db = TraceDB(config.trace_db_path)
    try:
        merge_lineage(db, name="feat")
    finally:
        db.close()

    bundle = build_review(config, lineage_name="feat")
    assert bundle.lineage.status == "merged"
    assert [s["step_id"] for s in bundle.steps] == ["feat-1", "feat-2"]
    assert bundle.decisions

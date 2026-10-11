"""The change-review loop: what a pull surfaces, who may judge it, and how a verdict
travels back to the author.

The whole round trip runs against the in-process reference server, so encryption,
archiving and session handling are the real production code path — the ledger is
verified to travel inside the ciphertext and nowhere else.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codegraph_trace.sync import cli, review, sshkeys
from codegraph_trace.sync.client import SyncClient
from codegraph_trace.sync.mock_transport import MockTransport
from codegraph_trace.sync.state import LocalState

QN = "game.js.connector.connectGames"
OTHER_QN = "game.js.connector.startGate"


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.name=Test", "-c", "user.email=t@t", "-C", str(repo), *args],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {proc.stderr}")
    return proc.stdout


def _commit(repo: Path, rel: str, content: str, message: str) -> str:
    path = repo / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", message)
    return _git(repo, "rev-parse", "HEAD").strip()


def _trace_db(repo: Path):
    import sqlite3

    trace = repo / ".codegraph-trace"
    trace.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(trace / "trace.db")
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS steps (
          step_id TEXT PRIMARY KEY, seq INTEGER, reasoning_text TEXT, author TEXT,
          before_sha TEXT, after_sha TEXT, changed_files TEXT);
        CREATE TABLE IF NOT EXISTS node_links (
          step_id TEXT, qualified_name TEXT, file_path TEXT, change_kind TEXT,
          author TEXT);
        """
    )
    return conn


def _record(repo: Path, step_id: str, seq: int, *, before, after, qn=QN, files="js/app.js"):
    conn = _trace_db(repo)
    conn.execute(
        "INSERT OR REPLACE INTO steps VALUES (?, ?, ?, ?, ?, ?, ?)",
        (step_id, seq, f"reasoning for {step_id}", "human", before, after, files),
    )
    conn.execute(
        "INSERT INTO node_links VALUES (?, ?, ?, ?, ?)",
        (step_id, qn, files, "changed", "human"),
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# unit construction: the four things a reviewer is shown
# ---------------------------------------------------------------------------

def test_a_new_step_becomes_one_unit_carrying_all_four_surfaces(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    first = _commit(repo, "js/app.js", "function a() { return 1; }\n", "initial commit")
    # An earlier step touched the same symbol, so the tree has an existing node too.
    _record(repo, "s1", 1, before=None, after=first)

    ledger = review.ReviewLedger()
    assert review.record_local(repo, ledger, author="teammate") == []  # the baseline
    assert ledger.known_step_ids == ["s1"]

    second = _commit(repo, "js/app.js", "function a() { return 2; }\n", "celebrate the win")
    _record(repo, "s2", 2, before=first, after=second)
    created = review.record_local(
        repo, ledger, author="teammate", push_message="the teammate's first change"
    )
    assert [u.unit_id for u in created] == ["s2"]
    unit = created[0]
    assert unit.status == review.PENDING
    assert unit.author == "teammate"
    assert unit.commit_message == "celebrate the win"          # (4) the commit message
    assert unit.files == ["js/app.js"]                          # (1) changed file node
    assert [s["qualified_name"] for s in unit.symbols] == [QN]  # (1) changed symbol node
    assert unit.seq == 2 and unit.related_seqs == [1]           # (2) new + existing tree node
    assert "-function a() { return 1; }" in unit.diff           # (3) before/after
    assert "+function a() { return 2; }" in unit.diff


def test_the_first_push_from_a_repo_is_the_baseline(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    sha = _commit(repo, "js/app.js", "x\n", "initial commit")
    _record(repo, "s1", 1, before=None, after=sha)
    _record(repo, "s2", 2, before=sha, after=sha, qn=OTHER_QN)
    ledger = review.ReviewLedger()
    assert review.record_local(repo, ledger, author="teammate") == []
    assert ledger.is_clear()


def test_a_recorded_unit_is_never_recreated_or_reset_to_pending(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    sha = _commit(repo, "js/app.js", "x\n", "initial commit")
    _record(repo, "s1", 1, before=None, after=sha)
    ledger = review.ReviewLedger()
    review.record_local(repo, ledger, author="teammate")

    second = _commit(repo, "js/app.js", "y\n", "second")
    _record(repo, "s2", 2, before=sha, after=second)
    review.record_local(repo, ledger, author="teammate")
    review.decide_in(ledger, "s2", review.REJECTED, by="reviewer")
    review.record_local(repo, ledger, author="teammate")
    assert [(u.unit_id, u.status) for u in ledger.units] == [("s2", review.REJECTED)]


def test_unit_falls_back_to_reasoning_when_git_has_no_commit(tmp_path):
    repo = tmp_path / "norepo"
    repo.mkdir()
    _record(repo, "s1", 1, before=None, after=None)
    ledger = review.ReviewLedger(seeded=True)
    created = review.record_local(repo, ledger, author="teammate")
    assert created[0].commit_message == "reasoning for s1"
    assert created[0].diff == ""


# ---------------------------------------------------------------------------
# ledger semantics
# ---------------------------------------------------------------------------

def test_you_do_not_review_your_own_change(tmp_path):
    ledger = review.ReviewLedger(units=[review.ReviewUnit(unit_id="s2", author="teammate")])
    assert [u.unit_id for u in ledger.pending_for("reviewer")] == ["s2"]
    assert ledger.pending_for("teammate") == []


def test_merge_keeps_the_latest_verdict_and_adds_unknown_units():
    mine = review.ReviewLedger(
        units=[
            review.ReviewUnit(unit_id="a", status=review.PENDING),
            review.ReviewUnit(
                unit_id="b", status=review.REJECTED, decided_by="reviewer",
                decided_at="2026-07-30T10:00:00+00:00",
            ),
        ],
        known_step_ids=["a", "b"],
        seeded=True,
    )
    theirs = review.ReviewLedger(
        units=[
            review.ReviewUnit(
                unit_id="a", status=review.ACCEPTED, decided_by="reviewer",
                decided_at="2026-07-30T09:00:00+00:00", diff="diff for a\n",
            ),
            review.ReviewUnit(
                unit_id="b", status=review.PENDING,  # older, must not win
            ),
            review.ReviewUnit(unit_id="c", status=review.PENDING),
        ],
        known_step_ids=["b", "c"],
    )
    mine.merge(theirs)
    assert {u.unit_id: u.status for u in mine.units} == {
        "a": review.ACCEPTED, "b": review.REJECTED, "c": review.PENDING,
    }
    assert mine.get("a").diff == "diff for a\n"  # a missing diff is filled in
    assert mine.known_step_ids == ["a", "b", "c"]


def test_ledger_is_clear_only_when_nothing_is_pending_or_rejected():
    ledger = review.ReviewLedger(units=[review.ReviewUnit(unit_id="a")])
    assert not ledger.is_clear()
    ledger.get("a").status = review.REJECTED
    assert not ledger.is_clear()
    ledger.get("a").status = review.ACCEPTED
    assert ledger.is_clear()


def test_decide_rejects_unknown_units_and_bad_verdicts(tmp_path):
    (tmp_path / ".codegraph-trace").mkdir()
    path = review.ledger_path(tmp_path)
    review.write_ledger(path, review.ReviewLedger(units=[review.ReviewUnit(unit_id="a")]))
    with pytest.raises(review.ReviewError):
        review.decide(path, "nope", review.ACCEPTED, by="reviewer")
    with pytest.raises(review.ReviewError):
        review.decide(path, "a", "maybe", by="reviewer")
    unit = review.decide(path, "a", review.REJECTED, by="reviewer")
    assert unit.decided_by == "reviewer" and unit.decided_at
    assert review.read_ledger(path).get("a").status == review.REJECTED


def test_unreadable_ledger_reads_as_empty(tmp_path):
    (tmp_path / ".codegraph-trace").mkdir()
    path = review.ledger_path(tmp_path)
    assert review.read_ledger(path).units == []
    path.write_text("{not json")
    assert review.read_ledger(path).units == []


# ---------------------------------------------------------------------------
# the loop, end to end over the encrypted transport
# ---------------------------------------------------------------------------

class Member:
    """One developer's machine: its own ~/.tracer, keypair and checkout."""

    def __init__(self, root: Path, server: MockTransport) -> None:
        self.home = root / ".tracer"
        self.repo = root / "repo"
        self.repo.mkdir(parents=True)
        _git(self.repo, "init", "-q")
        self.state = LocalState(home=self.home)
        self.client = SyncClient(self.state, server)
        self.keypair = sshkeys.generate_keypair(sshkeys.default_key_path(self.home))

    def ledger(self) -> review.ReviewLedger:
        return review.load(self.repo)


@pytest.fixture()
def server() -> MockTransport:
    return MockTransport()


@pytest.fixture()
def admin(tmp_path, server) -> Member:
    dev = Member(tmp_path / "reviewer", server)
    dev.client.entity_create("example-org", "ep", "reviewer", "pp")
    dev.client.login("example-org", "ep", "reviewer", "pp")
    dev.client.register_key(dev.keypair)
    return dev


@pytest.fixture()
def author(tmp_path, server, admin) -> Member:
    admin.client.add_user("teammate", "tp", role="user")
    dev = Member(tmp_path / "teammate", server)
    dev.client.login("example-org", "ep", "teammate", "tp")
    dev.client.register_key(dev.keypair)
    return dev


def _cli(member: Member, argv: list[str], server, monkeypatch, capsys) -> str:
    """Run a real ``tracer`` command for ``member`` against the reference server."""
    monkeypatch.setenv("TRACER_HOME", str(member.home))
    monkeypatch.setenv("COLUMNS", "200")
    monkeypatch.setattr(cli, "_client", lambda state: SyncClient(state, server))
    assert cli.main(argv) == 0, capsys.readouterr().out
    out = capsys.readouterr().out
    # Every command prints the compatibility notice; it is not part of the surface.
    return "\n".join(
        line for line in out.splitlines() if "OpenHands compatible" not in line
    ).strip()


def _author_change(dev: Member, step_id: str, seq: int, body: str, message: str) -> None:
    parent = _git(dev.repo, "rev-parse", "HEAD").strip()
    sha = _commit(dev.repo, "js/app.js", body, message)
    _record(dev.repo, step_id, seq, before=parent, after=sha)


def test_the_whole_loop_over_the_real_cli(admin, author, server, monkeypatch, capsys):
    # Baseline: the author's first push, the reviewer's first pull. Nothing to review.
    base = _commit(author.repo, "js/app.js", "function a() { return 1; }\n", "initial commit")
    _record(author.repo, "s1", 1, before=None, after=base)
    _cli(author, ["push", "--repo", str(author.repo), "-m", "baseline"], server, monkeypatch, capsys)
    out = _cli(admin, ["pull", "--repo", str(admin.repo)], server, monkeypatch, capsys)
    assert "Pulled version 1" in out and "restored:" in out
    assert admin.ledger().is_clear()

    # Two changes, one push.
    _author_change(author, "s2", 2, "function a() { return 2; }\n", "tune the return")
    _author_change(author, "s3", 3, "function a() { return 3; }\n", "celebrate the win")
    _cli(author, ["push", "--repo", str(author.repo), "-m", "my changes"], server, monkeypatch, capsys)

    # Reviewer side: the pull says only what came in and its commit messages.
    out = _cli(admin, ["pull", "--repo", str(admin.repo)], server, monkeypatch, capsys)
    assert out.splitlines()[-2:] == ["  tune the return", "  celebrate the win"]
    for banned in ("New commits", "New trace steps", "Changed files", "see:", "step#"):
        assert banned not in out
    ledger = admin.ledger()
    assert [u.unit_id for u in ledger.pending_for("reviewer")] == ["s2", "s3"]
    assert "+function a() { return 3; }" in ledger.get("s3").diff

    # Only the admin may judge, and the verdicts travel back on their next push.
    assert _cli(admin, ["review", "--repo", str(admin.repo), "accept", "s2"],
                server, monkeypatch, capsys).endswith("s2 accepted.")
    _cli(admin, ["review", "--repo", str(admin.repo), "reject", "s3"],
         server, monkeypatch, capsys)
    _cli(admin, ["push", "--repo", str(admin.repo), "-m", "verdicts"], server, monkeypatch, capsys)

    # The ledger reached the server as ciphertext only.
    for blob in server.storage.values():
        assert b"celebrate the win" not in blob
        assert b"tracer-review/1" not in blob

    # Author side: the verdicts arrive, and a rejected change shows its before/after
    # code and nothing else — no commit message, no counts, no verdict narration.
    out = _cli(author, ["pull", "--repo", str(author.repo)], server, monkeypatch, capsys)
    assert "-function a() { return 2; }" in out
    assert "+function a() { return 3; }" in out
    assert "celebrate the win" not in out and "reject" not in out

    # Pushing the fix answers the rejection.
    _author_change(author, "s4", 4, "function a() { return 4; }\n", "celebrate properly")
    _cli(author, ["push", "--repo", str(author.repo), "-m", "the fix"],
         server, monkeypatch, capsys)
    assert author.ledger().rejected() == []

    # Accepting the replacement clears the loop on both sides.
    _cli(admin, ["pull", "--repo", str(admin.repo)], server, monkeypatch, capsys)
    assert [u.unit_id for u in admin.ledger().pending_for("reviewer")] == ["s4"]
    _cli(admin, ["review", "--repo", str(admin.repo), "accept", "s4"],
         server, monkeypatch, capsys)
    assert admin.ledger().is_clear()
    out = _cli(admin, ["push", "--repo", str(admin.repo), "-m", "accepted"],
               server, monkeypatch, capsys)
    assert "diff --git" not in out
    out = _cli(author, ["pull", "--repo", str(author.repo)], server, monkeypatch, capsys)
    assert out.splitlines()[-1].startswith("  restored:")  # nothing left to say
    assert author.ledger().is_clear()


def test_a_conflicting_push_still_shows_the_rejection(admin, author, server, monkeypatch, capsys):
    """A version conflict must not swallow the author's only view of the rejection."""
    base = _commit(author.repo, "js/app.js", "one\n", "initial commit")
    _record(author.repo, "s1", 1, before=None, after=base)
    _cli(author, ["push", "--repo", str(author.repo)], server, monkeypatch, capsys)
    _author_change(author, "s2", 2, "two\n", "the change")
    _cli(author, ["push", "--repo", str(author.repo)], server, monkeypatch, capsys)
    _cli(admin, ["pull", "--repo", str(admin.repo)], server, monkeypatch, capsys)
    _cli(admin, ["review", "--repo", str(admin.repo), "reject", "s2"],
         server, monkeypatch, capsys)
    _cli(admin, ["push", "--repo", str(admin.repo)], server, monkeypatch, capsys)

    _author_change(author, "s3", 3, "three\n", "another change")
    monkeypatch.setenv("TRACER_HOME", str(author.home))
    monkeypatch.setattr(cli, "_client", lambda state: SyncClient(state, server))
    assert cli.main(["push", "--repo", str(author.repo)]) == 4  # version conflict
    out = capsys.readouterr().out
    assert "-one" in out and "+two" in out
    # The upload never happened, so the rejection is still standing.
    assert [u.unit_id for u in author.ledger().rejected_for("teammate")] == ["s2"]


def test_a_plain_user_cannot_record_a_verdict(admin, author, server, monkeypatch, capsys):
    base = _commit(author.repo, "js/app.js", "x\n", "initial commit")
    _record(author.repo, "s1", 1, before=None, after=base)
    _cli(author, ["push", "--repo", str(author.repo)], server, monkeypatch, capsys)
    _author_change(author, "s2", 2, "y\n", "second")
    _cli(author, ["push", "--repo", str(author.repo)], server, monkeypatch, capsys)
    _cli(admin, ["pull", "--repo", str(admin.repo)], server, monkeypatch, capsys)
    _cli(admin, ["push", "--repo", str(admin.repo)], server, monkeypatch, capsys)
    _cli(author, ["pull", "--repo", str(author.repo)], server, monkeypatch, capsys)

    monkeypatch.setenv("TRACER_HOME", str(author.home))
    monkeypatch.setattr(cli, "_client", lambda state: SyncClient(state, server))
    assert cli.main(["review", "--repo", str(author.repo), "accept", "s2"]) == 7
    assert author.ledger().get("s2").status == review.PENDING


def test_a_failed_push_does_not_claim_the_change_was_shared(admin, author, server, monkeypatch, capsys):
    base = _commit(author.repo, "js/app.js", "x\n", "initial commit")
    _record(author.repo, "s1", 1, before=None, after=base)
    _cli(author, ["push", "--repo", str(author.repo)], server, monkeypatch, capsys)
    _cli(admin, ["pull", "--repo", str(admin.repo)], server, monkeypatch, capsys)
    _cli(admin, ["push", "--repo", str(admin.repo)], server, monkeypatch, capsys)  # bump the version

    _author_change(author, "s2", 2, "y\n", "second")
    monkeypatch.setenv("TRACER_HOME", str(author.home))
    monkeypatch.setattr(cli, "_client", lambda state: SyncClient(state, server))
    assert cli.main(["push", "--repo", str(author.repo)]) == 4  # version conflict
    ledger = author.ledger()
    assert ledger.get("s2") is None and "s2" not in ledger.known_step_ids


def test_sync_from_remote_is_a_no_op_when_nothing_was_pushed(admin):
    assert review.sync_from_remote(admin.client, admin.repo) is False


def test_fetch_review_state_returns_none_without_a_ledger(admin):
    (admin.repo / ".codegraph-trace").mkdir(parents=True, exist_ok=True)
    (admin.repo / ".codegraph-trace" / "trace.db").write_text("x")
    admin.client.push(admin.repo, message="no ledger yet")
    assert admin.client.fetch_review_state() is None


def test_ledger_survives_the_round_trip_as_written(admin, author):
    (admin.repo / ".codegraph-trace").mkdir(parents=True, exist_ok=True)
    (admin.repo / ".codegraph-trace" / "trace.db").write_text("x")
    review.save(
        admin.repo,
        review.ReviewLedger(units=[review.ReviewUnit(unit_id="s9", commit_message="hello")]),
    )
    admin.client.push(admin.repo)
    author.client.pull(author.repo)
    assert [u.commit_message for u in author.ledger().units] == ["hello"]
    assert json.loads((author.repo / ".codegraph-trace" / "review.json").read_text())[
        "format"
    ] == review.FORMAT

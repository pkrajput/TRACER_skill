"""Change review: what an incoming change touched, and the verdict that goes back.

A *review unit* is one reviewable change — one recorded trace step that arrived in a
``tracer pull``. Each unit carries the four things a reviewer is shown: the files and
symbols it changed (code-structure highlight), the decision-tree steps it relates to,
its before/after diff, and its commit message.

Units live in ``.codegraph-trace/review.json``, which sits inside the synced tree. So
verdicts ride the same end-to-end encrypted payload as the rest of the trace data: the
server relays ciphertext and never learns that a review happened at all.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..ignore import is_trace_path

TRACE_DIR_NAME = ".codegraph-trace"
REVIEW_FILENAME = "review.json"
# Path of the ledger inside a payload archive (see ``payload.build_archive``).
REVIEW_MEMBER = f"{TRACE_DIR_NAME}/{REVIEW_FILENAME}"
TRACE_DB = Path(TRACE_DIR_NAME) / "trace.db"
FORMAT = "tracer-review/1"

PENDING = "pending"
ACCEPTED = "accepted"
REJECTED = "rejected"
# The author answered a rejection with a new push; the unit is closed.
SUPERSEDED = "superseded"
VERDICTS = (ACCEPTED, REJECTED)

# The ledger travels in every push, so a unit's stored diff is bounded.
MAX_DIFF_LINES = 400
# Trace/artifact payloads change on every push; a reviewer wants the code.
DIFF_EXCLUDES = (":(exclude).codegraph-trace", ":(exclude)artifacts", ":(exclude)graph.db")
_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's canonical empty tree


class ReviewError(Exception):
    """A verdict could not be recorded."""


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _git(repo: Path, *args: str) -> Optional[str]:
    """Run git in ``repo``, returning stdout, or None when git fails or is absent."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout if proc.returncode == 0 else None


def local_steps(repo_root: Path) -> list[dict[str, Any]]:
    """Every recorded step in the local trace DB, oldest first, with its node links."""
    db_path = repo_root / TRACE_DB
    if not db_path.exists():
        return []
    try:
        with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
            conn.row_factory = sqlite3.Row
            steps = [
                dict(r)
                for r in conn.execute(
                    "SELECT step_id, seq, reasoning_text, author, before_sha, after_sha, "
                    "changed_files FROM steps ORDER BY seq"
                )
            ]
            for s in steps:
                s["links"] = [
                    dict(r)
                    for r in conn.execute(
                        "SELECT qualified_name, file_path, change_kind, author "
                        "FROM node_links WHERE step_id = ? ORDER BY rowid",
                        (s["step_id"],),
                    )
                ]
    except sqlite3.Error:
        return []
    return steps


# ---------------------------------------------------------------------------
# the ledger
# ---------------------------------------------------------------------------

@dataclass
class ReviewUnit:
    """One reviewable change: one trace step plus everything needed to judge it."""

    unit_id: str
    seq: Optional[int] = None
    author: str = ""
    commit_message: str = ""
    files: list[str] = field(default_factory=list)
    symbols: list[dict[str, Any]] = field(default_factory=list)
    related_seqs: list[int] = field(default_factory=list)
    diff: str = ""
    status: str = PENDING
    decided_by: Optional[str] = None
    decided_at: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "seq": self.seq,
            "author": self.author,
            "commit_message": self.commit_message,
            "files": list(self.files),
            "symbols": [dict(s) for s in self.symbols],
            "related_seqs": list(self.related_seqs),
            "diff": self.diff,
            "status": self.status,
            "decided_by": self.decided_by,
            "decided_at": self.decided_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReviewUnit":
        return cls(
            unit_id=str(data.get("unit_id") or ""),
            seq=data.get("seq"),
            author=str(data.get("author") or ""),
            commit_message=str(data.get("commit_message") or ""),
            files=[f for f in (data.get("files") or []) if isinstance(f, str)],
            symbols=[s for s in (data.get("symbols") or []) if isinstance(s, dict)],
            related_seqs=[s for s in (data.get("related_seqs") or []) if isinstance(s, int)],
            diff=str(data.get("diff") or ""),
            status=str(data.get("status") or PENDING),
            decided_by=data.get("decided_by"),
            decided_at=data.get("decided_at"),
        )


@dataclass
class ReviewLedger:
    """Every review unit the team knows about, in arrival order.

    ``known_step_ids`` is the shared baseline: steps the team has already exchanged.
    A step outside it is a change someone still owes the team a look at. ``seeded``
    separates "no baseline recorded yet" (the first push, which *is* the baseline)
    from "the baseline is genuinely empty".
    """

    units: list[ReviewUnit] = field(default_factory=list)
    known_step_ids: list[str] = field(default_factory=list)
    seeded: bool = False

    def get(self, unit_id: str) -> Optional[ReviewUnit]:
        for u in self.units:
            if u.unit_id == unit_id:
                return u
        return None

    def add(self, unit: ReviewUnit) -> None:
        self.units.append(unit)

    def pending(self) -> list[ReviewUnit]:
        return [u for u in self.units if u.status == PENDING]

    def pending_for(self, viewer: str) -> list[ReviewUnit]:
        """Pending units someone else pushed — you do not review your own change."""
        return [u for u in self.pending() if u.author != viewer]

    def rejected_for(self, author: str) -> list[ReviewUnit]:
        return [u for u in self.units if u.status == REJECTED and u.author == author]

    def rejected(self) -> list[ReviewUnit]:
        return [u for u in self.units if u.status == REJECTED]

    def is_clear(self) -> bool:
        """True when nothing is waiting on either side."""
        return not self.pending() and not self.rejected()

    def merge(self, other: "ReviewLedger") -> None:
        """Fold ``other`` in: unknown units are added, verdicts resolve latest-decided-wins."""
        self.seeded = self.seeded or other.seeded
        for step_id in other.known_step_ids:
            if step_id not in self.known_step_ids:
                self.known_step_ids.append(step_id)
        for incoming in other.units:
            mine = self.get(incoming.unit_id)
            if mine is None:
                self.units.append(incoming)
                continue
            if (incoming.decided_at or "") > (mine.decided_at or ""):
                mine.status = incoming.status
                mine.decided_by = incoming.decided_by
                mine.decided_at = incoming.decided_at
            # A unit created without git (no diff available) is completed by the
            # side that could compute one.
            if not mine.diff and incoming.diff:
                mine.diff = incoming.diff
            if not mine.commit_message and incoming.commit_message:
                mine.commit_message = incoming.commit_message

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": FORMAT,
            "seeded": self.seeded,
            "known_step_ids": list(self.known_step_ids),
            "units": [u.to_dict() for u in self.units],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReviewLedger":
        if not isinstance(data, dict):
            return cls()
        units = [
            ReviewUnit.from_dict(u)
            for u in (data.get("units") or [])
            if isinstance(u, dict) and u.get("unit_id")
        ]
        known = [s for s in (data.get("known_step_ids") or []) if isinstance(s, str)]
        return cls(units=units, known_step_ids=known, seeded=bool(data.get("seeded")))


def ledger_path(repo_root: Path) -> Path:
    return Path(repo_root) / TRACE_DIR_NAME / REVIEW_FILENAME


def read_ledger(path: Path) -> ReviewLedger:
    """Load the ledger at ``path``; a missing or unreadable file is an empty ledger."""
    try:
        return ReviewLedger.from_dict(json.loads(Path(path).read_text()))
    except (OSError, ValueError):
        return ReviewLedger()


def write_ledger(path: Path, ledger: ReviewLedger) -> None:
    path = Path(path)
    if not path.parent.is_dir():
        return
    path.write_text(json.dumps(ledger.to_dict(), indent=2) + "\n")


def load(repo_root: Path) -> ReviewLedger:
    return read_ledger(ledger_path(repo_root))


def save(repo_root: Path, ledger: ReviewLedger) -> None:
    write_ledger(ledger_path(repo_root), ledger)


def decide_in(ledger: ReviewLedger, unit_id: str, verdict: str, *, by: str) -> ReviewUnit:
    """Record ``verdict`` for one unit of an in-memory ledger."""
    if verdict not in VERDICTS:
        raise ReviewError(f"verdict must be one of {', '.join(VERDICTS)}")
    unit = ledger.get(unit_id)
    if unit is None:
        raise ReviewError(f"no such change to review: {unit_id}")
    unit.status = verdict
    unit.decided_by = by
    unit.decided_at = _now_iso()
    return unit


def decide(path: Path, unit_id: str, verdict: str, *, by: str) -> ReviewUnit:
    """Record ``verdict`` for one unit in the ledger at ``path``."""
    ledger = read_ledger(path)
    unit = decide_in(ledger, unit_id, verdict, by=by)
    write_ledger(path, ledger)
    return unit


# ---------------------------------------------------------------------------
# building units out of what a pull brought in
# ---------------------------------------------------------------------------

def _first_line(text: Optional[str]) -> str:
    for line in (text or "").strip().splitlines():
        if line.strip():
            return line.strip()
    return ""


def _commit_subject(repo_root: Path, sha: Optional[str]) -> str:
    if not sha:
        return ""
    out = _git(repo_root, "log", "-1", "--no-merges", "--pretty=format:%s", sha)
    return (out or "").strip()


def _unit_diff(
    repo_root: Path,
    before_sha: Optional[str],
    after_sha: Optional[str],
    files: list[str],
) -> str:
    """The reviewer's before/after diff for one step, capped at ``MAX_DIFF_LINES``."""
    if not after_sha:
        return ""
    base = (before_sha or "").strip()
    if not base:
        parent = _git(repo_root, "rev-parse", "--verify", "--quiet", f"{after_sha}^")
        base = (parent or "").strip() or _EMPTY_TREE
    out = _git(
        repo_root, "diff", "--no-color", "--no-renames", base, after_sha,
        "--", *(files or ["."]), *DIFF_EXCLUDES,
    )
    lines = (out or "").splitlines()[:MAX_DIFF_LINES]
    return "\n".join(lines) + "\n" if lines else ""


def _related_seqs(repo_root: Path, qns: list[str], seq: Optional[int]) -> list[int]:
    """The most recent earlier step per changed symbol — the existing decision-tree
    node the incoming change lands on."""
    if not qns or seq is None:
        return []
    db_path = repo_root / TRACE_DB
    if not db_path.exists():
        return []
    placeholders = ",".join("?" for _ in qns)
    try:
        with contextlib.closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as conn:
            rows = conn.execute(
                "SELECT MAX(s.seq) FROM node_links nl JOIN steps s ON s.step_id = nl.step_id "
                f"WHERE nl.qualified_name IN ({placeholders}) AND s.seq < ? "
                "GROUP BY nl.qualified_name",
                (*qns, seq),
            ).fetchall()
    except sqlite3.Error:
        return []
    return sorted({int(r[0]) for r in rows if r[0] is not None})


def _unit_from_step(
    repo_root: Path,
    step: dict[str, Any],
    *,
    author: str,
    push_message: str,
) -> ReviewUnit:
    links = [
        n for n in step.get("links", [])
        if n.get("qualified_name") and not is_trace_path(n.get("file_path") or "")
    ]
    files: list[str] = []
    for raw in (step.get("changed_files") or "").split(","):
        f = raw.strip()
        if f and not is_trace_path(f) and f not in files:
            files.append(f)
    for n in links:
        fp = n.get("file_path")
        if fp and fp not in files:
            files.append(fp)
    symbols = [
        {
            "qualified_name": n["qualified_name"],
            "file_path": n.get("file_path") or "",
            "change_kind": n.get("change_kind") or "",
        }
        for n in links
    ]
    message = (
        _commit_subject(repo_root, step.get("after_sha"))
        or _first_line(step.get("reasoning_text"))
        or push_message
    )
    return ReviewUnit(
        unit_id=step["step_id"],
        seq=step.get("seq"),
        author=author,
        commit_message=message,
        files=files,
        symbols=symbols,
        related_seqs=_related_seqs(
            repo_root, [s["qualified_name"] for s in symbols], step.get("seq")
        ),
        diff=_unit_diff(repo_root, step.get("before_sha"), step.get("after_sha"), files),
    )


def record_local(
    repo_root: Path,
    ledger: ReviewLedger,
    *,
    author: str,
    push_message: str = "",
) -> list[ReviewUnit]:
    """Add a pending unit for every locally recorded step the team has not seen.

    Runs on the author's machine as part of a push, because that is the only place the
    git history — and therefore the commit message and the before/after diff — exists.
    The first push from a repo is the shared baseline, not a change to review.
    """
    steps = local_steps(repo_root)
    created: list[ReviewUnit] = []
    if ledger.seeded:
        known = set(ledger.known_step_ids)
        for step in steps:
            if step["step_id"] in known or ledger.get(step["step_id"]) is not None:
                continue
            unit = _unit_from_step(
                repo_root, step, author=author, push_message=push_message
            )
            ledger.add(unit)
            created.append(unit)
    ledger.seeded = True
    for step in steps:
        if step["step_id"] not in ledger.known_step_ids:
            ledger.known_step_ids.append(step["step_id"])
    return created


def supersede_rejected(
    ledger: ReviewLedger, author: str, *, by: str
) -> list[ReviewUnit]:
    """Close ``author``'s rejected units: pushing again is their answer to the rejection.

    Rejection is advisory — nothing is reverted — so the loop terminates when the
    author responds and the reviewer accepts what replaces it.
    """
    closed = ledger.rejected_for(author)
    for unit in closed:
        unit.status = SUPERSEDED
        unit.decided_by = by
        unit.decided_at = _now_iso()
    return closed


def sync_from_remote(client, repo_root: Path, *, since_version: Optional[int] = None) -> bool:
    """Merge verdicts recorded by teammates on the latest pushed version.

    Lets an author see a rejection without a full ``tracer pull`` overwriting their
    working tree: the newest blob is downloaded and decrypted in memory, and only the
    ledger is read out of it. Best effort — a network or key problem is never a reason
    to fail the caller.
    """
    try:
        info = client.status()
        latest = int(info.get("latestVersion") or 0)
        if latest < 1 or (since_version is not None and latest <= since_version):
            return False
        remote = client.fetch_review_state()
    except Exception:
        return False
    if not remote:
        return False
    path = ledger_path(repo_root)
    ledger = read_ledger(path)
    snapshot_before = ledger.to_dict()
    ledger.merge(ReviewLedger.from_dict(remote))
    if ledger.to_dict() == snapshot_before:
        return False
    write_ledger(path, ledger)
    return True

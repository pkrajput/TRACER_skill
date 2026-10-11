"""Development lineages: git-like forks of the recorded trace.

A *lineage* is an independent line of development with its own recorded steps. It is distinct
from the decision-ledger ``branches`` table (survived/abandoned attempts within a session).

One-way visibility (mirrors git):

- On ``main``: only main-line steps are visible.
- On a feature lineage forked at ``base_seq``: main-line steps with ``seq <= base_seq``, plus
    that lineage's own steps. Later main work is invisible; the feature is invisible from main.

Merge (:func:`merge_lineage`) folds a feature lineage into main by flipping its ``status`` to
``merged``: no rows are copied or retagged, the visibility predicate simply starts treating the
merged lineage's steps as part of the main line. Because ``seq`` is global and monotonic, the
branch's history slots into main's timeline right where it was recorded — anchored after the
fork point. Merging twice is a no-op, so nothing can ever duplicate.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from . import gitdiff
from .models import utcnow_iso
from .store.trace_db import TraceDB

MAIN_LINEAGE_ID = "main"


class LineageError(RuntimeError):
    """Raised when a lineage operation cannot proceed."""


class UnregisteredLineageError(LineageError):
    """HEAD is on a git branch that has no registered lineage (must ``branch create`` first)."""


@dataclass(frozen=True)
class LineageInfo:
    """One development lineage (main or a feature fork)."""

    lineage_id: str
    git_ref: str
    base_step_id: Optional[str] = None
    base_seq: Optional[int] = None
    base_commit: Optional[str] = None
    parent_lineage: str = MAIN_LINEAGE_ID
    status: str = "open"
    created_at: Optional[str] = None
    merged_at: Optional[str] = None

    @property
    def is_main(self) -> bool:
        """True when this is the primary development line."""
        return self.lineage_id == MAIN_LINEAGE_ID

    @property
    def is_merged(self) -> bool:
        """True when this lineage has been folded into the main line."""
        return self.status == "merged"

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON / CLI output."""
        return {
            "lineage_id": self.lineage_id,
            "git_ref": self.git_ref,
            "base_step_id": self.base_step_id,
            "base_seq": self.base_seq,
            "base_commit": self.base_commit,
            "parent_lineage": self.parent_lineage,
            "status": self.status,
            "created_at": self.created_at,
            "merged_at": self.merged_at,
        }


def normalize_lineage_id(lineage_id: Optional[str]) -> str:
    """Treat NULL / empty lineage_id as main (back-compat for pre-lineage rows)."""
    return lineage_id if lineage_id else MAIN_LINEAGE_ID


def is_main_lineage_id(lineage_id: Optional[str]) -> bool:
    """True when ``lineage_id`` is main (including NULL legacy rows)."""
    return normalize_lineage_id(lineage_id) == MAIN_LINEAGE_ID


def row_to_lineage(row: dict[str, Any]) -> LineageInfo:
    """Build a :class:`LineageInfo` from a ``lineages`` table row."""
    return LineageInfo(
        lineage_id=row["lineage_id"],
        git_ref=row["git_ref"],
        base_step_id=row.get("base_step_id"),
        base_seq=row.get("base_seq"),
        base_commit=row.get("base_commit"),
        parent_lineage=row.get("parent_lineage") or MAIN_LINEAGE_ID,
        status=row.get("status") or "open",
        created_at=row.get("created_at"),
        merged_at=row.get("merged_at"),
    )


def ensure_main_lineage(db: TraceDB, git_ref: str = MAIN_LINEAGE_ID) -> LineageInfo:
    """Ensure the ``main`` lineage row exists; return it."""
    existing = db.get_lineage(MAIN_LINEAGE_ID)
    if existing is not None:
        return existing
    db.upsert_lineage(
        lineage_id=MAIN_LINEAGE_ID,
        git_ref=git_ref or MAIN_LINEAGE_ID,
        base_step_id=None,
        base_seq=None,
        base_commit=None,
        parent_lineage=MAIN_LINEAGE_ID,
        status="open",
        created_at=utcnow_iso(),
    )
    info = db.get_lineage(MAIN_LINEAGE_ID)
    assert info is not None
    return info


def get_lineage(db: TraceDB, lineage_id: str) -> Optional[LineageInfo]:
    """Lookup by lineage id."""
    return db.get_lineage(lineage_id)


def get_lineage_by_git_ref(db: TraceDB, git_ref: str) -> Optional[LineageInfo]:
    """Lookup by bound git branch name."""
    return db.get_lineage_by_git_ref(git_ref)


def resolve_lineage(
    db: TraceDB,
    repo_root: str | Path,
    *,
    explicit: Optional[str] = None,
    allow_unregistered: bool = False,
) -> LineageInfo:
    """Resolve the active lineage from ``explicit`` id or the repo's current git branch.

    Raises :class:`UnregisteredLineageError` when HEAD is a non-main branch with no
    registered lineage (unless ``allow_unregistered`` is True, in which case main is
    returned only for main-like refs and the error still fires for others).
    """
    ensure_main_lineage(db)

    if explicit:
        info = db.get_lineage(explicit)
        if info is None:
            raise LineageError(
                f"No lineage '{explicit}'. Create one with "
                f"'codegraph-trace branch create {explicit} --from <seq>'."
            )
        return info

    ref = gitdiff.current_ref(repo_root) or MAIN_LINEAGE_ID
    # Detached HEAD (short sha): treat as main for read paths; recording should refuse.
    by_ref = db.get_lineage_by_git_ref(ref)
    if by_ref is not None:
        return by_ref

    if ref in (MAIN_LINEAGE_ID, "master") or _looks_like_sha(ref):
        main = db.get_lineage(MAIN_LINEAGE_ID)
        assert main is not None
        # Keep main.git_ref aligned with the repo's default branch name when on master.
        if ref in (MAIN_LINEAGE_ID, "master") and main.git_ref != ref:
            db.upsert_lineage(
                lineage_id=MAIN_LINEAGE_ID,
                git_ref=ref,
                base_step_id=None,
                base_seq=None,
                base_commit=None,
                parent_lineage=MAIN_LINEAGE_ID,
                status=main.status,
                created_at=main.created_at or utcnow_iso(),
            )
            main = db.get_lineage(MAIN_LINEAGE_ID)
            assert main is not None
        return main

    if allow_unregistered:
        main = db.get_lineage(MAIN_LINEAGE_ID)
        assert main is not None
        return main

    raise UnregisteredLineageError(
        f"Git branch '{ref}' is not a registered trace lineage. "
        f"Create one with: codegraph-trace branch create {ref} --from <seq>"
    )


def _looks_like_sha(ref: str) -> bool:
    """Heuristic: detached HEAD short/long SHAs are hex strings."""
    if not ref or len(ref) < 7:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in ref)


def visible_step_sql(
    lineage: LineageInfo,
    *,
    alias: str = "s",
    include_imports: bool = False,
) -> tuple[str, list[Any]]:
    """SQL predicate (and params) restricting ``alias`` to steps visible on ``lineage``.

    Local steps follow one-way lineage visibility. Steps of *merged* lineages count as
    main-line: merge folds a branch into main by status flip, not by rewriting rows, so the
    predicate treats any ``lineage_id`` whose registry row says ``status = 'merged'`` as part
    of the main line. When ``include_imports`` is True, imported steps (``source_repo`` set)
    are also included — used by the query funnel so cross-repo context remains reachable.
    Version listings keep ``include_imports=False``.
    """
    local = f"({alias}.source_repo IS NULL)"
    main_line = (
        f"({alias}.lineage_id IS NULL OR {alias}.lineage_id = ? OR "
        f"{alias}.lineage_id IN (SELECT lineage_id FROM lineages WHERE status = 'merged'))"
    )
    if lineage.is_main:
        local_vis = f"({local} AND {main_line})"
        params: list[Any] = [MAIN_LINEAGE_ID]
    else:
        base_seq = lineage.base_seq
        if base_seq is None:
            local_vis = f"({local} AND {alias}.lineage_id = ?)"
            params = [lineage.lineage_id]
        else:
            local_vis = (
                f"({local} AND (("
                f"{main_line} AND {alias}.seq IS NOT NULL AND {alias}.seq <= ?"
                f") OR {alias}.lineage_id = ?))"
            )
            params = [MAIN_LINEAGE_ID, int(base_seq), lineage.lineage_id]

    if include_imports:
        return f"(({alias}.source_repo IS NOT NULL) OR {local_vis})", params
    return local_vis, params


def step_visible(
    step: dict[str, Any],
    lineage: LineageInfo,
    *,
    merged_lineage_ids: frozenset[str] | set[str] = frozenset(),
) -> bool:
    """Python-side visibility check matching :func:`visible_step_sql`.

    ``merged_lineage_ids`` (from :meth:`TraceDB.merged_lineage_ids`) lists lineages whose
    history has been folded into main; their steps count as main-line.
    """
    if step.get("source_repo"):
        return False
    lid = normalize_lineage_id(step.get("lineage_id"))
    is_main_line = lid == MAIN_LINEAGE_ID or lid in merged_lineage_ids
    if lineage.is_main:
        return is_main_line
    if lid == lineage.lineage_id:
        return True
    if not is_main_line:
        return False
    seq = step.get("seq")
    if seq is None or lineage.base_seq is None:
        return False
    return int(seq) <= int(lineage.base_seq)


def create_lineage(
    db: TraceDB,
    *,
    name: str,
    from_seq: int,
    repo_root: str | Path,
    parent_lineage: str = MAIN_LINEAGE_ID,
    checkout: bool = True,
) -> LineageInfo:
    """Register a new lineage forked from ``from_seq`` and optionally ``git checkout -b``.

    The fork point must be a step visible on the parent lineage. Refuses duplicate ids/refs.
    """
    name = (name or "").strip()
    if not name:
        raise LineageError("Lineage name must be non-empty.")
    if name == MAIN_LINEAGE_ID:
        raise LineageError(f"'{MAIN_LINEAGE_ID}' is reserved.")

    ensure_main_lineage(db)
    if db.get_lineage(name) is not None:
        raise LineageError(f"Lineage '{name}' already exists.")
    if db.get_lineage_by_git_ref(name) is not None:
        raise LineageError(f"A lineage already uses git ref '{name}'.")

    parent = db.get_lineage(parent_lineage)
    if parent is None:
        raise LineageError(f"Parent lineage '{parent_lineage}' does not exist.")

    base = db.get_step_by_seq(from_seq)
    if base is None:
        raise LineageError(
            f"No version {from_seq}. Run 'codegraph-trace versions' to list them."
        )
    if not step_visible(base, parent, merged_lineage_ids=db.merged_lineage_ids()):
        raise LineageError(
            f"Version {from_seq} is not visible on parent lineage '{parent_lineage}'."
        )
    after_sha = base.get("after_sha")
    if not after_sha:
        raise LineageError(
            f"Version {from_seq} has no recorded commit (after_sha); cannot fork from it."
        )

    created_at = utcnow_iso()
    db.upsert_lineage(
        lineage_id=name,
        git_ref=name,
        base_step_id=base["step_id"],
        base_seq=int(base["seq"]),
        base_commit=after_sha,
        parent_lineage=parent_lineage,
        status="open",
        created_at=created_at,
    )

    if checkout:
        if not gitdiff.working_tree_clean(repo_root):
            # Roll back the lineage row so a dirty tree does not leave a half-created fork.
            db.delete_lineage(name)
            raise LineageError(
                "Working tree has uncommitted changes to tracked files. "
                "Commit or stash them first."
            )
        try:
            gitdiff.checkout(repo_root, after_sha, new_branch=name)
        except gitdiff.GitError as exc:
            db.delete_lineage(name)
            raise LineageError(str(exc)) from exc

    info = db.get_lineage(name)
    assert info is not None
    return info


def list_lineages(db: TraceDB) -> list[LineageInfo]:
    """Every registered lineage, main first then by id."""
    ensure_main_lineage(db)
    return db.list_lineages()


@dataclass(frozen=True)
class MergeResult:
    """Outcome of :func:`merge_lineage`."""

    lineage: LineageInfo
    already_merged: bool
    steps_folded: int
    decision_rows_folded: int
    signatures_folded: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON / CLI output."""
        return {
            "lineage": self.lineage.to_dict(),
            "already_merged": self.already_merged,
            "steps_folded": self.steps_folded,
            "decision_rows_folded": self.decision_rows_folded,
            "signatures_folded": self.signatures_folded,
        }


def merge_lineage(db: TraceDB, *, name: str) -> MergeResult:
    """Fold a feature lineage into main's story, anchored at its fork point.

    No rows are copied or retagged: the lineage's ``status`` flips to ``merged`` and the
    visibility predicate (:func:`visible_step_sql`) starts treating its steps, node links and
    decision-ledger rows as main-line. Their global ``seq`` numbers already place them after
    the fork point. The branch's ``node_signatures`` are folded into main's cache so change
    detection on main reflects the branch's final state.

    Idempotent: merging an already-merged lineage changes nothing and reports ``already_merged``.
    """
    info = db.get_lineage(name)
    if info is None:
        raise LineageError(
            f"No lineage '{name}'. List them with 'codegraph-trace branch list'."
        )
    if info.is_main:
        raise LineageError("'main' is the merge target; it cannot itself be merged.")

    parent = db.get_lineage(info.parent_lineage)
    if parent is not None and not parent.is_main and not parent.is_merged:
        raise LineageError(
            f"Parent lineage '{info.parent_lineage}' is not merged yet; merge it first so "
            f"'{name}' joins a history that main can see."
        )

    def _counts() -> tuple[int, int]:
        steps = db.conn.execute(
            "SELECT COUNT(*) AS c FROM steps WHERE lineage_id = ? AND source_repo IS NULL",
            (name,),
        ).fetchone()["c"]
        decisions = db.conn.execute(
            "SELECT COUNT(*) AS c FROM branches WHERE lineage_id = ?", (name,)
        ).fetchone()["c"]
        return int(steps), int(decisions)

    if info.is_merged:
        steps, decisions = _counts()
        return MergeResult(
            lineage=info,
            already_merged=True,
            steps_folded=steps,
            decision_rows_folded=decisions,
            signatures_folded=0,
        )

    signatures = db.fold_signatures_into_main(name)
    db.set_lineage_status(name, "merged", merged_at=utcnow_iso())
    merged = db.get_lineage(name)
    assert merged is not None
    steps, decisions = _counts()
    return MergeResult(
        lineage=merged,
        already_merged=False,
        steps_folded=steps,
        decision_rows_folded=decisions,
        signatures_folded=signatures,
    )

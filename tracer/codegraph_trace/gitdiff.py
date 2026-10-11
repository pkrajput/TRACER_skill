"""Turn a git SHA range into changed files, changed line ranges, and change content.

We shell out to ``git diff --unified=0`` so each hunk gives us exact post-image line ranges,
which we intersect with code-node spans in :mod:`codegraph_trace.codegraph`. We also keep the
added/removed line text per file so the recorder can distinguish a substantive change from a
pure reformat (whitespace-only) diff.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Example hunk header: @@ -12,0 +13,4 @@ def foo():
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")
# Example file header: +++ b/path/to/file.py
_PLUS_FILE_RE = re.compile(r"^\+\+\+ (?:b/)?(.*)$")

_EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"  # git's canonical empty tree


class GitError(RuntimeError):
    """Raised when a git invocation fails."""


@dataclass
class FileDiff:
    """The diff for a single file within a SHA range."""

    file_path: str
    ranges: list[tuple[int, int]] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    @property
    def substantive(self) -> bool:
        """True when the change is more than whitespace/formatting.

        Compares added vs removed lines after stripping all whitespace. If the two collapse to
        the same multiset of non-empty tokens, the change is reformat-only noise.
        """
        def norm(lines: list[str]) -> list[str]:
            out = ["".join(s.split()) for s in lines]
            return sorted(s for s in out if s)

        return norm(self.added) != norm(self.removed)


def _run_git(repo_root: Path, args: list[str]) -> str:
    # Force UTF-8 on Windows; locale default (cp1252) breaks on binary-ish diff bytes.
    proc = subprocess.run(
        ["git", *args],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if proc.returncode != 0:
        stderr = (proc.stderr or "").strip()
        raise GitError(f"git {' '.join(args)} failed ({proc.returncode}): {stderr}")
    return proc.stdout or ""


def head_sha(repo_root: str | Path) -> Optional[str]:
    """Return the current HEAD sha, or None if there are no commits yet."""
    try:
        out = _run_git(Path(repo_root), ["rev-parse", "HEAD"]).strip()
        return out or None
    except GitError:
        return None


def file_at_sha(repo_root: str | Path, sha: Optional[str], rel_path: str) -> Optional[str]:
    """Return the contents of ``rel_path`` at commit ``sha`` (the post-step image).

    Used to parse the *current* version of a changed file with a language parser, instead of
    relying on the stale code graph. Returns None when the file does not exist at that commit
    (e.g. it was deleted) or when ``sha`` is None.
    """
    if not sha:
        return None
    norm = (rel_path or "").replace("\\", "/")
    try:
        return _run_git(Path(repo_root), ["show", f"{sha}:{norm}"])
    except GitError:
        return None


def ls_files(repo_root: str | Path, sha: Optional[str]) -> list[str]:
    """Every file path tracked in the tree at ``sha`` (empty on error / None sha)."""
    if not sha:
        return []
    try:
        out = _run_git(Path(repo_root), ["ls-tree", "-r", "--name-only", sha])
    except GitError:
        return []
    return [fp for fp in out.splitlines() if fp]


def list_commits(repo_root: str | Path, max_count: Optional[int] = None) -> list[str]:
    """Return commit SHAs oldest-first (chronological), optionally limited to the most recent
    ``max_count`` commits."""
    args = ["rev-list", "--reverse"]
    if max_count is not None:
        args = ["rev-list", "--max-count", str(max_count)]
    args.append("HEAD")
    try:
        out = _run_git(Path(repo_root), args)
    except GitError:
        return []
    shas = [s for s in out.split() if s]
    if max_count is not None:
        # rev-list (no --reverse) returns newest-first; flip to chronological.
        shas = list(reversed(shas))
    return shas


def working_tree_clean(repo_root: str | Path) -> bool:
    """True when the working tree has no uncommitted changes to *tracked* files.

    Uses ``git status --porcelain --untracked-files=no``: untracked files (including the
    recording layer's own ``.codegraph-trace/`` output) are ignored because a checkout carries
    them across unchanged and never loses them. Only modified/staged tracked files, which a
    checkout could clobber, count as dirty.
    """
    try:
        out = _run_git(Path(repo_root), ["status", "--porcelain", "--untracked-files=no"])
    except GitError:
        return False
    return out.strip() == ""


def current_ref(repo_root: str | Path) -> Optional[str]:
    """The current branch name, or the short SHA when in detached HEAD."""
    repo_root = Path(repo_root)
    try:
        branch = _run_git(repo_root, ["symbolic-ref", "--short", "-q", "HEAD"]).strip()
    except GitError:
        branch = ""
    if branch:
        return branch
    try:
        return _run_git(repo_root, ["rev-parse", "--short", "HEAD"]).strip() or None
    except GitError:
        return None


def is_path_tracked(repo_root: str | Path, rel: str) -> bool:
    """True when ``rel`` (a path or directory prefix) is tracked by git."""
    try:
        out = _run_git(Path(repo_root), ["ls-files", "--", rel])
    except GitError:
        return False
    return out.strip() != ""


def checkout(
    repo_root: str | Path,
    ref: str,
    new_branch: Optional[str] = None,
) -> None:
    """Check out ``ref`` (detached) or create ``new_branch`` pointing at it.

    Non-destructive: the prior branch and all commits remain; only the working tree and HEAD
    move. Raises :class:`GitError` on failure.
    """
    repo_root = Path(repo_root)
    if new_branch:
        _run_git(repo_root, ["checkout", "-b", new_branch, ref])
    else:
        _run_git(repo_root, ["checkout", ref])


def diff_files(
    repo_root: str | Path,
    before_sha: Optional[str],
    after_sha: Optional[str],
) -> dict[str, FileDiff]:
    """Return ``{file_path: FileDiff}`` for the given SHA range.

    If ``before_sha`` is None (the first step), the diff is taken against the empty tree so the
    initial file content is reported as added.
    """
    repo_root = Path(repo_root)
    if after_sha is None:
        after_sha = head_sha(repo_root)
    if after_sha is None:
        return {}
    base = before_sha if before_sha else _EMPTY_TREE

    out = _run_git(
        repo_root,
        ["diff", "--unified=0", "--no-color", "--no-renames", base, after_sha],
    )
    return parse_unified_diff(out)


def diff_text(
    repo_root: str | Path,
    before_sha: Optional[str],
    after_sha: Optional[str],
) -> str:
    """A human-readable unified diff (default 3-line context) for the given SHA range.

    Unlike :func:`diff_files` (which uses ``--unified=0`` for exact node linking), this is the
    diff a reviewer reads. ``before_sha`` of None diffs against the empty tree.
    """
    repo_root = Path(repo_root)
    if after_sha is None:
        after_sha = head_sha(repo_root)
    if after_sha is None:
        return ""
    base = before_sha if before_sha else _EMPTY_TREE
    return _run_git(
        repo_root,
        ["diff", "--no-color", "--no-renames", base, after_sha],
    )


def rev_parse(repo_root: str | Path, ref: str) -> Optional[str]:
    """Resolve ``ref`` to a full SHA, or None when it does not exist."""
    try:
        out = _run_git(Path(repo_root), ["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"])
    except GitError:
        return None
    return out.strip() or None


def changed_ranges(
    repo_root: str | Path,
    before_sha: Optional[str],
    after_sha: Optional[str],
) -> dict[str, list[tuple[int, int]]]:
    """Convenience wrapper returning only ``{file_path: [(start, end), ...]}``."""
    return {fp: fd.ranges for fp, fd in diff_files(repo_root, before_sha, after_sha).items()}


def parse_unified_diff(diff_text: Optional[str]) -> dict[str, FileDiff]:
    """Parse ``git diff --unified=0`` output into per-file :class:`FileDiff` objects."""
    if not diff_text:
        return {}
    result: dict[str, FileDiff] = {}
    current: Optional[FileDiff] = None

    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            m = _PLUS_FILE_RE.match(line)
            target = m.group(1) if m else None
            if target in (None, "/dev/null"):
                current = None
            else:
                fp = target.replace("\\", "/")
                current = result.setdefault(fp, FileDiff(file_path=fp))
            continue

        if line.startswith("--- "):
            continue

        if line.startswith("@@"):
            m = _HUNK_RE.match(line)
            if not m or current is None:
                continue
            new_start = int(m.group(3))
            new_count = int(m.group(4)) if m.group(4) is not None else 1
            if new_count == 0:
                start = max(new_start, 1)
                end = start
            else:
                start = new_start
                end = new_start + new_count - 1
            current.ranges.append((start, end))
            continue

        if current is None:
            continue
        # Body lines (unified=0): collect added/removed content, skip the file-header markers.
        if line.startswith("+") and not line.startswith("+++"):
            current.added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            current.removed.append(line[1:])

    return result

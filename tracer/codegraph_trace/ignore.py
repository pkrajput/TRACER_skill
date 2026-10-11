"""Exclude the recording layer's own output dirs from source attribution.

``.codegraph-trace/`` (and the OpenHands twin ``.codegraph-trace-openhands/``) hold the
trace DB, snapshots, and agent event logs. They must never be treated as application code
even when someone commits them. Setup writes ``.gitignore`` rules; the recorder still
filters these paths out of diffs so gitignore is not the only protection.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

TRACE_DIR_PREFIXES = (".codegraph-trace/", ".codegraph-trace-openhands/")
_TRACE_DIR_NAMES = tuple(p.rstrip("/") for p in TRACE_DIR_PREFIXES)


def is_trace_path(file_path: str) -> bool:
    """True for paths under the recording layer's own output directories."""
    norm = (file_path or "").replace("\\", "/")
    # Strip leading "./" segments only — do not use str.lstrip("./"), which would
    # also eat the leading dot of ".codegraph-trace/".
    while norm.startswith("./"):
        norm = norm[2:]
    return any(norm.startswith(p) or norm == p.rstrip("/") for p in TRACE_DIR_PREFIXES)


def ensure_gitignore(repo: Path) -> bool:
    """Append missing ignore rules for recording-layer output dirs.

    Returns True when the file was created or updated.
    """
    repo = Path(repo)
    gitignore = repo / ".gitignore"
    existing = gitignore.read_text(encoding="utf-8") if gitignore.is_file() else ""
    lines = existing.splitlines()
    present = {ln.strip().rstrip("/") for ln in lines}
    missing = [pat for pat in TRACE_DIR_PREFIXES if pat.rstrip("/") not in present]
    if not missing:
        return False
    block = ["", "# codegraph-trace: recording layer outputs (never commit)", *missing]
    new_text = (
        existing
        + ("\n" if existing and not existing.endswith("\n") else "")
        + "\n".join(block)
        + "\n"
    )
    gitignore.write_text(new_text, encoding="utf-8")
    return True


def untrack_trace_dirs(repo: Path) -> None:
    """Stop tracking recording-layer outputs if a prior run committed them.

    A ``.gitignore`` rule does not untrack already-tracked files, so without this every
    ``git add -A`` would keep committing event logs / the trace DB. ``git rm --cached`` is
    index-only (files stay on disk). Best-effort: failures are ignored.
    """
    repo = Path(repo)
    if not (repo / ".git").is_dir():
        return
    for path in _TRACE_DIR_NAMES:
        subprocess.run(
            ["git", "rm", "-r", "--cached", "--ignore-unmatch", "-q", path],
            cwd=str(repo),
            capture_output=True,
            check=False,
        )


def ensure_trace_ignored(repo: Path) -> None:
    """Write ignore rules and untrack the dirs when a git repo is present."""
    repo = Path(repo)
    ensure_gitignore(repo)
    if (repo / ".git").is_dir():
        untrack_trace_dirs(repo)

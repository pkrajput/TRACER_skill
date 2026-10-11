"""Per-commit JSON snapshots of how the code graph changed.

For each recorded step we write ``snapshots/<after_sha>.json`` listing which nodes and edges
were added, removed, or changed. The delta is computed from the changed files only (cheap) by
comparing the current code-graph state of those files against the signatures recorded for the
previous step (held in ``node_signatures``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from ..models import LinkedNode, Snapshot


class SnapshotWriter:
    """Writes ``snapshots/<after_sha>.json`` files."""

    def __init__(self, snapshots_dir: str | Path) -> None:
        self.snapshots_dir = Path(snapshots_dir)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)

    def path_for(self, after_sha: str) -> Path:
        # SHAs are filesystem-safe; fall back to the step id when there is no sha.
        """Filesystem path for the snapshot of ``after_sha``."""
        return self.snapshots_dir / f"{after_sha}.json"

    def write(self, snapshot: Snapshot) -> Path:
        """Write a snapshot JSON for ``after_sha`` and return its path."""
        key = snapshot.commit or snapshot.step_id
        out = self.path_for(key)
        out.write_text(json.dumps(snapshot.to_json(), indent=2), encoding="utf-8")
        return out


def build_snapshot(
    *,
    step_id: str,
    after_sha: Optional[str],
    before_sha: Optional[str],
    links: list[LinkedNode],
    edge_changes: dict[str, list[str]],
    seq: Optional[int] = None,
) -> Snapshot:
    """Assemble a :class:`Snapshot` from the per-node change classifications.

    ``links`` carry a ``change_kind`` of added / removed / changed for each node. ``edge_changes``
    is a dict with keys ``added`` / ``removed`` / ``changed`` of ``"qualified_name"`` entries
    whose incident edges changed. ``seq`` is the step's monotonic number, written into the
    snapshot so a reader can say "these nodes were added at step N".
    """
    snap = Snapshot(
        commit=after_sha or "",
        step_id=step_id,
        before_sha=before_sha,
        seq=seq,
    )
    for ln in links:
        qn = ln.node.qualified_name
        if ln.change_kind == "added":
            snap.nodes_added.append(qn)
        elif ln.change_kind == "removed":
            snap.nodes_removed.append(qn)
        else:
            snap.nodes_changed.append(qn)

    snap.edges_added = list(edge_changes.get("added", []))
    snap.edges_removed = list(edge_changes.get("removed", []))
    snap.edges_changed = list(edge_changes.get("changed", []))
    return snap

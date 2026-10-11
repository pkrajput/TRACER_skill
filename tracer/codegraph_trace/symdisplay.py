"""Human-readable rendering of touched code objects.

Recorded qualified names carry the full repo slug
(``Users-…-game.js.chess.Chess.clear``) which is precise but unreadable. These
helpers shorten names to what a developer actually says (``Chess.clear``,
``connectGames``, ``.side-btn``), dedupe repeats, and group nodes by change
kind so both ``codegraph-trace history`` and ``tracer pull`` can print the
same compact "objects touched" summary.

This module is deliberately dependency-free (stdlib only) so the lean sync
CLI can import it without pulling in the graph/query stack.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Iterable, Optional

# Display order for change-kind groups; unknown kinds follow in first-seen order.
_KIND_ORDER = ("added", "changed", "removed")
KIND_SYMBOLS = {"added": "+", "changed": "~", "removed": "-"}


def short_symbol_name(qualified_name: str, file_path: Optional[str] = None) -> str:
    """Shorten a fully-qualified node name to its human part.

    The recorded form is ``<repo-slug>.<module.path>.<Symbol.path>`` where the
    module path mirrors ``file_path`` without its extension. We locate the
    module part and keep only what follows it. Falls back to the last two
    dot-segments when the file hint doesn't match.
    """
    if qualified_name.startswith("file::"):
        return qualified_name[len("file::"):]
    if file_path and qualified_name.rsplit(".", 1)[-1] == "__file__":
        # Whole-file node: the file path reads better than "connector.__file__".
        return file_path
    if file_path:
        module = ".".join(PurePosixPath(file_path.replace("\\", "/")).with_suffix("").parts)
        if module:
            idx = qualified_name.find(module + ".")
            if idx != -1:
                rest = qualified_name[idx + len(module) + 1:]
                if rest:
                    return rest
            if qualified_name.endswith(module):
                # File-level node: the qualified name IS the module; show the file.
                return file_path
    parts = qualified_name.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else qualified_name


def _node_suffix(node: dict[str, Any], branch_marker: Optional[str]) -> str:
    tags = []
    if (node.get("author") or "") == "human":
        tags.append("human-written")
    if node.get("locked"):
        tags.append("locked")
    out = f" [{', '.join(tags)}]" if tags else ""
    if branch_marker:
        out += f" {branch_marker}"
    return out


def summarize_touched_nodes(
    nodes: Iterable[dict[str, Any]],
    branch_markers: Optional[dict[str, str]] = None,
) -> list[tuple[str, list[str]]]:
    """Group node-link rows by change kind with short, deduped display names.

    ``branch_markers`` optionally maps a qualified name to a decision-ledger
    marker string (e.g. ``[abandoned - superseded by step 3]``) appended to
    that node's display name.

    Returns an ordered list of ``(change_kind, [display_name, ...])`` pairs.
    Duplicate rows for the same qualified name (which can appear in older
    trace data) are merged, keeping the strongest lock/author tags.
    """
    branch_markers = branch_markers or {}
    merged: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for n in nodes:
        qn = n.get("qualified_name") or "?"
        if qn not in merged:
            merged[qn] = dict(n)
            order.append(qn)
        else:
            prev = merged[qn]
            prev["locked"] = prev.get("locked") or n.get("locked")
            if (n.get("author") or "") == "human":
                prev["author"] = "human"

    groups: dict[str, list[str]] = {}
    kind_order: list[str] = []
    for qn in order:
        node = merged[qn]
        kind = node.get("change_kind") or "touched"
        if kind not in groups:
            groups[kind] = []
            kind_order.append(kind)
        name = short_symbol_name(qn, node.get("file_path"))
        groups[kind].append(name + _node_suffix(node, branch_markers.get(qn)))

    ordered = [k for k in _KIND_ORDER if k in groups]
    ordered += [k for k in kind_order if k not in _KIND_ORDER]
    return [(k, groups[k]) for k in ordered]

"""The read side: open a file's (or symbol's) reasoning log, or search reasoning.

If recording is done well, querying is almost nothing - each file already carries its ordered
story. These helpers just read it back.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

from . import symdisplay
from .codegraph import normalize_path
from .config import TraceConfig
from .store.trace_db import TraceDB

if TYPE_CHECKING:
    from .lineage import LineageInfo

_CODE_SUFFIXES = (
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt", ".c", ".cc",
    ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".swift", ".scala", ".sql", ".sh",
)


@dataclass
class HistoryEntry:
    """One step in a file's or symbol's reasoning log."""

    step_id: str
    timestamp: str
    before_sha: Optional[str]
    after_sha: Optional[str]
    prompt: str
    reasoning_text: str
    nodes: list[dict[str, Any]]
    seq: Optional[int] = None
    # Decision-ledger rows for this step (empty until `branches derive` has been run).
    branches: list[dict[str, Any]] = field(default_factory=list)
    # Who produced the step: "agent" or "human" (None on rows recorded before the column).
    author: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        """Serialize this history entry for JSON output."""
        return {
            "step_id": self.step_id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "before_sha": self.before_sha,
            "after_sha": self.after_sha,
            "prompt": self.prompt,
            "reasoning_text": self.reasoning_text,
            "author": self.author,
            "nodes": self.nodes,
            "branches": self.branches,
        }


@dataclass
class HistoryResolution:
    """Result of resolving a history target with symbol → file fallback."""

    target: str
    scope: str  # "symbol" | "file" | "none"
    file_path: Optional[str]
    entries: list[HistoryEntry]
    markers: Optional[dict[str, Any]] = None
    # Recorded QN used for lookup when it differs from ``target`` (prefix drift).
    resolved_qualified_name: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        """Serialize the resolved history (scope, markers, entries) for JSON output."""
        return {
            "target": self.target,
            "scope": self.scope,
            "file_path": self.file_path,
            "markers": self.markers,
            "resolved_qualified_name": self.resolved_qualified_name,
            "entries": [e.as_dict() for e in self.entries],
        }


@dataclass
class StoryResolution:
    """Raw DB-level story for a finding or panel target (shared with ``flag``)."""

    target: str
    scope: str  # "symbol" | "file" | "none"
    file_path: Optional[str]
    steps: list[dict[str, Any]]
    markers: Optional[dict[str, Any]]
    branch_rows: list[dict[str, Any]]
    # Recorded QN used for lookup when it differs from ``target`` (prefix drift).
    resolved_qualified_name: Optional[str] = None


def looks_like_file_path(target: str) -> bool:
    """Heuristic: path separator or known code suffix → treat as a file path."""
    t = target or ""
    return "/" in t or "\\" in t or t.endswith(_CODE_SUFFIXES)


def file_path_for_symbol(
    db: TraceDB,
    qualified_name: str,
    *,
    explicit: Optional[str] = None,
) -> Optional[str]:
    """Best-effort file path for a symbol QN (explicit arg, signature, links, ``file::``)."""
    if explicit:
        return normalize_path(explicit)
    qn = qualified_name or ""
    if qn.startswith("file::"):
        return normalize_path(qn[len("file::") :])
    sig = db.get_signature(qn)
    if sig and sig.get("file_path"):
        return normalize_path(sig["file_path"])
    row = db.conn.execute(
        """
        SELECT file_path FROM node_links
        WHERE qualified_name = ? AND file_path IS NOT NULL AND file_path != ''
        LIMIT 1
        """,
        (qn,),
    ).fetchone()
    if row and row["file_path"]:
        return normalize_path(row["file_path"])
    return None


def _short_name(qualified_name: str) -> str:
    return (qualified_name or "").rsplit(".", 1)[-1]


def _overlaps(a_lo: int, a_hi: int, b_lo: int, b_hi: int) -> bool:
    return a_lo <= b_hi and b_lo <= a_hi


def _suffix_score(target: str, recorded: str) -> int:
    """Length of the longest trailing dotted suffix of ``target`` that matches ``recorded``."""
    parts = [p for p in (target or "").split(".") if p]
    best = 0
    for i in range(len(parts)):
        suffix = ".".join(parts[i:])
        if recorded == suffix or recorded.endswith("." + suffix):
            best = max(best, len(suffix))
    return best


def _has_node_link(db: TraceDB, qualified_name: str) -> bool:
    row = db.conn.execute(
        "SELECT 1 FROM node_links WHERE qualified_name = ? LIMIT 1",
        (qualified_name,),
    ).fetchone()
    return row is not None


def recorded_qns_for_file(db: TraceDB, file_path: str) -> list[str]:
    """Distinct non-file symbol QNs recorded against ``file_path``."""
    fp = normalize_path(file_path)
    rows = db.conn.execute(
        """
        SELECT DISTINCT qualified_name FROM node_links
        WHERE file_path = ?
          AND qualified_name IS NOT NULL AND qualified_name != ''
          AND qualified_name NOT LIKE 'file::%'
        ORDER BY qualified_name
        """,
        (fp,),
    ).fetchall()
    return [r["qualified_name"] for r in rows]


def match_recorded_qualified_name(
    target: str,
    recorded_qns: list[str],
    *,
    signatures: Optional[dict[str, dict[str, Any]]] = None,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
) -> Optional[str]:
    """Pick the single unambiguous recorded QN for a (possibly drifted) graph QN.

    Same-file candidates must share the short name. Longer dotted-suffix matches win;
    optional span overlap breaks remaining ties. Returns None when ambiguous or empty.
    """
    target = (target or "").strip()
    if not target or not recorded_qns:
        return None
    if target in recorded_qns:
        return target

    short = _short_name(target)
    candidates = [qn for qn in recorded_qns if _short_name(qn) == short]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]

    scored = [(qn, _suffix_score(target, qn)) for qn in candidates]
    best_score = max(score for _, score in scored)
    if best_score > 0:
        candidates = [qn for qn, score in scored if score == best_score]
        if len(candidates) == 1:
            return candidates[0]

    lo = int(start_line or 0)
    hi = int(end_line or start_line or 0)
    if lo > 0 and signatures:
        overlapping: list[str] = []
        for qn in candidates:
            sig = signatures.get(qn) or {}
            s_lo = int(sig.get("start_line") or 0)
            s_hi = int(sig.get("end_line") or s_lo)
            if s_lo > 0 and _overlaps(s_lo, s_hi, lo, hi):
                overlapping.append(qn)
        if len(overlapping) == 1:
            return overlapping[0]
        if overlapping:
            candidates = overlapping

    return candidates[0] if len(candidates) == 1 else None


def resolve_recorded_qualified_name(
    db: TraceDB,
    target: str,
    *,
    file_path: Optional[str] = None,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
) -> Optional[str]:
    """Map a graph/short QN to the matching recorded QN in ``trace.db``, or None.

    Exact ``node_links`` hits return ``target`` unchanged. Otherwise requires a file path
    (explicit or inferred) and applies :func:`match_recorded_qualified_name`.
    """
    target = (target or "").strip()
    if not target or looks_like_file_path(target):
        return None
    if _has_node_link(db, target):
        return target

    fp = file_path_for_symbol(db, target, explicit=file_path)
    if not fp:
        return None

    recorded = recorded_qns_for_file(db, fp)
    if not recorded:
        return None

    signatures: dict[str, dict[str, Any]] = {}
    if start_line:
        for qn in recorded:
            sig = db.get_signature(qn)
            if sig:
                signatures[qn] = sig

    return match_recorded_qualified_name(
        target,
        recorded,
        signatures=signatures or None,
        start_line=start_line,
        end_line=end_line,
    )


def resolve_story(
    db: TraceDB,
    target: str,
    *,
    file_path: Optional[str] = None,
    start_line: Optional[int] = None,
    end_line: Optional[int] = None,
    lineage: Optional["LineageInfo"] = None,
) -> StoryResolution:
    """Shared symbol→file story lookup used by Semgrep ``flag`` and the panel.

    Tries exact symbol (or file) history first; aliases graph QNs that drifted after
    re-index to the matching recorded QN; if a symbol still has no steps, falls back to
    the file's recorded history. ``scope`` is ``symbol``, ``file``, or ``none``.

    When ``lineage`` is set, steps and decision-ledger rows respect one-way visibility.
    """
    target = (target or "").strip()
    if not target:
        return StoryResolution(
            target=target,
            scope="none",
            file_path=None,
            steps=[],
            markers=None,
            branch_rows=[],
        )

    if looks_like_file_path(target):
        fp = normalize_path(target)
        steps = db.steps_for_file(fp, lineage=lineage)
        branches = db.list_branches(target=fp, lineage=lineage)
        return StoryResolution(
            target=target,
            scope="file" if steps else "none",
            file_path=fp,
            steps=steps,
            markers=None,
            branch_rows=branches,
        )

    lookup_qn = target
    resolved: Optional[str] = None
    aliased = resolve_recorded_qualified_name(
        db,
        target,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
    )
    if aliased and aliased != target:
        lookup_qn = aliased
        resolved = aliased

    steps = db.steps_for_qualified_name(lookup_qn, lineage=lineage)
    markers = db.node_step_markers(lookup_qn, lineage=lineage)
    branches = db.list_branches(target=lookup_qn, lineage=lineage)
    fp = file_path_for_symbol(db, lookup_qn, explicit=file_path)
    if steps:
        return StoryResolution(
            target=target,
            scope="symbol",
            file_path=fp,
            steps=steps,
            markers=markers,
            branch_rows=branches,
            resolved_qualified_name=resolved or (lookup_qn if lookup_qn != target else None),
        )

    if fp:
        file_steps = db.steps_for_file(fp, lineage=lineage)
        if not branches:
            branches = db.list_branches(target=fp, lineage=lineage)
        if file_steps:
            return StoryResolution(
                target=target,
                scope="file",
                file_path=fp,
                steps=file_steps,
                markers=None,
                branch_rows=branches,
                resolved_qualified_name=resolved,
            )
        return StoryResolution(
            target=target,
            scope="none",
            file_path=fp,
            steps=[],
            markers=None,
            branch_rows=branches,
            resolved_qualified_name=resolved,
        )

    return StoryResolution(
        target=target,
        scope="none",
        file_path=None,
        steps=[],
        markers=markers,
        branch_rows=branches,
        resolved_qualified_name=resolved,
    )


@dataclass
class Version:
    """One point in the recorded version sequence (a single recorded step).

    Versions are numbered by the monotonic ``steps.seq`` (1, 2, 3, ...) and each maps to the
    git commit (``after_sha``) that captured that step. ``added`` / ``removed`` / ``changed``
    are the node-delta counts so a listing reads like a simple time series.
    """

    seq: int
    step_id: str
    timestamp: str
    before_sha: Optional[str]
    after_sha: Optional[str]
    changed_file_count: int
    added: int
    removed: int
    changed: int
    prompt: str
    author: Optional[str] = None
    lineage_id: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        """Serialize this version row for JSON output."""
        return {
            "seq": self.seq,
            "step_id": self.step_id,
            "timestamp": self.timestamp,
            "before_sha": self.before_sha,
            "after_sha": self.after_sha,
            "changed_file_count": self.changed_file_count,
            "added": self.added,
            "removed": self.removed,
            "changed": self.changed,
            "prompt": self.prompt,
            "author": self.author,
            "lineage_id": self.lineage_id or "main",
        }


class TraceQuery:
    """Read-only access to a recorded trace."""

    def __init__(self, config: TraceConfig, *, enable_embeddings: bool = True) -> None:
        self.config = config
        self.db = TraceDB(config.trace_db_path)
        self.chroma = None
        if enable_embeddings and config.chroma_dir.exists():
            try:
                from .store.chroma_store import ChromaStore

                self.chroma = ChromaStore(config.chroma_dir, config.embedding_model)
            except Exception:
                self.chroma = None
        self._lineage: Optional[LineageInfo] = None

    def active_lineage(self) -> LineageInfo:
        """Resolve (and cache) the lineage for the current git HEAD."""
        if self._lineage is None:
            from .lineage import resolve_lineage

            self._lineage = resolve_lineage(
                self.db, self.config.repo_root, allow_unregistered=True
            )
        return self._lineage

    def close(self) -> None:
        """Close the trace DB and optional Chroma store."""
        self.db.close()

    def __enter__(self) -> "TraceQuery":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # --- "open the reasoning log" -------------------------------------
    def get_file_history(self, file_path: str) -> list[HistoryEntry]:
        """Return the ordered reasoning log for every step that touched ``file_path``."""
        return [
            self._entry(row)
            for row in self.db.steps_for_file(file_path, lineage=self.active_lineage())
        ]

    def get_node_history(self, qualified_name: str) -> list[HistoryEntry]:
        """Return the ordered reasoning log for every step that linked ``qualified_name``."""
        return [
            self._entry(row)
            for row in self.db.steps_for_qualified_name(
                qualified_name, lineage=self.active_lineage()
            )
        ]

    def get_node_markers(self, qualified_name: str) -> Optional[dict[str, Any]]:
        """Step-number markers (introduced/last-changed) for a single node, or None."""
        return self.db.node_step_markers(qualified_name, lineage=self.active_lineage())

    def resolve_history(
        self,
        target: str,
        *,
        file_path: Optional[str] = None,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> HistoryResolution:
        """Resolve history with the shared symbol → file fallback (see :func:`resolve_story`)."""
        story = resolve_story(
            self.db,
            target,
            file_path=file_path,
            start_line=start_line,
            end_line=end_line,
            lineage=self.active_lineage(),
        )
        return HistoryResolution(
            target=story.target,
            scope=story.scope,
            file_path=story.file_path,
            entries=[self._entry(row) for row in story.steps],
            markers=story.markers,
            resolved_qualified_name=story.resolved_qualified_name,
        )

    # --- versions (the recorded time series) --------------------------
    def list_versions(self) -> list[Version]:
        """Every recorded version visible on the active lineage, ordered by ``seq``."""
        return [self._version(row) for row in self.db.list_steps(lineage=self.active_lineage())]

    def get_version(self, seq: int) -> Optional[Version]:
        """The version with the given sequence number, or None if it does not exist / is hidden."""
        row = self.db.get_step_by_seq(seq)
        if row is None:
            return None
        from .lineage import step_visible

        if not step_visible(
            row, self.active_lineage(), merged_lineage_ids=self.db.merged_lineage_ids()
        ):
            return None
        return self._version(row)

    def _version(self, row: dict[str, Any]) -> Version:
        seq = row.get("seq")
        changed_files = row.get("changed_files") or ""
        file_count = len([f for f in changed_files.split(",") if f])
        counts = self.db.link_counts(row["step_id"])
        return Version(
            seq=int(seq) if seq is not None else 0,
            step_id=row["step_id"],
            timestamp=row.get("timestamp") or "",
            before_sha=row.get("before_sha"),
            after_sha=row.get("after_sha"),
            changed_file_count=file_count,
            added=counts["added"],
            removed=counts["removed"],
            changed=counts["changed"],
            prompt=row.get("prompt") or "",
            author=row.get("author"),
            lineage_id=row.get("lineage_id") or "main",
        )

    def recent_activity(self, limit: int = 10) -> tuple[list[HistoryEntry], int]:
        """The newest recorded steps repo-wide, newest first.

        Returns ``(entries, total_step_count)`` so callers can say "last 10 of 17".
        """
        rows = self.db.list_steps(lineage=self.active_lineage())
        recent = [self._entry(r) for r in reversed(rows[-limit:])]
        return recent, len(rows)

    def _entry(self, row: dict[str, Any]) -> HistoryEntry:
        seq = row.get("seq")
        return HistoryEntry(
            step_id=row["step_id"],
            seq=int(seq) if seq is not None else None,
            timestamp=row.get("timestamp") or "",
            before_sha=row.get("before_sha"),
            after_sha=row.get("after_sha"),
            prompt=row.get("prompt") or "",
            reasoning_text=row.get("reasoning_text") or "",
            nodes=self.db.links_for_step(row["step_id"]),
            branches=self.db.branches_for_step(row["step_id"]),
            author=row.get("author"),
        )

    # --- semantic search ----------------------------------------------
    def semantic_search(self, query: str, k: int = 5) -> list[dict[str, Any]]:
        """Rank recorded reasoning by embedding similarity to ``query``."""
        if self.chroma is None:
            raise RuntimeError(
                "Semantic search needs ChromaDB embeddings, which are not available "
                "(install chromadb / sentence-transformers or record with embeddings enabled)."
            )
        visible = {s["step_id"] for s in self.db.list_steps(lineage=self.active_lineage())}
        hits = self.chroma.query(query, k=k, visible_step_ids=visible)
        for hit in hits:
            step = self.db.get_step(hit["step_id"])
            if step:
                hit["prompt"] = step.get("prompt")
                hit["reasoning_text"] = step.get("reasoning_text")
                hit["after_sha"] = step.get("after_sha")
        return hits


def format_history(
    entries: list[HistoryEntry],
    target: str,
    markers: Optional[dict[str, Any]] = None,
    *,
    scope: Optional[str] = None,
    file_path: Optional[str] = None,
    color: bool = False,
) -> str:
    """Render a reasoning log as readable text for the CLI."""
    if not entries:
        if scope == "none" or scope is None:
            return f"No trace data recorded for '{target}'."
        return f"No recorded reasoning for '{target}'."
    if scope == "file" and file_path and not looks_like_file_path(target):
        header = (
            f"No recorded steps for symbol '{target}'; showing file history for "
            f"'{file_path}' ({len(entries)} step(s)):"
        )
    else:
        header = f"Reasoning log for '{target}' ({len(entries)} step(s)):"
    if markers:
        header += (
            f"\nintroduced at step {markers['introduced_at_step']}, "
            f"last changed at step {markers['last_changed_at_step']} "
            f"({markers['touch_count']} touch(es))"
        )
    lines = [header, ""]
    for i, e in enumerate(entries, 1):
        sha = (e.after_sha or "")[:10]
        step_no = f"step#{e.seq} " if e.seq is not None else ""
        # Decision-ledger markers: symbol-level rows tag their node below; file-level rows
        # (empty qualified_name) tag the entry line itself.
        branch_by_qn = {
            b["qualified_name"]: b for b in e.branches if b.get("qualified_name")
        }
        file_markers = _dedupe(
            _branch_marker(b) for b in e.branches if not b.get("qualified_name")
        )
        entry_line = f"{i}. {step_no}{e.step_id}  @ {sha}  {e.timestamp}"
        if file_markers:
            entry_line += "  " + " ".join(file_markers)
        lines.append(entry_line)
        if e.prompt:
            lines.append(f"   prompt: {_truncate(e.prompt)}")
        if e.reasoning_text:
            # Show the full reasoning verbatim (it can be long); never truncate it. Each line is
            # indented so it stays visually grouped under its step.
            reasoning = e.reasoning_text.strip("\n")
            indented = "\n".join("   " + ln for ln in reasoning.splitlines())
            lines.append("   reasoning:")
            lines.append(indented)
        if e.nodes:
            lines.append("   objects touched:")
            lines.extend(format_touched_nodes(e.nodes, branch_by_qn, color=color))
        lines.append("")
    return "\n".join(lines)


def format_recent_activity(
    entries: list[HistoryEntry],
    total: int,
    *,
    color: bool = False,
) -> str:
    """Render the repo-wide recent-activity view (``history`` with no target).

    A compact scan of the newest steps: who did what, in which files, touching
    which objects — so you can spot an incoming change without knowing the file.
    """
    if not entries:
        return "No trace data recorded yet."
    header = (
        f"Recent activity — last {len(entries)} of {total} recorded step(s), newest first:"
    )
    lines = [header, ""]
    for e in entries:
        step_no = f"step#{e.seq} " if e.seq is not None else ""
        sha = (e.after_sha or "")[:10]
        author = f"  [{e.author}]" if e.author else ""
        lines.append(f"{step_no}{e.step_id}  @ {sha}  {e.timestamp}{author}")
        reasoning = (e.reasoning_text or "").strip().splitlines()
        if reasoning:
            lines.append(f"   {reasoning[0]}")
        files = _dedupe(
            n.get("file_path") for n in e.nodes if n.get("file_path")
        )
        if files:
            lines.append(f"   files: {', '.join(files)}")
        if e.nodes:
            lines.extend(format_touched_nodes(e.nodes, color=color))
        lines.append("")
    lines.append("Full story of one file or symbol: codegraph-trace history <target> --repo <repo>")
    return "\n".join(lines)


_ANSI_COLORS = {"added": "\033[32m", "changed": "\033[33m", "removed": "\033[31m"}
_ANSI_RESET = "\033[0m"


def format_touched_nodes(
    nodes: list[dict[str, Any]],
    branch_by_qn: Optional[dict[str, dict[str, Any]]] = None,
    *,
    color: bool = False,
    indent: str = "     ",
    width: int = 100,
) -> list[str]:
    """Render node links as grouped, wrapped ``+ added (N): name, name…`` lines.

    Names are shortened and deduped via :mod:`symdisplay`; groups are colorized
    (green added / yellow changed / red removed) when ``color`` is True.
    """
    import textwrap

    # Per-node markers only for the interesting ledger kinds; "[survived]" is the common case
    # and repeating it on every node is pure noise (the step line already carries it).
    markers = {
        qn: m
        for qn, b in (branch_by_qn or {}).items()
        if (m := _branch_marker(b)) != "[survived]"
    }
    out: list[str] = []
    for kind, names in symdisplay.summarize_touched_nodes(nodes, markers):
        symbol = symdisplay.KIND_SYMBOLS.get(kind, "•")
        prefix = f"{indent}{symbol} {kind} ({len(names)}): "
        wrapped = textwrap.wrap(
            ", ".join(names),
            width=max(width - len(prefix), 40),
            break_long_words=False,
            break_on_hyphens=False,
        ) or [""]
        group_lines = [prefix + wrapped[0]]
        group_lines += [" " * len(prefix) + w for w in wrapped[1:]]
        if color and kind in _ANSI_COLORS:
            group_lines = [f"{_ANSI_COLORS[kind]}{ln}{_ANSI_RESET}" for ln in group_lines]
        out.extend(group_lines)
    return out


def _branch_marker(row: dict[str, Any]) -> str:
    """Render one decision-ledger row as a compact marker, e.g. ``[abandoned - superseded by
    step 3]`` or ``[error retry]``."""
    kind = row.get("kind")
    if kind == "error_retry":
        return "[error retry]"
    if kind in ("abandoned", "revised"):
        sup = row.get("superseded_by_seq")
        suffix = f" - superseded by step {int(sup)}" if sup is not None else ""
        return f"[{kind}{suffix}]"
    return "[survived]"


def _dedupe(items) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def format_versions(
    versions: list[Version],
    important_step_ids: Optional[set[str]] = None,
) -> str:
    """Render the recorded version sequence as a readable time series for the CLI.

    Steps in ``important_step_ids`` (decision points: an abandoned attempt, an error retry, a
    supersession, or a touch on a human-locked node) are tagged ``[decision]``.
    """
    if not versions:
        return "No recorded versions yet."
    important = important_step_ids or set()
    lines = [f"Recorded versions ({len(versions)}):", ""]
    for v in versions:
        sha = (v.after_sha or "")[:10] or "-"
        files = f"{v.changed_file_count} file(s)"
        delta = f"(+{v.added} ~{v.changed} -{v.removed})"
        prompt = _truncate(v.prompt, 80) if v.prompt else ""
        lines.append(
            f"{v.seq:>3}  {sha:<10}  {v.timestamp}  {files}  {delta}"
            + ("  [decision]" if v.step_id in important else "")
            + (f'  "{prompt}"' if prompt else "")
        )
    lines.append("")
    lines.append("Go back with: codegraph-trace goto <N> --repo <repo>")
    return "\n".join(lines)


def _truncate(text: str, limit: int = 280) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."

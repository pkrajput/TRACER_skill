"""The recording loop.

:meth:`Recorder.record_step` is the heart of the system. For one agent step it:

1. diffs ``before_sha..after_sha`` to get changed files + line ranges + change content,
2. resolves the code nodes those changed lines touched (read-only code graph),
3. drops pure reformat (whitespace-only) noise and classifies each kept node as
   added / changed / removed using the recorded node signatures,
4. writes the step row, the node-link bridge rows, the updated signatures, the reasoning
   embedding, and the per-commit JSON snapshot.

Re-recording the same ``step_id`` is idempotent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from . import gitdiff
from .ast_symbols import extract_symbols, language_for_path
from .codegraph import CodeGraph, normalize_path
from .config import TraceConfig
from .ignore import is_trace_path
from .models import LinkedNode, NodeRef, Step, utcnow_iso
from .store.snapshots import SnapshotWriter, build_snapshot
from .store.trace_db import TraceDB

# Node labels that live-source (AST) symbol extraction can produce. For these, the post-step
# source is the authority on whether a symbol still exists; other labels (File, Module, Route,
# ...) only ever come from the code graph and are checked against it.
_LIVE_SYMBOL_LABELS = {"Class", "Function", "Method", "Interface", "Enum", "Rule", "Keyframes"}

# Back-compat alias for callers that imported the private name.
_is_trace_path = is_trace_path


def _combine_reasoning(*texts: str) -> str:
    """Join reasoning fragments with a blank line, dropping empties."""
    parts = [(t or "").strip() for t in texts]
    return "\n\n".join(p for p in parts if p)


# Basenames that can appear in a git diff but never produce symbol links we would index.
# A step whose cumulative window only touches these (plus trace dirs) is not a version boundary.
_NON_INDEXABLE_BASENAMES = frozenset({".gitignore"})


def is_indexable_path(file_path: str) -> bool:
    """True for paths we would attribute as code when deciding version boundaries.

    Excludes the recorder's own output dirs and pure meta files (e.g. ``.gitignore``) that
    never produce symbol links.
    """
    if is_trace_path(file_path):
        return False
    norm = (file_path or "").replace("\\", "/")
    while norm.startswith("./"):
        norm = norm[2:]
    base = norm.rsplit("/", 1)[-1]
    return base not in _NON_INDEXABLE_BASENAMES


def _step_changes_code(config: TraceConfig, step: Step) -> bool:
    """True when this step's cumulative git diff touches an indexable path.

    "Changes code" means there is something we would index. A step whose diff is empty, only
    the recorder's own ``.codegraph-trace/`` bookkeeping, or only meta files like ``.gitignore``
    is not a real version boundary.
    """
    diff = gitdiff.diff_files(config.repo_root, step.before_sha, step.after_sha)
    return any(is_indexable_path(fp) for fp in diff)


def _merge_raw_events(dst: Step, src: Step) -> None:
    """Append ``src``'s raw trail onto ``dst`` when either side carries a list."""
    if isinstance(src.raw_event, list):
        if isinstance(dst.raw_event, list):
            dst.raw_event = [*dst.raw_event, *src.raw_event]
        else:
            dst.raw_event = list(src.raw_event)


def _fold_step_into(dst: Step, src: Step) -> None:
    """Fold ``src`` into ``dst``: reasoning, raw trail, and extend ``after_sha``."""
    dst.reasoning_text = _combine_reasoning(dst.reasoning_text, src.reasoning_text)
    dst.reasoning_segments = [
        *getattr(dst, "reasoning_segments", []),
        *getattr(src, "reasoning_segments", []),
    ]
    _merge_raw_events(dst, src)
    dst.after_sha = src.after_sha


def merge_empty_diff_steps(config: TraceConfig, steps: list[Step]) -> list[Step]:
    """Fold consecutive turns until the cumulative git diff is indexable.

    Steps must already carry ``before_sha`` / ``after_sha``. Keep merging the next step into an
    open buffer (reasoning + raw trail + ``after_sha``) until the buffer's cumulative
    ``before_sha..after_sha`` window touches an indexable path; then emit one version. Trailing
    non-indexable turns fold into the last emitted version. A session that never touches
    indexable code collapses to a single step so the reasoning trail is still recorded.

    When a buffer becomes indexable by folding in a completing step, that step's identity
    (``step_id`` / prompt / timestamp / author) is adopted — same as the old lead-forward rule.
    """
    if not steps:
        return []

    kept: list[Step] = []
    buf: Optional[Step] = None

    for step in steps:
        if buf is None:
            buf = step
        else:
            _fold_step_into(buf, step)
            if _step_changes_code(config, buf):
                # Completing turn wins identity (lead empties fold into the changing step).
                buf.step_id = step.step_id
                buf.prompt = step.prompt
                buf.timestamp = step.timestamp
                buf.author = step.author
                kept.append(buf)
                buf = None
            continue

        if _step_changes_code(config, buf):
            kept.append(buf)
            buf = None

    if buf is not None:
        if kept:
            _fold_step_into(kept[-1], buf)
        else:
            # Entire session was non-indexable: one collapsed step, not N empty versions.
            kept.append(buf)
    return kept


def replay_over_commits(
    recorder: "Recorder",
    steps: list[Step],
    commit_shas: list[str],
) -> list["RecordResult"]:
    """Drive the recorder over a session whose steps map 1:1 to commits in order.

    Step ``i`` is recorded with ``after_sha = commit_shas[i]`` and ``before_sha`` set to the
    previous commit (or None for the first), so each step's git diff captures exactly what that
    step changed. Extra steps beyond the available commits reuse the last commit's after_sha.

    Consecutive turns are cumulatively merged until the git diff is indexable (see
    :func:`merge_empty_diff_steps`) before recording, so empty / meta-only turns do not become
    their own versions.
    """
    prev: Optional[str] = None
    for i, step in enumerate(steps):
        after = commit_shas[i] if i < len(commit_shas) else (commit_shas[-1] if commit_shas else None)
        step.before_sha = prev
        step.after_sha = after
        prev = after

    merged = merge_empty_diff_steps(recorder.config, steps)
    return [recorder.record_step(step) for step in merged]


@dataclass
class RecordResult:
    """What a single :meth:`Recorder.record_step` produced."""

    step_id: str
    changed_files: list[str] = field(default_factory=list)
    linked_nodes: list[LinkedNode] = field(default_factory=list)
    snapshot_path: Optional[str] = None
    skipped_reformat: bool = False
    author: str = "agent"
    locked_nodes: list[str] = field(default_factory=list)
    proposed_nodes: list[str] = field(default_factory=list)


class Recorder:
    """Owns the trace stores and runs the recording loop for a repo."""

    def __init__(self, config: TraceConfig, *, enable_embeddings: bool = True) -> None:
        self.config = config
        self.config.ensure_dirs()

        self.codegraph: Optional[CodeGraph] = None
        if config.graph_db_path and Path(config.graph_db_path).is_file():
            self.codegraph = CodeGraph(config.graph_db_path)

        self.db = TraceDB(config.trace_db_path)
        self.snapshots = SnapshotWriter(config.snapshots_dir)
        self._active_lineage_id = "main"

        # Qualified names owned by a read-only import: we may read their reasoning for context
        # but must never modify them, so the other repo's recorded history stays intact.
        self._readonly_qns = self.db.readonly_qualified_names()

        # Qualified names a human wrote and locked: an agent step may read them for context but
        # must never overwrite or delete that record. An agent change to one is captured as a
        # pending proposal for the human to review instead of being forced in.
        # Reloaded per-step for the active lineage inside ``record_step``.
        self._human_locked_qns = self.db.human_locked_qualified_names("main")

        # ChromaDB is optional at runtime: if it (or its deps) is unavailable, we still record
        # steps, links, and snapshots - only semantic search is disabled.
        self.chroma = None
        self.embeddings_error: Optional[str] = None
        if enable_embeddings:
            try:
                from .store.chroma_store import ChromaStore

                self.chroma = ChromaStore(config.chroma_dir, config.embedding_model)
            except Exception as exc:  # pragma: no cover - depends on environment
                self.embeddings_error = f"{type(exc).__name__}: {exc}"

    def close(self) -> None:
        """Close the trace DB and optional Chroma store."""
        if self.codegraph is not None:
            self.codegraph.close()
        self.db.close()

    def __enter__(self) -> "Recorder":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    # --- recording loop ------------------------------------------------
    def record_step(self, step: Step) -> RecordResult:
        """Record one step and append it to the log of every node it changed."""
        from .lineage import LineageError, resolve_lineage

        # Stamp the development lineage. An explicit non-main ``step.lineage_id`` (tests /
        # ``record --lineage``) wins; otherwise resolve from the current git branch. Unregistered
        # feature branches refuse loudly so they never pollute main.
        if step.lineage_id and step.lineage_id != "main":
            lineage = self.db.get_lineage(step.lineage_id)
            if lineage is None:
                raise LineageError(
                    f"No lineage '{step.lineage_id}'. Create one with "
                    f"'codegraph-trace branch create {step.lineage_id} --from <seq>'."
                )
        else:
            lineage = resolve_lineage(self.db, self.config.repo_root)
        # A merged lineage's history is a permanent part of main's story — never writable.
        if not lineage.is_main and lineage.is_merged:
            raise LineageError(
                f"Lineage '{lineage.lineage_id}' was merged into main; its history is "
                f"permanent. Fork a new branch to continue: "
                f"'codegraph-trace branch create <name> --from <seq>'."
            )
        step.lineage_id = lineage.lineage_id
        self._active_lineage_id = lineage.lineage_id
        self._human_locked_qns = self.db.human_locked_qualified_names(lineage.lineage_id)

        if step.after_sha is None:
            step.after_sha = gitdiff.head_sha(self.config.repo_root)

        diff = gitdiff.diff_files(self.config.repo_root, step.before_sha, step.after_sha)
        # Never attribute the recording layer's own outputs as code changes. If the workspace
        # tracked these before an ignore rule existed, they otherwise show up in every diff.
        diff = {fp: fd for fp, fd in diff.items() if not is_trace_path(fp)}
        changed_files = sorted(diff.keys())

        kept: list[LinkedNode] = []
        edge_changes: dict[str, list[str]] = {"added": [], "removed": [], "changed": []}

        for fp, fd in diff.items():
            nodes = self._resolve(fp, fd.ranges, step.after_sha)
            for node in nodes:
                link = self._classify(node, fd.substantive, step.step_id, edge_changes)
                if link is not None:
                    kept.append(link)

            # Detect removed symbols: previously-recorded nodes in this file that no longer
            # exist in the post-step source (or, failing that, the code graph).
            for removed in self._detect_removed(fp, step.step_id, edge_changes, step.after_sha):
                kept.append(removed)

        # Never modify nodes owned by a read-only import: drop any such links so the imported
        # repo's recorded history is preserved untouched.
        if self._readonly_qns:
            kept = [ln for ln in kept if ln.node.qualified_name not in self._readonly_qns]

        is_human = (getattr(step, "author", "agent") or "agent") == "human"

        # Provenance lock: an agent step may read a human-locked node but must never overwrite or
        # delete it. Drop any link to such a node and capture the agent's attempted change as a
        # pending proposal the human can review (accept -> unlock, reject -> keep locked).
        proposed_nodes: list[str] = []
        if not is_human and self._human_locked_qns:
            allowed: list[LinkedNode] = []
            for ln in kept:
                if ln.node.qualified_name in self._human_locked_qns:
                    self.db.add_proposal(
                        step_id=step.step_id,
                        qualified_name=ln.node.qualified_name,
                        file_path=ln.node.file_path,
                        change_kind=ln.change_kind,
                        author=step.author,
                        prompt=step.prompt,
                        reasoning_text=step.reasoning_text,
                        after_sha=step.after_sha,
                        created_at=utcnow_iso(),
                    )
                    proposed_nodes.append(ln.node.qualified_name)
                else:
                    allowed.append(ln)
            kept = allowed

        snapshot = build_snapshot(
            step_id=step.step_id,
            after_sha=step.after_sha,
            before_sha=step.before_sha,
            links=kept,
            edge_changes=edge_changes,
            seq=self.db.peek_seq(step.step_id),
        )
        snapshot_path = None
        if step.after_sha:
            snapshot_path = str(self.snapshots.write(snapshot))

        author = step.author if is_human else "agent"
        self.db.upsert_step(step, changed_files, snapshot_path)
        self.db.replace_node_links(step.step_id, kept, author=author)
        self._persist_signatures(kept, step.step_id, author=author, locked=is_human)
        # Update the co-change matrix: every pair of symbols touched in this step is now a bit
        # more coupled. Idempotent on re-record (see TraceDB.bump_co_change).
        self.db.bump_co_change(
            [ln.node.qualified_name for ln in kept],
            step.step_id,
            self.db.peek_seq(step.step_id),
        )

        if self.chroma is not None and kept:
            # Embeddings are best-effort: a failure here must never lose the recorded step.
            try:
                self.chroma.add_step(step, kept)
            except Exception as exc:  # pragma: no cover - depends on environment
                self.embeddings_error = f"{type(exc).__name__}: {exc}"

        return RecordResult(
            step_id=step.step_id,
            changed_files=changed_files,
            linked_nodes=kept,
            snapshot_path=snapshot_path,
            skipped_reformat=(not kept and bool(changed_files) and not proposed_nodes),
            author=author,
            locked_nodes=[ln.node.qualified_name for ln in kept] if is_human else [],
            proposed_nodes=proposed_nodes,
        )

    # --- helpers -------------------------------------------------------
    def _resolve(
        self,
        file_path: str,
        ranges: list[tuple[int, int]],
        after_sha: Optional[str],
    ) -> list[NodeRef]:
        if self.codegraph is not None:
            # Prefer live-source (AST) resolution so brand-new symbols are attributed to their
            # own node instead of being folded into a stale neighbour or the file node. Falls
            # back to stale-graph overlap when the language is unsupported or the post-step
            # source cannot be read.
            language = language_for_path(file_path)
            if language is not None:
                source = gitdiff.file_at_sha(self.config.repo_root, after_sha, file_path)
                if source is not None:
                    return self.codegraph.resolve_nodes_via_source(
                        file_path, ranges, source, language
                    )
            return self.codegraph.resolve_nodes(file_path, ranges)
        # No code graph available: fall back to a stable file-level node.
        norm = normalize_path(file_path)
        return [
            NodeRef(
                node_id=None,
                label="File",
                qualified_name=f"file::{norm}",
                file_path=norm,
                start_line=0,
                end_line=0,
            )
        ]

    def _classify(
        self,
        node: NodeRef,
        substantive: bool,
        step_id: str,
        edge_changes: dict[str, list[str]],
    ) -> Optional[LinkedNode]:
        """Decide whether to link this node and how it changed.

        Returns None when the change is pure reformat noise (skip), otherwise a LinkedNode.
        """
        fingerprint = ""
        if self.codegraph is not None:
            fingerprint = self.codegraph.edge_fingerprint(node.node_id)

        prior = self.db.get_signature(
            node.qualified_name, lineage_id=getattr(self, "_active_lineage_id", "main")
        )

        if prior is None:
            # First time we have ever seen this node. Reformat-only first touches are still
            # noise and are skipped.
            if not substantive:
                return None
            if fingerprint:
                edge_changes["added"].append(node.qualified_name)
            return LinkedNode(node=node, change_kind="added", edge_fingerprint=fingerprint)

        sig_changed = (
            prior.get("label") != node.label
            or prior.get("start_line") != node.start_line
            or prior.get("end_line") != node.end_line
            or (prior.get("edge_fingerprint") or "") != fingerprint
        )

        # Link when the body actually changed (substantive diff) or the structural signature
        # changed. Pure reformat with no signature change is dropped.
        if not substantive and not sig_changed:
            return None

        if fingerprint and (prior.get("edge_fingerprint") or "") != fingerprint:
            edge_changes["changed"].append(node.qualified_name)

        return LinkedNode(node=node, change_kind="changed", edge_fingerprint=fingerprint)

    def _detect_removed(
        self,
        file_path: str,
        step_id: str,
        edge_changes: dict[str, list[str]],
        after_sha: Optional[str],
    ) -> list[LinkedNode]:
        """Previously-recorded symbols in ``file_path`` that no longer exist after this step.

        The post-step source is the authority: the code graph is stale by design (indexed
        before the step ran), so a brand-new symbol recorded via live AST is missing from the
        graph and would be falsely flagged as removed on the next step touching its file -
        while a genuinely deleted symbol is still *present* in the stale graph and would be
        missed. Parsing the source at ``after_sha`` gets both cases right. Signatures whose
        label the extractor cannot produce (File, Module, Route, ...) and files whose source is
        unavailable or unparseable fall back to the prior graph-presence check.
        """
        if self.codegraph is None:
            return []
        norm = normalize_path(file_path)

        live_qns: Optional[set[str]] = None
        language = language_for_path(file_path)
        if language is not None:
            source = gitdiff.file_at_sha(self.config.repo_root, after_sha, file_path)
            if source is not None:
                symbols = extract_symbols(source, language=language)
                # An empty result may mean a parse failure (mid-edit syntax error, missing
                # grammar), so only trust the live set when it actually found symbols.
                if symbols:
                    prefix = self.codegraph.module_prefix(file_path) or ""
                    live_qns = {
                        f"{prefix}.{s.dotted_suffix}" if prefix else s.dotted_suffix
                        for s in symbols
                    }

        graph_qns = {n.qualified_name for n in self.codegraph.nodes_in_file(file_path)}
        # When a session is re-recorded from the start, signatures written by LATER steps are
        # already in the DB; an early step must not compare them against its (older) source and
        # flag them removed. Only signatures last touched at or before this step count.
        cur_seq = self.db.peek_seq(step_id)
        removed: list[LinkedNode] = []
        for row in self._signatures_for_file(norm):
            qn = row["qualified_name"]
            if qn.startswith("file::"):
                continue
            last_seq = self._seq_of_step(row.get("last_step_id"))
            if last_seq is not None and last_seq > cur_seq:
                continue
            if live_qns is not None and (row.get("label") or "") in _LIVE_SYMBOL_LABELS:
                present = qn in live_qns
            else:
                present = qn in graph_qns
            if not present:
                node = NodeRef(
                    node_id=None,
                    label=row.get("label") or "",
                    qualified_name=qn,
                    file_path=norm,
                    start_line=row.get("start_line") or 0,
                    end_line=row.get("end_line") or 0,
                )
                edge_changes["removed"].append(qn)
                removed.append(LinkedNode(node=node, change_kind="removed"))
        return removed

    def _seq_of_step(self, step_id: Optional[str]) -> Optional[int]:
        """The recorded ``seq`` of a step, or None when the step (or its seq) is unknown."""
        if not step_id:
            return None
        row = self.db.conn.execute(
            "SELECT seq FROM steps WHERE step_id = ?", (step_id,)
        ).fetchone()
        return int(row["seq"]) if row and row["seq"] is not None else None

    def _signatures_for_file(self, file_path_norm: str) -> list[dict]:
        lid = getattr(self, "_active_lineage_id", "main") or "main"
        rows = self.db.conn.execute(
            "SELECT * FROM node_signatures WHERE file_path = ? AND lineage_id = ?",
            (file_path_norm, lid),
        ).fetchall()
        return [dict(r) for r in rows]

    def _persist_signatures(
        self,
        links: list[LinkedNode],
        step_id: str,
        author: str = "agent",
        locked: bool = False,
    ) -> None:
        lid = getattr(self, "_active_lineage_id", "main") or "main"
        for ln in links:
            if ln.change_kind == "removed":
                self.db.conn.execute(
                    "DELETE FROM node_signatures WHERE qualified_name = ? AND lineage_id = ?",
                    (ln.node.qualified_name, lid),
                )
                # A removed node is no longer locked; drop it from the in-memory lock set too.
                self._human_locked_qns.discard(ln.node.qualified_name)
                continue
            self.db.upsert_signature(
                qualified_name=ln.node.qualified_name,
                file_path=ln.node.file_path,
                label=ln.node.label,
                start_line=ln.node.start_line,
                end_line=ln.node.end_line,
                edge_fingerprint=ln.edge_fingerprint,
                step_id=step_id,
                author=author,
                locked=locked,
                lineage_id=lid,
            )
            # Keep the in-memory lock set current so a later step in the same session sees a
            # node a human just locked (separate CLI runs reload it at init).
            if locked and author == "human":
                self._human_locked_qns.add(ln.node.qualified_name)
        self.db.conn.commit()

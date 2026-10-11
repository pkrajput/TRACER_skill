"""Derive the decision ledger: the branches each step tried that did not make it.

The step history is a straight line (``steps.seq``), but development is not: the agent writes
something, it fails or gets replaced, and a different approach wins. Because the run driver
commits the workspace after every step, every abandoned attempt already exists as an
intermediate git commit - so we never ask a model "was this a decision?". We compare code
states with git:

    Anything a step ADDED that is NOT PRESENT in the session's final state was abandoned.

That is two git diffs and a set intersection - deterministic by construction. This module
reads only ``steps`` (+ ``node_links``) and git, and writes rows into the ``branches`` table.
Re-deriving is idempotent: the affected sessions' rows are deleted and re-inserted in a
deterministic order, so running derive twice yields a byte-identical table.

Row kinds:

- ``survived``:    everything the step added in that file/symbol is still there at the end.
- ``abandoned``:   nothing survived (or the symbol is gone at the end).
- ``revised``:     part of what the step added survived.
- ``error_retry``: the step's raw event trail shows an error observation followed by another
  action on the same file - a failed attempt, independent of the diff signal.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from . import gitdiff
from .ast_symbols import AstSymbol, extract_symbols, language_for_path, source_parses
from .config import TraceConfig
from .ignore import is_trace_path
from .store.trace_db import TraceDB

# OpenHands step ids look like ``oh-<conversation>-<event>``. The conversation id may itself
# contain hyphens, and in live V1 sessions the event id is a hyphenated UUID - so try the
# UUID shape first, then fall back to a hyphen-free event id (an integer or ``n<counter>``).
_OH_STEP_UUID_RE = re.compile(
    r"^oh-(?P<conv>.+)-(?P<event>[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)
_OH_STEP_RE = re.compile(r"^oh-(?P<conv>.+)-(?P<event>[^-]+)$")

_MANUAL_SESSION = "manual"

# Error markers scanned in observation text (deterministic, case-insensitive).
_ERROR_RE = re.compile(r"traceback|error|failed|non-zero exit", re.IGNORECASE)


def session_for_step_id(step_id: str) -> str:
    """The session a step belongs to: the conversation part of an OpenHands step id, or
    ``manual`` for steps recorded by hand with the ``record`` command."""
    for pattern in (_OH_STEP_UUID_RE, _OH_STEP_RE):
        m = pattern.match(step_id or "")
        if m:
            return m.group("conv")
    return _MANUAL_SESSION


@dataclass
class DeriveResult:
    """What one ``derive`` run produced."""

    sessions: dict[str, int] = field(default_factory=dict)  # session_id -> row count
    counts: dict[str, int] = field(default_factory=dict)    # kind -> row count
    decision_step_ids: list[str] = field(default_factory=list)

    @property
    def total_rows(self) -> int:
        """Total branch rows across all sessions."""
        return sum(self.sessions.values())

    def to_dict(self) -> dict[str, Any]:
        """Serialize derive counts and session totals for JSON output."""
        return {
            "sessions": self.sessions,
            "counts": self.counts,
            "total_rows": self.total_rows,
            "decision_step_ids": self.decision_step_ids,
        }


def derive_branches(config: TraceConfig, session: Optional[str] = None) -> DeriveResult:
    """Derive the branches table for every session (or one) recorded in the trace.

    Reads ``steps`` + ``node_links`` + git only; writes ``branches`` rows. Idempotent: the
    affected sessions' rows are replaced wholesale.

    Derivation is per development lineage: each lineage's sessions are evaluated against that
    lineage's own final SHA. Feature lineages never feed main's ledger and vice versa.
    """
    from .lineage import normalize_lineage_id

    db = TraceDB(config.trace_db_path)
    try:
        # All local steps (no visibility filter) so every lineage is derived.
        steps = db.list_steps()
        # Partition by (lineage_id, session_id).
        buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for s in steps:
            lid = normalize_lineage_id(s.get("lineage_id"))
            sid = session_for_step_id(s["step_id"])
            buckets.setdefault((lid, sid), []).append(s)
        if session is not None:
            buckets = {k: v for k, v in buckets.items() if k[1] == session}

        all_rows: list[dict[str, Any]] = []
        session_ids: set[str] = set()
        for (lid, sid) in sorted(buckets):
            session_ids.add(sid)
            rows = _derive_session(config, db, sid, buckets[(lid, sid)])
            for row in rows:
                row["lineage_id"] = lid
            all_rows.extend(rows)

        db.replace_branches_for_sessions(sorted(session_ids), all_rows)

        result = DeriveResult()
        for row in all_rows:
            result.sessions[row["session_id"]] = result.sessions.get(row["session_id"], 0) + 1
            result.counts[row["kind"]] = result.counts.get(row["kind"], 0) + 1
        for (_lid, sid) in buckets:
            result.sessions.setdefault(sid, 0)

        derived_step_ids = {s["step_id"] for ss in buckets.values() for s in ss}
        result.decision_step_ids = sorted(db.important_step_ids() & derived_step_ids)
        return result
    finally:
        db.close()


# --- per-session derivation --------------------------------------------------------------


def tree_parseable(repo: Any, sha: Optional[str]) -> bool:
    """True iff every Python source file in the tree at ``sha`` AST-parses.

    Non-Python source files are skipped: their tree-sitter parsers are
    error-tolerant, so parse failure cannot be detected reliably.
    """
    for fp in gitdiff.ls_files(repo, sha):
        if is_trace_path(fp) or language_for_path(fp) != "python":
            continue
        source = gitdiff.file_at_sha(repo, sha, fp)
        if source is not None and source_parses(source, language="python") is False:
            return False
    return True


def last_parseable_sha(repo: Any, steps: list[dict[str, Any]]) -> Optional[str]:
    """The most recent ``after_sha`` in ``steps`` whose tree fully AST-parses,
    or None when no commit parses."""
    seen: set[str] = set()
    for step in reversed(steps):
        sha = step.get("after_sha")
        if not sha or sha in seen:
            continue
        seen.add(sha)
        if tree_parseable(repo, sha):
            return sha
    return None


def _derive_session(
    config: TraceConfig,
    db: TraceDB,
    session_id: str,
    steps: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    # The final state is the end of the SAME session, not the end of the repo: "abandoned
    # within the run" is the decision signal; code removed months later is normal evolution.
    final_sha = steps[-1].get("after_sha")
    # Symbol-level verdicts compare against the LAST PARSEABLE commit: a syntax error in
    # the final commit would otherwise empty ``final_suffixes`` for the affected files and
    # retroactively mark every symbol abandoned (the metric-v2 poisoning artifact).
    # Line-level rows keep the true final state - a trailing syntax error does not delete
    # lines, so they are not poisoned.
    symbol_final_sha = final_sha
    if final_sha and not tree_parseable(config.repo_root, final_sha):
        symbol_final_sha = last_parseable_sha(config.repo_root, steps) or final_sha

    rows: list[dict[str, Any]] = []
    for step in steps:
        rows.extend(_diff_rows(config, db, session_id, step, final_sha, symbol_final_sha))
        rows.extend(_error_retry_rows(session_id, step))
    rows.extend(_cross_step_error_retries(session_id, steps))

    _pair_supersessions(rows)
    return rows


def _diff_rows(
    config: TraceConfig,
    db: TraceDB,
    session_id: str,
    step: dict[str, Any],
    final_sha: Optional[str],
    symbol_final_sha: Optional[str],
) -> list[dict[str, Any]]:
    """File-level and symbol-level survived/abandoned/revised rows for one step."""
    repo = config.repo_root
    before, after = step.get("before_sha"), step.get("after_sha")
    if not after:
        return []

    added_by_file = {
        fp: fd
        for fp, fd in gitdiff.diff_files(repo, before, after).items()
        if not is_trace_path(fp) and fd.added
    }
    if not added_by_file:
        return []

    # GONE: lines present right after this step but absent at the session's final state.
    gone_by_file = (
        {
            fp: fd
            for fp, fd in gitdiff.diff_files(repo, after, final_sha).items()
            if not is_trace_path(fp)
        }
        if final_sha and after != final_sha
        else {}
    )

    rows: list[dict[str, Any]] = []
    for fp in sorted(added_by_file):
        added_set = _normalize_lines(added_by_file[fp].added)
        if not added_set:
            continue
        gone_fd = gone_by_file.get(fp)
        gone_set = _normalize_lines(gone_fd.removed) if gone_fd else set()
        # Comparing normalized text as sets means line-number shifts from later edits do not
        # break the match.
        abandoned_lines = added_set & gone_set
        ratio = 1.0 - len(abandoned_lines) / len(added_set)
        if ratio >= 1.0:
            kind = "survived"
        elif ratio <= 0.0:
            kind = "abandoned"
        else:
            kind = "revised"
        rows.append(
            _row(
                session_id,
                step,
                file_path=fp,
                qualified_name="",
                kind=kind,
                survival_ratio=round(ratio, 6),
                abandoned_content=(
                    "\n".join(sorted(abandoned_lines)) if abandoned_lines else None
                ),
            )
        )
        rows.extend(
            _symbol_rows(config, db, session_id, step, fp, symbol_final_sha)
        )
    return rows


def _symbol_rows(
    config: TraceConfig,
    db: TraceDB,
    session_id: str,
    step: dict[str, Any],
    file_path: str,
    final_sha: Optional[str],
) -> list[dict[str, Any]]:
    """Symbol-level verdicts: a symbol this step ADDED that is absent at FINAL was abandoned.

    More robust than lines (renames/reindents inside a surviving symbol do not flag it), and it
    lines up with everything else we store: the symbols come straight from ``node_links``.
    """
    added_links = [
        nl
        for nl in db.links_for_step(step["step_id"])
        if nl.get("change_kind") == "added"
        and (nl.get("file_path") or "") == file_path
        and not (nl.get("qualified_name") or "").startswith("file::")
        and nl.get("qualified_name")
    ]
    if not added_links:
        return []

    language = language_for_path(file_path)
    if language is None:
        return []
    repo = config.repo_root
    source_after = gitdiff.file_at_sha(repo, step.get("after_sha"), file_path)
    if source_after is None:
        return []
    symbols_after = extract_symbols(source_after, language=language)
    if not symbols_after:  # parse failure: no reliable symbol verdict
        return []

    source_final = gitdiff.file_at_sha(repo, final_sha, file_path)
    symbols_final = (
        extract_symbols(source_final, language=language) if source_final else []
    )
    # The module prefix is constant per file, so comparing dotted suffixes is equivalent to
    # comparing full qualified names - and needs no code graph.
    final_suffixes = {s.dotted_suffix for s in symbols_final}

    rows: list[dict[str, Any]] = []
    after_lines = source_after.splitlines()
    for nl in sorted(added_links, key=lambda r: r["qualified_name"]):
        qn = nl["qualified_name"]
        sym = _match_symbol(symbols_after, qn)
        if sym is None:
            continue
        if sym.dotted_suffix in final_suffixes:
            rows.append(
                _row(
                    session_id, step, file_path=file_path, qualified_name=qn,
                    kind="survived", survival_ratio=1.0, abandoned_content=None,
                )
            )
        else:
            text = "\n".join(after_lines[sym.start_line - 1 : sym.end_line])
            rows.append(
                _row(
                    session_id, step, file_path=file_path, qualified_name=qn,
                    kind="abandoned", survival_ratio=0.0, abandoned_content=text,
                )
            )
    return rows


def _match_symbol(symbols: list[AstSymbol], qualified_name: str) -> Optional[AstSymbol]:
    """The extracted symbol whose dotted suffix matches a node link's qualified name.

    Full qualified names are ``<module_prefix>.<dotted_suffix>``; we match by suffix so no
    graph lookup is needed. The longest matching suffix wins (most specific).
    """
    best: Optional[AstSymbol] = None
    for sym in symbols:
        if qualified_name == sym.dotted_suffix or qualified_name.endswith(
            "." + sym.dotted_suffix
        ):
            if best is None or len(sym.dotted_suffix) > len(best.dotted_suffix):
                best = sym
    return best


# --- error retries (independent signal from the raw event trail) --------------------------


def _error_retry_rows(session_id: str, step: dict[str, Any]) -> list[dict[str, Any]]:
    """``error_retry`` rows from one step's own raw event trail.

    Pattern: an observation whose text contains error markers, followed later in the trail by
    an action referencing a file this step touched. One row per (step, file), in addition to
    the survived/abandoned rows.
    """
    events = _raw_events(step)
    if not events:
        return []
    changed = _changed_files(step)
    if not changed:
        return []

    error_seen = False
    retried: set[str] = set()
    for event in events:
        if _is_observation(event) and _ERROR_RE.search(_event_text(event)):
            error_seen = True
            continue
        if error_seen and _is_action(event):
            text = _event_text(event).replace("\\", "/")
            for fp in changed:
                if fp in text:
                    retried.add(fp)
    return [
        _row(
            session_id, step, file_path=fp, qualified_name="",
            kind="error_retry", survival_ratio=None, abandoned_content=None,
        )
        for fp in sorted(retried)
    ]


def _cross_step_error_retries(
    session_id: str, steps: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """``error_retry`` rows spanning a step boundary.

    In a live session each step ends with its trailing observation(s), so a failed attempt
    usually shows up as: step i's trail ends in an error observation, and step i+1 acts on the
    same file. The row lands on step i+1 - the retry is the decision.
    """
    rows: list[dict[str, Any]] = []
    for prev, nxt in zip(steps, steps[1:]):
        events = _raw_events(prev)
        if not events:
            continue
        # Only a TRAILING error counts: an error observation with no in-step action after it
        # (in-step retries are already reported by _error_retry_rows).
        trailing_error = False
        for event in events:
            if _is_observation(event) and _ERROR_RE.search(_event_text(event)):
                trailing_error = True
            elif trailing_error and _is_action(event):
                trailing_error = False
        if not trailing_error:
            continue
        shared = _changed_files(prev) & _changed_files(nxt)
        for fp in sorted(shared):
            rows.append(
                _row(
                    session_id, nxt, file_path=fp, qualified_name="",
                    kind="error_retry", survival_ratio=None, abandoned_content=None,
                )
            )
    return rows


def _raw_events(step: dict[str, Any]) -> list[dict[str, Any]]:
    raw = step.get("raw_event")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return []
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return [e for e in raw if isinstance(e, dict)]


def _changed_files(step: dict[str, Any]) -> set[str]:
    files = (step.get("changed_files") or "").split(",")
    return {
        f.replace("\\", "/").strip()
        for f in files
        if f.strip() and not is_trace_path(f)
    }


def _is_observation(event: dict[str, Any]) -> bool:
    kind = str(event.get("kind") or "")
    if "Observation" in kind:
        return True
    return "observation" in event  # V0 legacy shape


def _is_action(event: dict[str, Any]) -> bool:
    kind = str(event.get("kind") or "")
    if "Action" in kind:
        return True
    return bool(event.get("action"))  # V0 legacy shape


def _event_text(value: Any) -> str:
    """Every string VALUE in an event, recursively (keys are ignored so a bare ``"error"``
    key never trips the marker regex)."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return "\n".join(t for t in (_event_text(v) for v in value.values()) if t)
    if isinstance(value, (list, tuple)):
        return "\n".join(t for t in (_event_text(v) for v in value) if t)
    return ""


# --- shared helpers ------------------------------------------------------------------------


def _normalize_lines(lines: list[str]) -> set[str]:
    """Strip leading/trailing whitespace and drop blanks, as a set of line texts."""
    return {s for s in (ln.strip() for ln in lines) if s}


def _row(
    session_id: str,
    step: dict[str, Any],
    *,
    file_path: str,
    qualified_name: str,
    kind: str,
    survival_ratio: Optional[float],
    abandoned_content: Optional[str],
) -> dict[str, Any]:
    return {
        "session_id": session_id,
        "step_id": step["step_id"],
        "seq": step.get("seq"),
        "file_path": file_path,
        "qualified_name": qualified_name,
        "kind": kind,
        "survival_ratio": survival_ratio,
        "superseded_by_step_id": None,
        "abandoned_content": abandoned_content,
    }


def _pair_supersessions(rows: list[dict[str, Any]]) -> None:
    """Fill ``superseded_by_step_id``: the 'tried X, then did Y instead' edge.

    For every abandoned/revised row, the superseder is the earliest later step (by seq) in the
    same session with a ``survived`` row on the same (file, symbol) target - or, failing an
    exact target match, on the same file (the replacement usually has a different name).
    """
    survived_by_target: dict[tuple[str, str], list[tuple[int, str]]] = {}
    survived_by_file: dict[str, list[tuple[int, str]]] = {}
    for r in rows:
        if r["kind"] != "survived" or r.get("seq") is None:
            continue
        entry = (int(r["seq"]), r["step_id"])
        survived_by_target.setdefault((r["file_path"], r["qualified_name"]), []).append(entry)
        survived_by_file.setdefault(r["file_path"], []).append(entry)

    for r in rows:
        if r["kind"] not in ("abandoned", "revised") or r.get("seq") is None:
            continue
        seq = int(r["seq"])
        later = [
            e for e in survived_by_target.get((r["file_path"], r["qualified_name"]), [])
            if e[0] > seq
        ]
        if not later:
            later = [e for e in survived_by_file.get(r["file_path"], []) if e[0] > seq]
        if later:
            r["superseded_by_step_id"] = min(later)[1]

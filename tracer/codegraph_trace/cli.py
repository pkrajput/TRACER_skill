"""Command-line interface for the recording layer.

Commands:
  replay   Replay a recorded agent session log over a repo, recording each step.
  history  Open the reasoning log for a file path or a symbol's qualified name.
  search   Semantic search across recorded reasoning.
  record   Record a single step from explicit prompt/reasoning + SHAs.
  ensure-ignore  Add .codegraph-trace/ to .gitignore and untrack if needed.
  versions List the recorded version sequence (1, 2, 3, ...).
  goto     Restore the code to a recorded version's commit (non-destructive).
  import   Merge another repo's reasoning graph into this one (editable/read-only).
  locks    List locked human-written nodes (protected from agent overwrite).
  proposals List/accept/reject agent-suggested changes against locked human nodes.
  reconcile Backfill real node ids / canonical names after a codebase-memory-mcp re-index.
  branches  The decision ledger: derive/show the attempts each step made and their fate.
  branch   Development lineages: create/list git-like forks of the recorded trace.
  flag     Join Semgrep findings with the trace (who wrote it, why, one-shot heuristics).
  panel    Serve the one-page visual panel over trace.db for the editor plugin.
  overlay  Per-file symbol overlay (spans + last reasoning) for editor hover/gutter marks.
  symbol-at Resolve a file line to the innermost recorded symbol's qualified name.
  symbol-content A symbol's text at a recorded step, for the editor's per-symbol restore.
  resolve-graph-db  Print the verified code-map DB for --repo (or a clear setup error).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from . import gitdiff
from .adapters.openhands import OpenHandsAdapter
from .config import (
    TRACE_DIR_NAME,
    GraphDbSetupError,
    TraceConfig,
    discover_graph_db,
    graph_db_setup_message,
    resolve_graph_db,
)
from .gitdiff import GitError, list_commits
from .ignore import ensure_trace_ignored
from .models import Step, utcnow_iso
from .query import (
    TraceQuery,
    _truncate,
    format_history,
    format_recent_activity,
    format_versions,
)
from .recorder import Recorder, replay_over_commits
from .store.trace_db import TraceDB


def _config(args: argparse.Namespace) -> TraceConfig:
    graph_db = getattr(args, "graph_db", None)
    graph_db_path = Path(graph_db).expanduser() if graph_db else None
    repo_root = Path(args.repo)
    # If a graph DB was explicitly requested but is not there, say so: recording silently falls
    # back to file-level nodes (no per-symbol links), and `~` is expanded above in case that was
    # the problem.
    if graph_db_path is not None and not graph_db_path.is_file():
        print(
            f"[warn] code-graph DB not found at {graph_db_path}; symbol-level links are "
            f"unavailable (file-level nodes only).\n{graph_db_setup_message(repo_root)}",
            file=sys.stderr,
        )
        graph_db_path = None
    try:
        return TraceConfig(
            repo_root=repo_root,
            graph_db_path=graph_db_path,
            embedding_model=getattr(args, "embedding_model", None) or "all-MiniLM-L6-v2",
        )
    except GraphDbSetupError as exc:
        # Wrong-project map must never be used silently — abort with the setup message.
        print(str(exc), file=sys.stderr)
        raise SystemExit(2) from exc


def cmd_resolve_graph_db(args: argparse.Namespace) -> int:
    """Resolve (and verify) the code-map DB for the current repository."""
    import json as _json

    repo_root = Path(args.repo).resolve()
    explicit = Path(args.graph_db).expanduser() if getattr(args, "graph_db", None) else None
    try:
        path = resolve_graph_db(repo_root, explicit, require=True)
    except GraphDbSetupError as exc:
        if getattr(args, "json", False):
            print(
                _json.dumps(
                    {
                        "ok": False,
                        "repo": str(repo_root),
                        "graph_db": None,
                        "error": str(exc),
                    },
                    indent=2,
                )
            )
        else:
            print(str(exc), file=sys.stderr)
        return 2

    assert path is not None
    if getattr(args, "json", False):
        print(
            _json.dumps(
                {"ok": True, "repo": str(repo_root), "graph_db": str(path)},
                indent=2,
            )
        )
    else:
        print(path)
    return 0


def _embeddings_enabled(args: argparse.Namespace) -> bool:
    return not getattr(args, "no_embeddings", False)


def cmd_replay(args: argparse.Namespace) -> int:
    """Replay a recorded agent session over a repo, recording each step against its commit.

    The session log is parsed by an adapter into the harness-agnostic ``Step`` shape; the
    OpenHands adapter (V0 ``events.jsonl`` / V1 conversation dirs) is the one bundled today.
    Any harness that keeps the commit-per-step discipline can plug in with its own adapter -
    or skip adapters entirely and call ``record`` per step.
    """
    config = _config(args)
    adapter = OpenHandsAdapter(args.events)
    steps = list(adapter.steps())
    if not steps:
        print("No steps found in the event stream.", file=sys.stderr)
        return 1

    shas = list_commits(config.repo_root, max_count=len(steps))
    if not shas:
        print(
            "No commits found in the repo; cannot align steps to SHAs. Commit once per step.",
            file=sys.stderr,
        )
        return 1

    with Recorder(config, enable_embeddings=_embeddings_enabled(args)) as rec:
        if rec.embeddings_error:
            print(f"[warn] embeddings disabled: {rec.embeddings_error}", file=sys.stderr)
        results = replay_over_commits(rec, steps, shas)

    linked = sum(len(r.linked_nodes) for r in results)
    skipped = sum(1 for r in results if r.skipped_reformat)
    print(
        f"Recorded {len(results)} step(s); {linked} node link(s); "
        f"{skipped} reformat-only step(s) skipped."
    )
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    """Print the ordered reasoning log for a file path or symbol qualified name."""
    import json as _json

    config = _config(args)
    file_hint = getattr(args, "file", None)
    with TraceQuery(config, enable_embeddings=False) as q:
        if not args.target:
            # No target: repo-wide recent activity, so you can spot what just
            # changed (e.g. after a pull) without knowing which file to ask about.
            entries, total = q.recent_activity(limit=getattr(args, "limit", 10))
            if getattr(args, "json", False):
                print(_json.dumps([e.as_dict() for e in entries], indent=2))
            else:
                print(
                    format_recent_activity(
                        entries, total, color=sys.stdout.isatty()
                    )
                )
            return 0
        resolved = q.resolve_history(args.target, file_path=file_hint)
        if getattr(args, "json", False):
            out = resolved.as_dict()
            out["important_step_ids"] = sorted(q.db.important_step_ids())
            print(_json.dumps(out, indent=2))
        else:
            print(
                format_history(
                    resolved.entries,
                    resolved.target,
                    resolved.markers,
                    scope=resolved.scope,
                    file_path=resolved.file_path,
                    color=sys.stdout.isatty(),
                )
            )
    return 0


def cmd_search(args: argparse.Namespace) -> int:
    """Semantic search across recorded reasoning embeddings (requires ChromaDB)."""
    config = _config(args)
    with TraceQuery(config, enable_embeddings=True) as q:
        try:
            hits = q.semantic_search(args.query, k=args.k)
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        if not hits:
            print("No matches.")
            return 0
        for i, hit in enumerate(hits, 1):
            meta = hit.get("metadata", {})
            print(f"{i}. step {hit['step_id']}  dist={hit.get('distance')}")
            print(f"   files: {meta.get('file_paths', '')}")
            snippet = " ".join((hit.get("reasoning_text") or hit.get("document") or "").split())
            print(f"   {snippet[:240]}")
    return 0


def cmd_record(args: argparse.Namespace) -> int:
    """Record a single explicit step from prompt/reasoning and before/after SHAs."""
    from .lineage import LineageError

    config = _config(args)
    # Setup protection: ignore rules + untrack; recorder still filters even if tracked.
    ensure_trace_ignored(config.repo_root)
    author = "human" if args.author == "human" else "agent"
    lineage_id = getattr(args, "lineage", None) or "main"
    step = Step(
        step_id=args.step_id,
        prompt=args.prompt or "",
        reasoning_text=args.reasoning or "",
        before_sha=args.before,
        after_sha=args.after,
        author=author,
        lineage_id=lineage_id,
    )
    # Lock defaults: a human edit locks the nodes it touches unless --no-lock is given; an agent
    # edit never locks. argparse stores None when neither --lock nor --no-lock was passed.
    lock = (author == "human") if args.lock is None else bool(args.lock)

    try:
        with Recorder(config, enable_embeddings=_embeddings_enabled(args)) as rec:
            result = rec.record_step(step)
            if author == "human" and not lock and result.locked_nodes:
                # Human author tags provenance but the caller opted out of the lock.
                for qn in result.locked_nodes:
                    rec.db.unlock_node(qn, lineage_id=step.lineage_id or "main")
    except LineageError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    tag = "human-written" if author == "human" else "agent"
    print(
        f"Recorded {tag} step {result.step_id}: {len(result.linked_nodes)} node link(s) "
        f"across {len(result.changed_files)} changed file(s) "
        f"[lineage={step.lineage_id}]."
    )
    if author == "human" and lock and result.locked_nodes:
        print(f"Locked {len(result.locked_nodes)} node(s) from agent overwrite.")
    if result.proposed_nodes:
        print(
            f"{len(result.proposed_nodes)} change(s) to locked human node(s) were not applied; "
            f"recorded as pending proposal(s). Review with 'codegraph-trace proposals'."
        )
    return 0


def cmd_branch_create(args: argparse.Namespace) -> int:
    """Create a development lineage forked from a recorded version (git-like)."""
    import json as _json

    from .lineage import LineageError, create_lineage

    config = _config(args)
    config.ensure_dirs()
    db = TraceDB(config.trace_db_path)
    try:
        info = create_lineage(
            db,
            name=args.name,
            from_seq=int(args.from_seq),
            repo_root=config.repo_root,
            parent_lineage=args.parent or "main",
            checkout=not args.no_checkout,
        )
    except LineageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()

    if args.json:
        print(_json.dumps(info.to_dict(), indent=2))
        return 0
    print(
        f"Created lineage '{info.lineage_id}' forked from version {info.base_seq} "
        f"({(info.base_commit or '')[:10]}) on git branch '{info.git_ref}'."
    )
    if not args.no_checkout:
        print(f"Checked out git branch '{info.git_ref}'. Recorded steps will belong to this lineage.")
    print(
        "Main cannot see this lineage until it is accepted with "
        f"'codegraph-trace branch merge {info.lineage_id}'."
    )
    return 0


def cmd_branch_list(args: argparse.Namespace) -> int:
    """List registered development lineages."""
    import json as _json

    from .lineage import list_lineages, resolve_lineage

    config = _config(args)
    db = TraceDB(config.trace_db_path)
    try:
        rows = list_lineages(db)
        active = resolve_lineage(db, config.repo_root, allow_unregistered=True)
    finally:
        db.close()

    if args.json:
        print(
            _json.dumps(
                {"active": active.lineage_id, "lineages": [r.to_dict() for r in rows]},
                indent=2,
            )
        )
        return 0
    if not rows:
        print("No lineages registered.")
        return 0
    print(f"Development lineages (active: {active.lineage_id}):")
    print("")
    for r in rows:
        mark = "*" if r.lineage_id == active.lineage_id else " "
        fork = (
            f"forked at seq={r.base_seq}"
            if r.base_seq is not None
            else "root"
        )
        print(
            f"  {mark} {r.lineage_id}  git={r.git_ref}  {fork}  status={r.status}"
        )
    return 0


def cmd_branch_merge(args: argparse.Namespace) -> int:
    """Fold an accepted feature lineage into main's trace (idempotent)."""
    import json as _json

    from .lineage import LineageError, merge_lineage

    config = _config(args)
    config.ensure_dirs()
    db = TraceDB(config.trace_db_path)
    try:
        result = merge_lineage(db, name=args.name)
    except LineageError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()

    if args.json:
        print(_json.dumps(result.to_dict(), indent=2))
        return 0

    info = result.lineage
    if result.already_merged:
        print(
            f"Lineage '{info.lineage_id}' is already merged "
            f"({info.merged_at or 'unknown time'}); nothing to do."
        )
        return 0
    print(
        f"Merged lineage '{info.lineage_id}' into main, anchored at version "
        f"{info.base_seq} ({(info.base_commit or '')[:10]})."
    )
    print(
        f"  {result.steps_folded} step(s), {result.decision_rows_folded} decision-ledger "
        f"row(s) and their node links are now part of main's story."
    )
    if result.signatures_folded:
        print(f"  {result.signatures_folded} node signature(s) folded into main's cache.")
    print(
        f"The lineage is closed to new recording. Merge the code too with: "
        f"git merge {info.git_ref}"
    )
    return 0


def cmd_ensure_ignore(args: argparse.Namespace) -> int:
    """Write .gitignore rules for recording-layer dirs and untrack them if needed."""
    config = _config(args)
    ensure_trace_ignored(config.repo_root)
    print(f"Ensured recording-layer outputs are ignored under {config.repo_root}")
    return 0


def cmd_locks(args: argparse.Namespace) -> int:
    """List human-written nodes locked against agent overwrite."""
    config = _config(args)
    with TraceQuery(config, enable_embeddings=False) as q:
        rows = q.db.locked_nodes()
    if not rows:
        print("No locked human-written nodes.")
        return 0
    print(f"Locked human-written nodes ({len(rows)}):")
    print("")
    for r in rows:
        label = r.get("label") or "?"
        print(f"  {r['qualified_name']}  [{label}]  {r.get('file_path') or ''}")
    print("")
    print("An agent may read these for context but cannot overwrite them; its edits become "
          "proposals (codegraph-trace proposals).")
    return 0


def cmd_proposals(args: argparse.Namespace) -> int:
    """List, accept, or reject agent proposals against locked human nodes."""
    config = _config(args)
    with TraceQuery(config, enable_embeddings=False) as q:
        if args.accept:
            return _resolve_proposal(q.db, args.accept, accept=True)
        if args.reject:
            return _resolve_proposal(q.db, args.reject, accept=False)

        rows = q.db.list_proposals(status=args.status)
        if not rows:
            scope = f" with status '{args.status}'" if args.status else ""
            print(f"No proposals{scope}.")
            return 0
        print(f"Proposals ({len(rows)}):")
        print("")
        for r in rows:
            print(f"  [{r['status']}] {r['proposal_id']}")
            print(f"    node: {r['qualified_name']}  ({r.get('change_kind') or '?'})")
            if r.get("prompt"):
                print(f"    prompt: {_truncate(r['prompt'], 120)}")
            if r.get("reasoning_text"):
                print(f"    reasoning: {_truncate(r['reasoning_text'], 200)}")
            print("")
        print("Accept (unlock so the agent change can be recorded): "
              "codegraph-trace proposals --accept <id>")
        print("Reject (keep the human node locked):               "
              "codegraph-trace proposals --reject <id>")
    return 0


def _resolve_proposal(db, proposal_id: str, *, accept: bool) -> int:
    proposal = db.get_proposal(proposal_id)
    if proposal is None:
        print(f"No proposal '{proposal_id}'. List them with 'codegraph-trace proposals'.",
              file=sys.stderr)
        return 1
    if accept:
        db.set_proposal_status(proposal_id, "accepted")
        unlocked = db.unlock_node(proposal["qualified_name"])
        print(f"Accepted proposal {proposal_id}.")
        if unlocked:
            print(
                f"Unlocked {proposal['qualified_name']}; re-record the agent step to apply its "
                f"change."
            )
        return 0
    db.set_proposal_status(proposal_id, "rejected")
    print(f"Rejected proposal {proposal_id}; {proposal['qualified_name']} stays locked "
          f"(the human record is kept).")
    return 0


def cmd_versions(args: argparse.Namespace) -> int:
    """List the recorded version sequence (one entry per step)."""
    config = _config(args)
    with TraceQuery(config, enable_embeddings=False) as q:
        lineage = q.active_lineage()
        print(
            format_versions(
                q.list_versions(),
                important_step_ids=q.db.important_step_ids(lineage=lineage),
            )
        )
    return 0


def cmd_branches_derive(args: argparse.Namespace) -> int:
    """Derive the decision ledger from steps and git diffs (deterministic, no LLM)."""
    import json as _json

    from .branches import derive_branches

    config = _config(args)
    result = derive_branches(config, session=args.session)

    if args.json:
        print(_json.dumps(result.to_dict(), indent=2))
        return 0

    if not result.sessions:
        scope = f" '{args.session}'" if args.session else ""
        print(f"No recorded session{scope} to derive branches from.")
        return 0

    print(
        f"Derived {result.total_rows} branch row(s) across "
        f"{len(result.sessions)} session(s):"
    )
    for sid in sorted(result.sessions):
        print(f"  {sid}: {result.sessions[sid]} row(s)")
    if result.counts:
        counts = ", ".join(f"{k}={result.counts[k]}" for k in sorted(result.counts))
        print(f"Kinds: {counts}")
    if result.decision_step_ids:
        print(f"Decision point(s): {len(result.decision_step_ids)} step(s): "
              + ", ".join(result.decision_step_ids))
    else:
        print("Decision point(s): none (every step was plain forward motion).")
    print("Inspect with: codegraph-trace branches show [file-or-symbol]")
    return 0


def cmd_branches_show(args: argparse.Namespace) -> int:
    """Print the decision ledger, optionally filtered to a file or symbol."""
    import json as _json

    from .codegraph import normalize_path

    config = _config(args)
    target = normalize_path(args.target) if args.target else None
    with TraceQuery(config, enable_embeddings=False) as q:
        lineage = q.active_lineage()
        rows = q.db.list_branches(target=target, lineage=lineage)
        important = q.db.important_step_ids(lineage=lineage)

    if args.json:
        out = [dict(r, important=(r["step_id"] in important)) for r in rows]
        print(_json.dumps(out, indent=2))
        return 0

    if not rows:
        scope = f" for '{args.target}'" if args.target else ""
        print(f"No branch rows{scope}. Run 'codegraph-trace branches derive' first.")
        return 0

    scope = f" for '{args.target}'" if args.target else ""
    print(f"Decision ledger{scope} ({len(rows)} row(s)):")
    print("")
    for r in rows:
        step_no = f"step#{r['seq']}" if r.get("seq") is not None else r["step_id"]
        node = r["qualified_name"] or "(file-level)"
        tag = " [decision]" if r["step_id"] in important else ""
        print(f"{step_no}  {r['step_id']}  {r['file_path']} :: {node}{tag}")

        verdict = f"  attempt -> {r['kind']}"
        if r.get("superseded_by_seq") is not None:
            verdict += (
                f" -> replaced by step {int(r['superseded_by_seq'])} "
                f"({r['superseded_by_step_id']})"
            )
        elif r.get("superseded_by_step_id"):
            verdict += f" -> replaced by {r['superseded_by_step_id']}"
        if r.get("survival_ratio") is not None:
            verdict += f"  (survival {float(r['survival_ratio']):.2f})"
        print(verdict)

        if r.get("prompt"):
            print(f"  prompt: {_truncate(r['prompt'], 120)}")
        if r.get("reasoning_text"):
            print(f"  reasoning: {_truncate(r['reasoning_text'], 200)}")
        if r.get("abandoned_content"):
            print("  abandoned code:")
            for ln in r["abandoned_content"].splitlines():
                print(f"    {ln}")
        print("")
    return 0


def cmd_review(args: argparse.Namespace) -> int:
    """Assemble the review surface for a branch: diff + reasoning log + decision ledger."""
    import json as _json

    from .lineage import LineageError, UnregisteredLineageError
    from .review import build_review, format_review

    config = _config(args)
    try:
        bundle = build_review(config, lineage_name=args.lineage)
    except (LineageError, UnregisteredLineageError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.json:
        print(_json.dumps(bundle.to_dict(), indent=2))
        return 0
    print(format_review(bundle))
    return 0


def cmd_flag(args: argparse.Namespace) -> int:
    """Join Semgrep findings with the trace (author, reasoning, branch heuristics)."""
    import json as _json

    from .flag import flag_findings, format_report

    config = _config(args)
    findings_path = Path(args.findings).expanduser()
    if not findings_path.is_file():
        print(
            f"Findings file not found: {findings_path}. Produce one with: "
            f"semgrep scan --config p/security-audit --json --output findings.json <repo>",
            file=sys.stderr,
        )
        return 1
    try:
        report = flag_findings(config, findings_path)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if getattr(args, "save", False):
        # Persist for the visual panel's has-finding filter (/api/findings reads this).
        config.trace_dir.mkdir(parents=True, exist_ok=True)
        save_path = config.trace_dir / "findings-report.json"
        save_path.write_text(
            _json.dumps(report.to_dict(), indent=2), encoding="utf-8"
        )
        print(f"[flag] report saved to {save_path}", file=sys.stderr)

    if args.json:
        print(_json.dumps(report.to_dict(), indent=2))
        return 0
    print(format_report(report))
    return 0


def cmd_panel(args: argparse.Namespace) -> int:
    """Serve the local visual panel HTTP app over the recorded trace."""
    from .panel import run_panel

    config = _config(args)
    return run_panel(config, host=args.host, port=args.port)


def cmd_overlay(args: argparse.Namespace) -> int:
    """Per-file editor overlay: each recorded symbol's span, provenance, and last reasoning.

    Built for the editor plugin's hover/gutter marks: one CLI call per open file returns
    everything the editor needs, so it never reads trace.db itself.
    """
    import json as _json

    from .codegraph import normalize_path
    from .lineage import resolve_lineage

    config = _config(args)
    norm = normalize_path(args.file)
    db = TraceDB(config.trace_db_path)
    try:
        lineage = resolve_lineage(db, config.repo_root, allow_unregistered=True)
        vis_sql, vis_params = db._visible_clause(lineage, alias="s")
        rows = db.conn.execute(
            f"""
            SELECT nl.qualified_name, nl.author AS author,
                   s.seq AS last_seq, s.step_id AS last_step_id,
                   s.prompt AS last_prompt, s.reasoning_text AS last_reasoning
            FROM node_links nl
            JOIN steps s ON s.step_id = nl.step_id
            WHERE nl.file_path = ? AND {vis_sql}
            ORDER BY s.seq
            """,
            (norm, *vis_params),
        ).fetchall()
        last_by_qn: dict[str, dict] = {}
        for r in rows:
            last_by_qn[r["qualified_name"]] = dict(r)

        symbols = []
        for qn, last in sorted(last_by_qn.items()):
            if not qn or qn.startswith("file::"):
                continue
            sig = db.conn.execute(
                "SELECT label, start_line, end_line, locked FROM node_signatures "
                "WHERE qualified_name = ? AND lineage_id = ?",
                (qn, lineage.lineage_id),
            ).fetchone()
            if sig is None or not sig["start_line"] or sig["start_line"] <= 0:
                continue
            symbols.append(
                {
                    "qualified_name": qn,
                    "label": sig["label"],
                    "start_line": int(sig["start_line"]),
                    "end_line": int(sig["end_line"] or sig["start_line"]),
                    "author": last.get("author"),
                    "locked": bool(sig["locked"]),
                    "last_seq": last.get("last_seq"),
                    "last_step_id": last.get("last_step_id"),
                    "last_prompt": last.get("last_prompt") or "",
                    "last_reasoning": last.get("last_reasoning") or "",
                }
            )
    finally:
        db.close()

    out = {"file": norm, "symbols": symbols}
    if getattr(args, "json", False):
        print(_json.dumps(out, indent=2))
        return 0
    if not symbols:
        print(f"No recorded symbols for '{norm}'.")
        return 0
    print(f"Recorded symbols in '{norm}' ({len(symbols)}):")
    for s in symbols:
        lock = " [locked]" if s["locked"] else ""
        print(
            f"  {s['qualified_name']}  L{s['start_line']}-{s['end_line']}  "
            f"author={s['author'] or '?'}{lock}  last step#{s['last_seq']}"
        )
        if s["last_reasoning"]:
            print(f"    {_truncate(s['last_reasoning'], 160)}")
    return 0


def cmd_symbol_at(args: argparse.Namespace) -> int:
    """Resolve ``<file> --line N`` to the innermost recorded symbol (for editor hover)."""
    import json as _json

    from .codegraph import CodeGraph, normalize_path

    config = _config(args)
    norm = normalize_path(args.file)
    line = int(args.line)

    result: Optional[dict] = None
    # Prefer the code graph's spans (authoritative when the index is fresh).
    if config.graph_db_path and Path(config.graph_db_path).is_file():
        try:
            graph = CodeGraph(config.graph_db_path)
            nodes = [
                n
                for n in graph.resolve_nodes(norm, [(line, line)])
                if n.label != "File" and not n.qualified_name.startswith("file::")
                and n.end_line >= n.start_line > 0
            ]
            if nodes:
                n = min(nodes, key=lambda n: n.end_line - n.start_line)
                result = {
                    "qualified_name": n.qualified_name,
                    "label": n.label,
                    "start_line": n.start_line,
                    "end_line": n.end_line,
                    "source": "graph",
                }
        except FileNotFoundError:
            pass
    if result is None:
        # Fall back to recorded signature spans (works with no code graph at all).
        db = TraceDB(config.trace_db_path)
        try:
            row = db.conn.execute(
                """
                SELECT qualified_name, label, start_line, end_line
                FROM node_signatures
                WHERE file_path = ? AND start_line > 0
                  AND start_line <= ? AND end_line >= ?
                ORDER BY (end_line - start_line) ASC
                LIMIT 1
                """,
                (norm, line, line),
            ).fetchone()
        finally:
            db.close()
        if row is not None:
            result = {
                "qualified_name": row["qualified_name"],
                "label": row["label"],
                "start_line": int(row["start_line"]),
                "end_line": int(row["end_line"]),
                "source": "signatures",
            }

    out = {"file": norm, "line": line}
    out.update(result or {"qualified_name": None})
    if getattr(args, "json", False):
        print(_json.dumps(out, indent=2))
        return 0
    if result is None:
        print(f"No recorded symbol at {norm}:{line}.")
        return 0
    print(
        f"{result['qualified_name']}  ({result['label']}, "
        f"L{result['start_line']}-{result['end_line']})"
    )
    return 0


def cmd_symbol_content(args: argparse.Namespace) -> int:
    """A single symbol's text at a recorded point in time, plus its current span.

    Powers the editor's per-symbol restore: the extension replaces just the symbol's
    current span with the historical text via a WorkspaceEdit (undoable), instead of
    checking out a whole version.
    """
    import json as _json

    from .ast_symbols import extract_symbols, language_for_path
    from .branches import _match_symbol
    from .codegraph import normalize_path

    config = _config(args)
    norm = normalize_path(args.file)
    qn = args.qualified_name
    language = language_for_path(norm)

    if (args.at_seq is None) == (args.branch_id is None):
        print("Pass exactly one of --at-seq <N> or --branch-id <B>.", file=sys.stderr)
        return 1

    historical: Optional[dict] = None
    if args.branch_id is not None:
        db = TraceDB(config.trace_db_path)
        try:
            row = db.conn.execute(
                "SELECT * FROM branches WHERE branch_id = ?", (args.branch_id,)
            ).fetchone()
        finally:
            db.close()
        if row is None:
            print(f"No branch row with branch_id={args.branch_id}.", file=sys.stderr)
            return 1
        historical = {
            "content": row["abandoned_content"],
            "source_seq": row["seq"],
            "source": "branch",
            "kind": row["kind"],
        }
    else:
        with TraceQuery(config, enable_embeddings=False) as q:
            version = q.get_version(args.at_seq)
        if version is None or not version.after_sha:
            print(f"No recorded version {args.at_seq} with a commit.", file=sys.stderr)
            return 1
        source = gitdiff.file_at_sha(config.repo_root, version.after_sha, norm)
        content = None
        if source is not None and language:
            sym = _match_symbol(extract_symbols(source, language=language), qn)
            if sym is not None:
                lines = source.splitlines()
                content = "\n".join(lines[sym.start_line - 1 : sym.end_line])
        historical = {
            "content": content,
            "source_seq": args.at_seq,
            "source": "git",
        }

    # Where the symbol lives in the working tree right now (spans in the trace DB or the
    # code graph can be stale; the live parse is authoritative for an editor edit).
    current: dict = {"exists": False}
    live_path = config.repo_root / norm
    if live_path.is_file() and language:
        try:
            live_source = live_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            live_source = None
        if live_source is not None:
            sym = _match_symbol(extract_symbols(live_source, language=language), qn)
            if sym is not None:
                current = {
                    "exists": True,
                    "start_line": sym.start_line,
                    "end_line": sym.end_line,
                }

    out = {
        "file": norm,
        "qualified_name": qn,
        "historical": historical,
        "current": current,
    }
    if getattr(args, "json", False):
        print(_json.dumps(out, indent=2))
        return 0
    if not historical or historical.get("content") is None:
        print(f"No recorded content for '{qn}' at that point.")
        return 0
    span = (
        f"currently at L{current['start_line']}-{current['end_line']}"
        if current.get("exists")
        else "not present in the working tree"
    )
    print(f"{qn} ({span}); content as of step {historical.get('source_seq')}:")
    print(historical["content"])
    return 0


def cmd_goto(args: argparse.Namespace) -> int:
    """Check out a recorded version's commit without rewriting history or the trace."""
    config = _config(args)
    with TraceQuery(config, enable_embeddings=False) as q:
        version = q.get_version(args.version)
    if version is None:
        print(
            f"No version {args.version}. Run 'codegraph-trace versions' to list them.",
            file=sys.stderr,
        )
        return 1
    if not version.after_sha:
        print(
            f"Version {args.version} has no recorded commit (after_sha); cannot go back to it.",
            file=sys.stderr,
        )
        return 1

    repo = config.repo_root
    if not args.force and not gitdiff.working_tree_clean(repo):
        print(
            "Working tree has uncommitted changes to tracked files. Commit or stash them "
            "first, or pass --force to attempt the checkout anyway.",
            file=sys.stderr,
        )
        return 1

    from .config import TRACE_DIR_NAME

    if gitdiff.is_path_tracked(repo, TRACE_DIR_NAME):
        print(
            f"[warn] {TRACE_DIR_NAME}/ is tracked by git; going back may move the recorded "
            f"trace too. Add it to .gitignore to keep the trace stable across versions.",
            file=sys.stderr,
        )

    prior = gitdiff.current_ref(repo)
    try:
        gitdiff.checkout(repo, version.after_sha, new_branch=args.branch)
    except GitError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    sha = version.after_sha[:10]
    if args.branch:
        print(f"Checked out version {version.seq} ({sha}) on new branch '{args.branch}'.")
    else:
        print(f"Checked out version {version.seq} ({sha}) in detached HEAD.")
    if prior:
        print(f"Return with: git checkout {prior}")
    print("Re-index with codebase-memory-mcp to refresh the code graph for this version.")
    return 0


def cmd_import(args: argparse.Namespace) -> int:
    """Merge another repo's reasoning graph into this one (read-only or editable)."""
    our_repo = Path(args.repo).resolve()
    other_repo = Path(args.other_repo).expanduser().resolve()
    if not other_repo.is_dir():
        print(f"Other repo not found: {other_repo}", file=sys.stderr)
        return 1

    other_trace_db = other_repo / TRACE_DIR_NAME / "trace.db"
    other_graph_db = (
        Path(args.other_graph_db).expanduser()
        if args.other_graph_db
        else discover_graph_db(other_repo)
    )
    name = args.name or other_repo.name
    mode = "read_only" if args.mode in ("read-only", "read_only") else "editable"

    config = TraceConfig(repo_root=our_repo)
    config.ensure_dirs()

    if not other_trace_db.is_file():
        print(
            f"[warn] no recorded trace at {other_trace_db}; registering the code graph only "
            f"(no reasoning history to merge).",
            file=sys.stderr,
        )

    db = TraceDB(config.trace_db_path)
    try:
        counts = db.import_repo(
            name=name,
            repo_root=str(other_repo),
            other_trace_db_path=str(other_trace_db),
            graph_db_path=str(other_graph_db) if other_graph_db else None,
            mode=mode,
            imported_at=utcnow_iso(),
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()

    print(
        f"Imported '{name}' ({mode}) from {other_repo}: "
        f"{counts['steps']} step(s), {counts['node_links']} node link(s), "
        f"{counts['co_change']} co-change pair(s)."
    )
    if other_graph_db:
        print(f"Registered code graph: {other_graph_db}")
    return 0


def cmd_reconcile(args: argparse.Namespace) -> int:
    """Backfill node ids and canonical names after a codebase-memory-mcp re-index."""
    import json as _json

    from .reconcile import StaleGraphError, reconcile

    config = _config(args)
    try:
        result = reconcile(
            config,
            dry_run=args.dry_run,
            force=args.force,
            enable_embeddings=_embeddings_enabled(args) and not args.dry_run,
        )
    except (FileNotFoundError, StaleGraphError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    if args.json:
        print(_json.dumps(result.to_dict(), indent=2))
        return 0

    prefix = "[dry-run] would " if result.dry_run else ""
    if not (result.backfilled or result.renamed or result.unresolved):
        print("Nothing to reconcile: every node link already has a graph node id.")
        return 0

    if result.backfilled:
        print(f"{prefix}backfill {len(result.backfilled)} node id(s):")
        for o in result.backfilled:
            print(f"  {o.qualified_name}  ->  node_id={o.node_id}")
    if result.renamed:
        print(f"{prefix}rename {len(result.renamed)} symbol(s) to the graph's canonical name:")
        for o in result.renamed:
            print(f"  {o.qualified_name}  ->  {o.new_qualified_name}  (node_id={o.node_id})")
    if result.unresolved:
        print(f"{len(result.unresolved)} symbol(s) left unresolved:")
        for o in result.unresolved:
            print(f"  {o.qualified_name}  ({o.reason})")
        print(
            "Re-index with codebase-memory-mcp "
            f'(index_repository(repo_path="{config.repo_root}", mode="fast")) and re-run '
            "reconcile if these symbols should exist in the graph."
        )
    if not result.dry_run:
        print(f"Updated {result.steps_updated} step(s).")
        if result.chroma_error:
            print(f"[warn] chroma metadata not updated: {result.chroma_error}", file=sys.stderr)
        elif result.chroma_updated:
            print(f"Refreshed embedding metadata for {result.chroma_updated} step(s).")
    return 0


_CODE_SUFFIXES = (
    ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".kt", ".c", ".cc",
    ".cpp", ".h", ".hpp", ".cs", ".rb", ".php", ".swift", ".scala", ".sql", ".sh",
)


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for every codegraph-trace subcommand."""
    parser = argparse.ArgumentParser(prog="codegraph-trace", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--repo", default=".", help="Repository root being recorded.")
        p.add_argument("--graph-db", default=None, help="Path to the code-graph SQLite DB.")
        p.add_argument(
            "--embedding-model", default=None, help="Embedding model name (or 'hash')."
        )
        p.add_argument(
            "--no-embeddings", action="store_true", help="Disable ChromaDB embeddings."
        )

    p_replay = sub.add_parser(
        "replay", help="Replay a recorded agent session log over a repo."
    )
    p_replay.add_argument(
        "events",
        help="Path to the session log (OpenHands events.jsonl or a V1 conversation dir; "
        "other harnesses plug in via their own adapter or per-step `record` calls).",
    )
    add_common(p_replay)
    p_replay.set_defaults(func=cmd_replay)

    p_hist = sub.add_parser("history", help="Open the reasoning log for a file or symbol.")
    p_hist.add_argument(
        "target",
        nargs="?",
        default=None,
        help="File path or symbol qualified_name. Omit for a repo-wide recent-activity view.",
    )
    p_hist.add_argument(
        "--file",
        default=None,
        help="Optional file path hint when target is a symbol (enables file-history fallback).",
    )
    p_hist.add_argument(
        "--limit",
        type=int,
        default=10,
        help="How many steps the no-target recent-activity view shows (default 10).",
    )
    p_hist.add_argument("--json", action="store_true", help="Emit the log as JSON.")
    add_common(p_hist)
    p_hist.set_defaults(func=cmd_history)

    p_search = sub.add_parser("search", help="Semantic search across reasoning.")
    p_search.add_argument("query", help="Free-text query.")
    p_search.add_argument("-k", type=int, default=5, help="Number of results.")
    add_common(p_search)
    p_search.set_defaults(func=cmd_search)

    p_rec = sub.add_parser("record", help="Record a single explicit step.")
    p_rec.add_argument("step_id")
    p_rec.add_argument("--prompt", default="")
    p_rec.add_argument("--reasoning", default="")
    p_rec.add_argument("--before", default=None, help="before_sha")
    p_rec.add_argument("--after", default=None, help="after_sha (defaults to HEAD)")
    p_rec.add_argument(
        "--author",
        choices=["agent", "human"],
        default="agent",
        help="Who made the edit. 'human' tags it human-written and locks the touched nodes from "
        "agent overwrite (default: agent).",
    )
    p_rec.add_argument(
        "--lock",
        dest="lock",
        action="store_true",
        default=None,
        help="Force-lock the touched nodes (default: on for --author human).",
    )
    p_rec.add_argument(
        "--no-lock",
        dest="lock",
        action="store_false",
        help="Tag a human edit's provenance without locking the nodes.",
    )
    p_rec.add_argument(
        "--lineage",
        default=None,
        help="Stamp this development lineage (default: resolve from current git branch). "
        "Use a registered non-main id to override HEAD for tests.",
    )
    add_common(p_rec)
    p_rec.set_defaults(func=cmd_record)

    p_ensure = sub.add_parser(
        "ensure-ignore",
        help="Add the recording layer's output dirs to .gitignore; untrack if already tracked.",
    )
    add_common(p_ensure)
    p_ensure.set_defaults(func=cmd_ensure_ignore)

    p_ver = sub.add_parser("versions", help="List the recorded version sequence (1, 2, 3, ...).")
    add_common(p_ver)
    p_ver.set_defaults(func=cmd_versions)

    p_import = sub.add_parser(
        "import", help="Merge another repo's reasoning graph into this one (editable/read-only)."
    )
    p_import.add_argument("other_repo", help="Path to the other repo to import.")
    p_import.add_argument("--repo", default=".", help="This repo (the import target).")
    p_import.add_argument(
        "--mode",
        choices=["read-only", "editable"],
        default="read-only",
        help="read-only: context only, never modified (default). editable: may be refreshed.",
    )
    p_import.add_argument("--name", default=None, help="Name for the import (defaults to dir name).")
    p_import.add_argument(
        "--other-graph-db", default=None, help="The OTHER repo's code-graph SQLite DB."
    )
    p_import.set_defaults(func=cmd_import)

    p_locks = sub.add_parser(
        "locks", help="List locked human-written nodes (protected from agent overwrite)."
    )
    add_common(p_locks)
    p_locks.set_defaults(func=cmd_locks)

    p_prop = sub.add_parser(
        "proposals",
        help="List/accept/reject agent-suggested changes against locked human nodes.",
    )
    p_prop.add_argument(
        "--status",
        choices=["pending", "accepted", "rejected"],
        default=None,
        help="Filter the listing by status.",
    )
    p_prop.add_argument(
        "--accept", default=None, metavar="ID",
        help="Accept a proposal: unlock its node so the agent change can be re-recorded.",
    )
    p_prop.add_argument(
        "--reject", default=None, metavar="ID",
        help="Reject a proposal: keep the human node locked (the original is preserved).",
    )
    add_common(p_prop)
    p_prop.set_defaults(func=cmd_proposals)

    p_reconcile = sub.add_parser(
        "reconcile",
        help="After a codebase-memory-mcp re-index, backfill real node ids and adopt the "
        "graph's canonical qualified names for symbols created mid-session.",
    )
    p_reconcile.add_argument(
        "--dry-run", action="store_true", help="Report the plan without writing anything."
    )
    p_reconcile.add_argument(
        "--force",
        action="store_true",
        help="Proceed even if the graph appears older than the last recorded step.",
    )
    p_reconcile.add_argument(
        "--json", action="store_true", help="Emit the result as JSON."
    )
    add_common(p_reconcile)
    p_reconcile.set_defaults(func=cmd_reconcile)

    p_branch = sub.add_parser(
        "branch",
        help="Development lineages: create/list git-like forks of the recorded trace "
        "(distinct from 'branches', the decision ledger).",
    )
    branch_sub = p_branch.add_subparsers(dest="branch_command", required=True)

    p_bcreate = branch_sub.add_parser(
        "create",
        help="Fork a new lineage from a recorded version and create a matching git branch.",
    )
    p_bcreate.add_argument("name", help="Lineage id and git branch name.")
    p_bcreate.add_argument(
        "--from",
        dest="from_seq",
        type=int,
        required=True,
        help="Version number (steps.seq) to fork from.",
    )
    p_bcreate.add_argument(
        "--parent",
        default="main",
        help="Parent lineage to fork from (default: main).",
    )
    p_bcreate.add_argument(
        "--no-checkout",
        action="store_true",
        help="Register the lineage without running git checkout -b.",
    )
    p_bcreate.add_argument("--json", action="store_true", help="Emit the lineage as JSON.")
    add_common(p_bcreate)
    p_bcreate.set_defaults(func=cmd_branch_create)

    p_blist = branch_sub.add_parser("list", help="List registered development lineages.")
    p_blist.add_argument("--json", action="store_true", help="Emit lineages as JSON.")
    add_common(p_blist)
    p_blist.set_defaults(func=cmd_branch_list)

    p_bmerge = branch_sub.add_parser(
        "merge",
        help="Accept a feature lineage: fold its steps, node links and decision rows into "
        "main's trace, anchored at the fork point. Idempotent.",
    )
    p_bmerge.add_argument("name", help="Lineage id to merge into main.")
    p_bmerge.add_argument("--json", action="store_true", help="Emit the result as JSON.")
    add_common(p_bmerge)
    p_bmerge.set_defaults(func=cmd_branch_merge)

    p_branches = sub.add_parser(
        "branches",
        help="The decision ledger: derive/show the attempts each step made and their fate "
        "(survived / abandoned / revised / error retry).",
    )
    br_sub = p_branches.add_subparsers(dest="branches_command", required=True)

    p_bderive = br_sub.add_parser(
        "derive",
        help="Deterministically derive branch rows from steps + git (no LLM). Idempotent.",
    )
    p_bderive.add_argument(
        "--session", default=None,
        help="Only derive this session (a recorded conversation id, or 'manual').",
    )
    p_bderive.add_argument("--json", action="store_true", help="Emit the result as JSON.")
    add_common(p_bderive)
    p_bderive.set_defaults(func=cmd_branches_derive)

    p_bshow = br_sub.add_parser(
        "show", help="Print the decision ledger, joined with each step's reasoning."
    )
    p_bshow.add_argument(
        "target", nargs="?", default=None,
        help="Optional file path or symbol qualified_name to filter by.",
    )
    p_bshow.add_argument("--json", action="store_true", help="Emit the rows as JSON.")
    add_common(p_bshow)
    p_bshow.set_defaults(func=cmd_branches_show)

    p_review = sub.add_parser(
        "review",
        help="Assemble everything a reviewer needs for a branch's pull request: the code "
        "diff, the branch's reasoning log, and its decision ledger (text or --json).",
    )
    p_review.add_argument(
        "lineage",
        nargs="?",
        default=None,
        help="Lineage id to review (default: the current git branch's lineage).",
    )
    p_review.add_argument(
        "--json", action="store_true",
        help="Emit the bundle as JSON (for an agent reviewer).",
    )
    add_common(p_review)
    p_review.set_defaults(func=cmd_review)

    p_flag = sub.add_parser(
        "flag",
        help="Join Semgrep findings with the recorded trace: symbol, author, lock state, "
        "touch count, reasoning, branches, plus two labelled heuristics.",
    )
    p_flag.add_argument(
        "--findings", required=True,
        help="Path to Semgrep's JSON output (semgrep scan --json --output findings.json).",
    )
    p_flag.add_argument("--json", action="store_true", help="Emit the report as JSON.")
    p_flag.add_argument(
        "--save",
        action="store_true",
        help="Also write the report to .codegraph-trace/findings-report.json for the panel.",
    )
    add_common(p_flag)
    p_flag.set_defaults(func=cmd_flag)

    p_panel = sub.add_parser(
        "panel", help="Serve the one-page visual panel over trace.db (for the editor plugin)."
    )
    p_panel.add_argument("--host", default="127.0.0.1", help="Bind address.")
    p_panel.add_argument("--port", type=int, default=0, help="Port (0 picks a free one).")
    add_common(p_panel)
    p_panel.set_defaults(func=cmd_panel)

    p_overlay = sub.add_parser(
        "overlay",
        help="Per-file symbol overlay (spans, provenance, last reasoning) for the editor.",
    )
    p_overlay.add_argument("file", help="Repo-relative file path.")
    p_overlay.add_argument("--json", action="store_true", help="Emit the overlay as JSON.")
    add_common(p_overlay)
    p_overlay.set_defaults(func=cmd_overlay)

    p_symat = sub.add_parser(
        "symbol-at",
        help="Resolve a file line to the innermost recorded symbol's qualified name.",
    )
    p_symat.add_argument("file", help="Repo-relative file path.")
    p_symat.add_argument("--line", type=int, required=True, help="1-based line number.")
    p_symat.add_argument("--json", action="store_true", help="Emit the result as JSON.")
    add_common(p_symat)
    p_symat.set_defaults(func=cmd_symbol_at)

    p_symc = sub.add_parser(
        "symbol-content",
        help="A symbol's text at a recorded step (or an abandoned branch) plus its "
        "current working-tree span, for the editor's per-symbol restore.",
    )
    p_symc.add_argument("file", help="Repo-relative file path.")
    p_symc.add_argument("qualified_name", help="The symbol's qualified name.")
    p_symc.add_argument(
        "--at-seq", type=int, default=None, help="Take the text as of this version (steps.seq)."
    )
    p_symc.add_argument(
        "--branch-id", type=int, default=None,
        help="Take the text from this decision-ledger row's abandoned_content.",
    )
    p_symc.add_argument("--json", action="store_true", help="Emit the result as JSON.")
    add_common(p_symc)
    p_symc.set_defaults(func=cmd_symbol_content)

    p_goto = sub.add_parser(
        "goto", help="Restore the code to a recorded version's commit (non-destructive)."
    )
    p_goto.add_argument("version", type=int, help="Version number from 'versions' (steps.seq).")
    p_goto.add_argument(
        "--branch", default=None, help="Create and switch to this branch instead of detached HEAD."
    )
    p_goto.add_argument(
        "--force", action="store_true", help="Proceed even if the working tree is dirty."
    )
    add_common(p_goto)
    p_goto.set_defaults(func=cmd_goto)

    p_rgdb = sub.add_parser(
        "resolve-graph-db",
        help="Print the verified code-map DB for this repo (fails if none / wrong project).",
    )
    p_rgdb.add_argument("--json", action="store_true", help="Emit JSON {ok, repo, graph_db}.")
    add_common(p_rgdb)
    p_rgdb.set_defaults(func=cmd_resolve_graph_db)

    return parser


def _force_utf8_output() -> None:
    """Print UTF-8 regardless of the console codepage (Windows defaults to cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point: parse argv and dispatch to the chosen subcommand."""
    _force_utf8_output()
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

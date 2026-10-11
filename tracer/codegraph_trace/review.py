"""The review surface: everything a reviewer needs for one branch, in one bundle.

``build_review`` assembles, for a feature lineage (a pull request in trace terms):

- the **code diff** from the fork-point commit to the branch tip (readable, 3-line context);
- the branch's **reasoning log** — its own recorded steps with prompts, reasoning, changed
  files and node links;
- its **decision ledger** — the derived survived / abandoned / revised / error_retry rows,
  freshly re-derived so the bundle is self-contained.

``format_review`` renders the bundle as text for a human; ``ReviewBundle.to_dict`` is the JSON
an agent reviewer can consume (wiring an agent to act on it is out of scope here).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from . import gitdiff
from .branches import derive_branches
from .config import TraceConfig
from .lineage import LineageError, LineageInfo
from .store.trace_db import TraceDB


@dataclass
class ReviewBundle:
    """One branch's review surface: diff + reasoning log + decision ledger."""

    lineage: LineageInfo
    base_commit: Optional[str]
    tip_commit: Optional[str]
    diff_text: str
    diff_files: list[dict[str, Any]] = field(default_factory=list)
    steps: list[dict[str, Any]] = field(default_factory=list)
    decisions: list[dict[str, Any]] = field(default_factory=list)
    important_step_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """The machine-readable review surface (stable JSON shape)."""
        return {
            "lineage": self.lineage.to_dict(),
            "diff": {
                "base_commit": self.base_commit,
                "tip_commit": self.tip_commit,
                "text": self.diff_text,
                "files": self.diff_files,
            },
            "steps": self.steps,
            "decisions": self.decisions,
            "important_step_ids": self.important_step_ids,
        }


def build_review(config: TraceConfig, *, lineage_name: Optional[str] = None) -> ReviewBundle:
    """Assemble the review bundle for ``lineage_name`` (default: the current git branch).

    Raises :class:`LineageError` for main (nothing to review) or an unknown lineage. Works
    both before and after a merge — the branch's history stays reviewable.
    """
    from .lineage import resolve_lineage

    db = TraceDB(config.trace_db_path)
    try:
        lineage = resolve_lineage(db, config.repo_root, explicit=lineage_name)
        if lineage.is_main:
            raise LineageError(
                "'main' is not reviewable; pass a feature lineage "
                "(codegraph-trace review <lineage>)."
            )

        steps = db.steps_for_lineage(lineage.lineage_id)
        tip = None
        for s in reversed(steps):
            if s.get("after_sha"):
                tip = s["after_sha"]
                break
        if tip is None:
            tip = gitdiff.rev_parse(config.repo_root, lineage.git_ref)

        base = lineage.base_commit
        text = ""
        files: list[dict[str, Any]] = []
        if tip:
            text = gitdiff.diff_text(config.repo_root, base, tip)
            for fp, fd in sorted(gitdiff.diff_files(config.repo_root, base, tip).items()):
                files.append(
                    {
                        "file_path": fp,
                        "added_lines": len(fd.added),
                        "removed_lines": len(fd.removed),
                    }
                )

        step_payloads = [
            {
                "step_id": s["step_id"],
                "seq": s.get("seq"),
                "timestamp": s.get("timestamp"),
                "author": s.get("author"),
                "before_sha": s.get("before_sha"),
                "after_sha": s.get("after_sha"),
                "prompt": s.get("prompt") or "",
                "reasoning_text": s.get("reasoning_text") or "",
                "changed_files": [
                    f for f in (s.get("changed_files") or "").split(",") if f
                ],
                "nodes": [
                    {
                        "qualified_name": n.get("qualified_name"),
                        "file_path": n.get("file_path"),
                        "label": n.get("label"),
                        "change_kind": n.get("change_kind"),
                        "locked": bool(n.get("locked")),
                    }
                    for n in db.links_for_step(s["step_id"])
                ],
            }
            for s in steps
        ]
    finally:
        db.close()

    # Re-derive the decision ledger so the bundle never shows a stale verdict. Deterministic
    # and idempotent, so this is safe to run on every review.
    derive_branches(config)

    db = TraceDB(config.trace_db_path)
    try:
        decisions = [
            r
            for r in db.list_branches(lineage=lineage)
            if (r.get("lineage_id") or "main") == lineage.lineage_id
        ]
        step_ids = {s["step_id"] for s in step_payloads}
        important = sorted(db.important_step_ids() & step_ids)
    finally:
        db.close()

    return ReviewBundle(
        lineage=lineage,
        base_commit=base,
        tip_commit=tip,
        diff_text=text,
        diff_files=files,
        steps=step_payloads,
        decisions=decisions,
        important_step_ids=important,
    )


def format_review(bundle: ReviewBundle) -> str:
    """Render the review bundle as readable text (the human side of the surface)."""
    lin = bundle.lineage
    out: list[str] = []
    out.append(f"Review: lineage '{lin.lineage_id}' (git branch '{lin.git_ref}')")
    out.append(
        f"Forked from version {lin.base_seq} ({(lin.base_commit or '')[:10]}); "
        f"status: {lin.status}"
        + (f"; merged at {lin.merged_at}" if lin.merged_at else "")
    )
    out.append(
        f"Tip commit: {(bundle.tip_commit or 'none')[:10]}  |  "
        f"{len(bundle.steps)} recorded step(s)  |  "
        f"{len(bundle.decisions)} decision-ledger row(s)"
    )

    out.append("")
    out.append("=== Code diff (fork point -> tip) " + "=" * 30)
    if bundle.diff_files:
        for f in bundle.diff_files:
            out.append(
                f"  {f['file_path']}  (+{f['added_lines']} / -{f['removed_lines']})"
            )
        out.append("")
    if bundle.diff_text.strip():
        out.append(bundle.diff_text.rstrip("\n"))
    else:
        out.append("(no code changes recorded on this branch)")

    out.append("")
    out.append("=== Reasoning log " + "=" * 46)
    if not bundle.steps:
        out.append("(no steps recorded on this branch)")
    important = set(bundle.important_step_ids)
    for s in bundle.steps:
        step_no = f"step#{s['seq']}" if s.get("seq") is not None else s["step_id"]
        tag = "  [decision]" if s["step_id"] in important else ""
        out.append("")
        out.append(f"{step_no}  {s['step_id']}  author={s.get('author') or '?'}{tag}")
        if s.get("prompt"):
            out.append(f"  prompt: {s['prompt']}")
        if s.get("reasoning_text"):
            out.append(f"  reasoning: {s['reasoning_text']}")
        if s["changed_files"]:
            out.append(f"  files: {', '.join(s['changed_files'])}")
        for n in s["nodes"]:
            lock = "  [locked]" if n["locked"] else ""
            out.append(
                f"    {n['change_kind'] or '?':8s} {n['qualified_name']}"
                f"  [{n['label'] or '?'}]{lock}"
            )

    out.append("")
    out.append("=== Decision ledger " + "=" * 44)
    if not bundle.decisions:
        out.append("(no decision rows: every step was plain forward motion)")
    for r in bundle.decisions:
        step_no = f"step#{r['seq']}" if r.get("seq") is not None else r["step_id"]
        node = r["qualified_name"] or "(file-level)"
        out.append("")
        out.append(f"{step_no}  {r['file_path']} :: {node}")
        verdict = f"  attempt -> {r['kind']}"
        if r.get("superseded_by_seq") is not None:
            verdict += f" -> replaced by step {int(r['superseded_by_seq'])}"
        elif r.get("superseded_by_step_id"):
            verdict += f" -> replaced by {r['superseded_by_step_id']}"
        if r.get("survival_ratio") is not None:
            verdict += f"  (survival {float(r['survival_ratio']):.2f})"
        out.append(verdict)
        if r.get("abandoned_content"):
            out.append("  abandoned code:")
            for ln in r["abandoned_content"].splitlines():
                out.append(f"    {ln}")

    out.append("")
    return "\n".join(out)

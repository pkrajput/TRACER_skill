"""Join Semgrep findings with the recorded trace: ``codegraph-trace flag``.

Semgrep (https://semgrep.dev) is a deterministic static-analysis scanner; run it first:

    semgrep scan --config p/security-audit --json --output findings.json <repo>

Then this module answers, per finding: *which symbol is this, who wrote it, how many times
was it touched, what was the reasoning, and did the author ever branch/retry here?* The
output is a triage report for a human, not a detector - the two extra signals are labelled
heuristics on purpose.

Symbol mapping reuses the recorder's own resolution path
(:meth:`codegraph.CodeGraph.resolve_nodes_via_source`, i.e. ``ast_symbols.extract_symbols``
+ ``symbols_for_range`` + ``module_prefix``) so the qualified names here are byte-identical
to the ones the recorder wrote into ``trace.db``. There is deliberately no second
name-builder.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .ast_symbols import language_for_path
from .codegraph import CodeGraph, normalize_path
from .config import TraceConfig
from .models import NodeRef
from .query import resolve_story
from .store.trace_db import TraceDB

# Fixed keyword list for the sensitive_reasoning heuristic (substring match, lowercase).
SENSITIVE_KEYWORDS = (
    "auth", "token", "password", "sql", "injection", "sanitize", "validate",
    "escape", "crypto", "secret", "permission", "cors", "xss",
)

# Hedging vocabulary for the one_shot_confident heuristic (substring match, lowercase).
HEDGING_WORDS = ("maybe", "alternatively", "verify", "double-check", "not sure")

REVIEW_FIRST_NOTE = (
    "flagged line was written in one confident pass with no security consideration in the "
    "reasoning - review first (possible hallucinated safety)"
)

_REASONING_SNIPPET_LIMIT = 240


@dataclass
class FlagReport:
    """The whole triage report: one row per Semgrep finding."""

    rows: list[dict[str, Any]] = field(default_factory=list)
    findings_total: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Serialize the triage report for ``--json`` / ``--save`` output."""
        return {"findings_total": self.findings_total, "rows": self.rows}


def _load_findings(findings_path: Path) -> list[dict[str, Any]]:
    data = json.loads(Path(findings_path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        return list(data.get("results") or [])
    if isinstance(data, list):  # allow a bare results array
        return data
    raise ValueError(f"Unrecognised findings JSON shape in {findings_path}")


def _relative_path(path: str, repo_root: Path) -> str:
    """Semgrep may emit absolute paths or paths relative to its scan root; normalize to a
    repo-relative, forward-slash path (the shape stored in ``node_links.file_path``)."""
    p = Path(path)
    if p.is_absolute():
        try:
            p = p.resolve().relative_to(repo_root.resolve())
        except ValueError:
            pass
    return normalize_path(str(p))


def _pick_symbol(nodes: list[NodeRef]) -> Optional[NodeRef]:
    """The most specific symbol node (smallest span), skipping file-level fallbacks."""
    symbols = [n for n in nodes if n.label != "File" and n.end_line >= n.start_line > 0]
    if not symbols:
        return None
    return min(symbols, key=lambda n: (n.end_line - n.start_line, n.start_line))


def _map_finding_to_node(
    finding: dict[str, Any],
    repo_root: Path,
    graph: Optional[CodeGraph],
) -> NodeRef:
    """Map one finding's line range to a node exactly the way the recorder does.

    Falls back to the file-level node when no symbol overlaps, when the language is
    unsupported, when the file cannot be read, or when there is no code graph (in which
    case the recorder would also have recorded file-level nodes).
    """
    rel = _relative_path(finding.get("path") or "", repo_root)
    start = int((finding.get("start") or {}).get("line") or 1)
    end = int((finding.get("end") or {}).get("line") or start)

    file_fallback = NodeRef(
        node_id=None, label="File", qualified_name=f"file::{rel}", file_path=rel,
    )
    if graph is None:
        return file_fallback

    language = language_for_path(rel)
    if language is None:
        return graph.file_node(rel) or file_fallback

    try:
        source = (repo_root / rel).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return graph.file_node(rel) or file_fallback

    nodes = graph.resolve_nodes_via_source(rel, [(start, end)], source, language)
    return _pick_symbol(nodes) or graph.file_node(rel) or file_fallback


def _snippet(text: str, limit: int = _REASONING_SNIPPET_LIMIT) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _keyword_hits(texts: list[str], keywords: tuple[str, ...]) -> list[str]:
    blob = "\n".join(t.lower() for t in texts if t)
    return [kw for kw in keywords if kw in blob]


def _branch_summary(branch_rows: list[dict[str, Any]]) -> dict[str, Any]:
    counts = {"survived": 0, "abandoned": 0, "revised": 0, "error_retry": 0}
    for r in branch_rows:
        kind = r.get("kind")
        if kind in counts:
            counts[kind] += 1
    return {"attempts": len(branch_rows), **counts}


def _story_for_node(
    node: NodeRef, db: TraceDB
) -> tuple[list[dict[str, Any]], Optional[dict[str, Any]], list[dict[str, Any]]]:
    """(steps, markers, branch_rows) via the shared symbol → file history lookup."""
    story = resolve_story(db, node.qualified_name, file_path=node.file_path)
    return story.steps, story.markers, story.branch_rows


def flag_findings(config: TraceConfig, findings_path: Path) -> FlagReport:
    """Build the triage report joining Semgrep findings with the recorded trace."""
    findings = _load_findings(findings_path)
    report = FlagReport(findings_total=len(findings))
    if not findings:
        return report

    graph: Optional[CodeGraph] = None
    if config.graph_db_path is not None and Path(config.graph_db_path).is_file():
        graph = CodeGraph(config.graph_db_path)

    db = TraceDB(config.trace_db_path)
    try:
        for finding in findings:
            report.rows.append(_row_for_finding(finding, config.repo_root, graph, db))
    finally:
        db.close()
        if graph is not None:
            graph.close()
    return report


def _row_for_finding(
    finding: dict[str, Any],
    repo_root: Path,
    graph: Optional[CodeGraph],
    db: TraceDB,
) -> dict[str, Any]:
    rel = _relative_path(finding.get("path") or "", repo_root)
    start = int((finding.get("start") or {}).get("line") or 1)
    end = int((finding.get("end") or {}).get("line") or start)
    extra = finding.get("extra") or {}

    node = _map_finding_to_node(finding, repo_root, graph)
    steps, markers, branch_rows = _story_for_node(node, db)
    signature = db.get_signature(node.qualified_name)

    reasoning_texts = [s.get("reasoning_text") or "" for s in steps]
    author = (signature or {}).get("author")
    if not author:
        authors = {s.get("author") for s in steps if s.get("author")}
        author = "human" if "human" in authors else ("agent" if authors else None)
    locked = bool((signature or {}).get("locked"))
    touch_count = (markers or {}).get("touch_count", len(steps))

    sensitive_hits = _keyword_hits(reasoning_texts, SENSITIVE_KEYWORDS)
    hedging_hits = _keyword_hits(reasoning_texts, HEDGING_WORDS)
    sensitive = bool(sensitive_hits)
    # "Zero branch rows" means zero *forks*: a plain `survived` row is exactly the one-pass
    # case this signal describes, so only abandoned/revised/error_retry rows disqualify it.
    fork_rows = [r for r in branch_rows if r.get("kind") != "survived"]
    one_shot = touch_count == 1 and not fork_rows and not hedging_hits
    review_first = one_shot and not sensitive

    return {
        "check_id": finding.get("check_id"),
        "severity": extra.get("severity"),
        "message": extra.get("message"),
        "path": rel,
        "start_line": start,
        "end_line": end,
        "location": f"{rel}:{start}",
        "symbol": node.qualified_name,
        "symbol_kind": node.label,
        "author": author,
        "locked": locked,
        "touch_count": touch_count,
        "steps": [
            {
                "step_id": s.get("step_id"),
                "seq": s.get("seq"),
                "author": s.get("author"),
                "reasoning": _snippet(s.get("reasoning_text") or ""),
            }
            for s in steps
        ],
        "reasoning_snippets": [_snippet(t) for t in reasoning_texts if t.strip()],
        "branch_summary": _branch_summary(branch_rows),
        "heuristics": {
            "sensitive_reasoning": {"value": sensitive, "matched": sensitive_hits},
            "one_shot_confident": {"value": one_shot, "hedging_matched": hedging_hits},
            "review_first": review_first,
            "note": REVIEW_FIRST_NOTE if review_first else None,
        },
    }


def format_report(report: FlagReport) -> str:
    """Render the triage report as readable text for the CLI."""
    if not report.rows:
        return f"No Semgrep findings to flag ({report.findings_total} in the input)."
    lines = [f"Semgrep triage report ({len(report.rows)} finding(s)):", ""]
    for i, r in enumerate(report.rows, 1):
        lines.append(f"{i}. [{r.get('severity') or '?'}] {r['check_id']}")
        lines.append(f"   at: {r['location']}  symbol: {r['symbol']} [{r['symbol_kind']}]")
        if r.get("message"):
            lines.append(f"   finding: {_snippet(r['message'], 160)}")
        author = r.get("author") or "unrecorded"
        locked = "yes" if r.get("locked") else "no"
        lines.append(
            f"   author: {author}  locked: {locked}  touch_count: {r['touch_count']}"
        )
        bs = r["branch_summary"]
        lines.append(
            f"   branches: attempts={bs['attempts']} abandoned={bs['abandoned']} "
            f"revised={bs['revised']} error_retries={bs['error_retry']}"
        )
        if r["reasoning_snippets"]:
            lines.append("   reasoning:")
            for snip in r["reasoning_snippets"]:
                lines.append(f"     - {snip}")
        else:
            lines.append("   reasoning: (none recorded)")
        heur = r["heuristics"]
        sens = heur["sensitive_reasoning"]
        sens_txt = "yes (" + ", ".join(sens["matched"]) + ")" if sens["value"] else "no"
        one = heur["one_shot_confident"]
        lines.append(
            f"   heuristics: sensitive_reasoning={sens_txt}  "
            f"one_shot_confident={'yes' if one['value'] else 'no'}"
        )
        if heur["review_first"]:
            lines.append(f"   >>> {REVIEW_FIRST_NOTE}")
        lines.append("")
    lines.append("Heuristic signals are triage hints for a human reviewer, not detections.")
    return "\n".join(lines)

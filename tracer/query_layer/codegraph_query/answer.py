"""Synthesize a natural-language answer from ranked reasoning + graph context."""

from __future__ import annotations

import os
from typing import Optional

from codegraph_trace.models import NodeRef

from .graph_nav import GraphNavigator
from .models import AnchorNode, RankedStep


def synthesize_answer(
    question: str,
    *,
    anchors: list[AnchorNode],
    neighbourhood: list[NodeRef],
    ranked: list[RankedStep],
    navigator: Optional[GraphNavigator] = None,
    llm_model: Optional[str] = None,
    use_llm: bool = True,
) -> tuple[str, dict]:
    """Return (answer_text, meta). Uses LLM when credentials exist, else a template."""
    context = _build_context(question, anchors, neighbourhood, ranked, navigator)
    meta: dict = {"mode": "template"}

    if use_llm and _llm_available():
        try:
            answer = _llm_answer(question, context, llm_model or os.getenv("LLM_MODEL", "gemini/gemini-2.5-flash"))
            meta["mode"] = "llm"
            return answer, meta
        except Exception as exc:
            meta["llm_error"] = str(exc)

    return _template_answer(question, anchors, neighbourhood, ranked), meta


def _llm_available() -> bool:
    return bool(os.getenv("LLM_API_KEY"))


def _build_context(
    question: str,
    anchors: list[AnchorNode],
    neighbourhood: list[NodeRef],
    ranked: list[RankedStep],
    navigator: Optional[GraphNavigator],
) -> str:
    lines = [f"Question: {question}", "", "Anchor nodes:"]
    for a in anchors:
        lines.append(f"- {a.node.qualified_name} ({a.node.label}): {a.match_reason}")

    if navigator and anchors:
        primary = anchors[0].node
        if primary.node_id is not None:
            callers = navigator.callers(primary.node_id, limit=10)
            callees = navigator.callees(primary.node_id, limit=10)
            if callers:
                lines.extend(["", "Direct callers (may break if anchor changes):"])
                for c in callers:
                    lines.append(f"- {c.qualified_name} ({c.label})")
            if callees:
                lines.extend(["", "Direct dependencies:"])
                for c in callees:
                    lines.append(f"- {c.qualified_name} ({c.label})")

    lines.extend(["", f"Neighbourhood ({len(neighbourhood)} nodes):"])
    for n in neighbourhood[:20]:
        lines.append(f"- {n.qualified_name} ({n.label}, {n.file_path})")
    if len(neighbourhood) > 20:
        lines.append(f"- ... and {len(neighbourhood) - 20} more")

    lines.extend(["", "Ranked agent reasoning (most relevant first):"])
    for i, rs in enumerate(ranked, 1):
        c = rs.candidate
        lines.append(f"{i}. [score={rs.score:.3f}] step {c.step_id} @ {c.after_sha or '?'}")
        if c.prompt:
            lines.append(f"   prompt: {_truncate(c.prompt, 300)}")
        if c.reasoning_text:
            lines.append(f"   reasoning: {_truncate(c.reasoning_text, 400)}")
        if c.linked_qualified_names:
            lines.append(f"   linked: {', '.join(c.linked_qualified_names[:8])}")

    return "\n".join(lines)


def _llm_answer(question: str, context: str, model: str) -> str:
    import litellm

    response = litellm.completion(
        model=model,
        api_key=os.getenv("LLM_API_KEY"),
        messages=[
            {
                "role": "system",
                "content": (
                    "You answer questions about why code changed and what might break. "
                    "Use ONLY the provided graph neighbourhood and recorded agent reasoning. "
                    "If the evidence is thin, say so. Be concise and specific."
                ),
            },
            {
                "role": "user",
                "content": f"{context}\n\nAnswer the question based on the evidence above.",
            },
        ],
        max_tokens=800,
        temperature=0.2,
    )
    return (response.choices[0].message.content or "").strip()


def _template_answer(
    question: str,
    anchors: list[AnchorNode],
    neighbourhood: list[NodeRef],
    ranked: list[RankedStep],
) -> str:
    if not ranked:
        anchor_names = ", ".join(a.node.qualified_name for a in anchors) or "(none found)"
        return (
            f"No recorded reasoning linked to the neighbourhood around {anchor_names}.\n"
            "Run the recording layer while the agent works, then re-index the repo."
        )

    lines = [f"## Answer", "", f"**Question:** {question}", ""]
    if anchors:
        lines.append(
            "**Scope:** "
            + ", ".join(f"`{a.node.qualified_name}`" for a in anchors)
            + f" and {len(neighbourhood)} neighbouring node(s)."
        )
        lines.append("")

    lines.append("### Why it changed (from recorded agent reasoning)")
    for i, rs in enumerate(ranked, 1):
        c = rs.candidate
        lines.append(f"{i}. **Step `{c.step_id[:12]}…`** (relevance {rs.score:.2f})")
        if c.prompt:
            lines.append(f"   - Trigger: {_truncate(c.prompt, 220)}")
        if c.reasoning_text:
            lines.append(f"   - Agent said: {_truncate(c.reasoning_text, 280)}")
        lines.append("")

    lines.append("### Impact notes")
    lines.append(
        "The funnel gathered reasoning only for nodes in the graph neighbourhood "
        "(anchor + dependency walk via `node_links`). Check direct callers in the graph "
        "for breakage risk when changing the anchor symbol."
    )
    return "\n".join(lines)


def _truncate(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."

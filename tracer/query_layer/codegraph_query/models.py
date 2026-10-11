"""Data shapes for the query funnel."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from codegraph_trace.models import NodeRef


@dataclass
class AnchorNode:
    """A code-graph node chosen as the entry point for a query."""

    node: NodeRef
    match_reason: str


@dataclass
class ReasoningCandidate:
    """One recorded step linked to the neighbourhood via node_links."""

    step_id: str
    prompt: str
    reasoning_text: str
    timestamp: str
    before_sha: Optional[str]
    after_sha: Optional[str]
    linked_qualified_names: list[str]
    linked_files: list[str]

    @property
    def document(self) -> str:
        """Text used for ranking: prompt plus reasoning."""
        prompt = (self.prompt or "").strip()
        reasoning = (self.reasoning_text or "").strip()
        if prompt and reasoning:
            return f"{prompt}\n\n{reasoning}"
        return prompt or reasoning

    def as_dict(self) -> dict[str, Any]:
        """Serialize this candidate for JSON output."""
        return {
            "step_id": self.step_id,
            "prompt": self.prompt,
            "reasoning_text": self.reasoning_text,
            "timestamp": self.timestamp,
            "before_sha": self.before_sha,
            "after_sha": self.after_sha,
            "linked_qualified_names": self.linked_qualified_names,
            "linked_files": self.linked_files,
        }


@dataclass
class RankedStep:
    """A reasoning candidate after question-similarity ranking."""

    candidate: ReasoningCandidate
    score: float


@dataclass
class FunnelResult:
    """Full output of one funnel query."""

    question: str
    anchors: list[AnchorNode]
    neighbourhood: list[NodeRef]
    candidates: list[ReasoningCandidate]
    ranked: list[RankedStep]
    answer: str
    meta: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        """Serialize the full funnel result for JSON output."""
        return {
            "question": self.question,
            "anchors": [
                {"qualified_name": a.node.qualified_name, "match_reason": a.match_reason}
                for a in self.anchors
            ],
            "neighbourhood": [n.qualified_name for n in self.neighbourhood],
            "candidate_count": len(self.candidates),
            "ranked": [
                {"step_id": r.candidate.step_id, "score": r.score}
                for r in self.ranked
            ],
            "answer": self.answer,
            "meta": self.meta,
        }

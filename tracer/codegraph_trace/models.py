"""Internal data shapes shared across the recording layer.

The single most important type here is :class:`Step` - the tiny, agent-agnostic shape that
every adapter maps into and that everything downstream depends on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


def utcnow_iso() -> str:
    """Return a timezone-aware UTC timestamp in ISO-8601 form."""
    return datetime.now(timezone.utc).isoformat()


# --- reasoning provenance taxonomy --------------------------------------
#
# TRACER's own, harness-agnostic vocabulary for *where a piece of reasoning came from*.
# Adapters map their harness's fields into these values; nothing downstream ever needs to
# know which harness (or model provider) produced the text. Provider quirks are absorbed
# upstream by the harness layer (e.g. LiteLLM normalising reasoning fields) — TRACER never
# talks to a model provider directly.

#: The agent's narration messages — what it said out loud between actions.
NARRATION = "narration"
#: The justification a harness attaches to a single tool call (OpenHands ``thought``).
TOOL_THOUGHT = "tool_thought"
#: Raw reasoning tokens the provider returned and the harness logged (visible CoT).
EXPOSED_COT = "exposed_cot"
#: A provider-sanitised summary of hidden reasoning — NOT faithful CoT; kept distinct so
#: research consumers never mistake it for the real thing.
COT_SUMMARY = "cot_summary"

REASONING_PROVENANCES = (NARRATION, TOOL_THOUGHT, EXPOSED_COT, COT_SUMMARY)


@dataclass
class ReasoningSegment:
    """One provenance-tagged piece of a step's reasoning.

    ``reasoning_text`` on :class:`Step` remains the flat, embedded/displayed blob;
    segments carry the same content *split by provenance* so consumers that care about
    faithfulness (research queries, audit heuristics) can distinguish the agent's stated
    narration from exposed chain-of-thought.
    """

    provenance: str  # one of REASONING_PROVENANCES
    text: str

    def to_json(self) -> dict[str, str]:
        """Serialize this segment to a JSON-ready dict."""
        return {"provenance": self.provenance, "text": self.text}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "ReasoningSegment":
        """Rebuild a segment from its :meth:`to_json` form."""
        return cls(provenance=str(data.get("provenance", "")), text=str(data.get("text", "")))


@dataclass
class Step:
    """One agent step in the internal, agent-agnostic shape.

    This is the plugin contract. Adapters produce ``Step`` objects; the recorder consumes
    them. Keep it tiny on purpose.

    Attributes:
        step_id: Stable, unique id for the step (used as the primary key everywhere).
        prompt: The prompt/instruction that triggered the step.
        reasoning_text: The agent's written turns around its tool calls, flattened into one
            blob (what gets embedded and displayed). Split by provenance in
            ``reasoning_segments``.
        reasoning_segments: The same reasoning split into provenance-tagged
            :class:`ReasoningSegment` pieces (narration / tool_thought / exposed_cot /
            cot_summary). Empty for adapters or explicit ``record`` calls that do not
            distinguish provenance.
        timestamp: ISO-8601 timestamp for ordering.
        before_sha: Git SHA before the step's edits (None for the very first step).
        after_sha: Git SHA after the step's edits (the commit that captured them).
        raw_event: The adapter's raw record, stored verbatim so new parsers can be written
            later against the original data.
        author: Who produced the step - ``"agent"`` (the default, an AI model) or ``"human"``.
            Human-authored steps tag and lock the nodes they touch so agent recording can never
            quietly overwrite or delete that record.
        lineage_id: Development lineage this step belongs to (``"main"`` by default). Feature
            forks stamp their own id so one-way visibility can hide them from main until merge.
    """

    step_id: str
    prompt: str
    reasoning_text: str
    timestamp: str = field(default_factory=utcnow_iso)
    before_sha: Optional[str] = None
    after_sha: Optional[str] = None
    raw_event: Optional[Any] = None
    author: str = "agent"
    lineage_id: str = "main"
    reasoning_segments: list[ReasoningSegment] = field(default_factory=list)

    def document(self) -> str:
        """The text that gets embedded: prompt followed by reasoning."""
        prompt = (self.prompt or "").strip()
        reasoning = (self.reasoning_text or "").strip()
        if prompt and reasoning:
            return f"{prompt}\n\n{reasoning}"
        return prompt or reasoning


@dataclass(frozen=True)
class NodeRef:
    """A reference to a node in the read-only code graph.

    ``node_id`` is the volatile integer id from the current index; ``qualified_name`` is the
    durable identity that survives a re-index.
    """

    qualified_name: str
    label: str
    file_path: str
    start_line: int = 0
    end_line: int = 0
    node_id: Optional[int] = None

    def span(self) -> tuple[int, int]:
        """``(start_line, end_line)`` span of this node in its file."""
        return (self.start_line, self.end_line)


@dataclass
class LinkedNode:
    """A code node a step touched, plus how it changed and its signature fingerprint."""

    node: NodeRef
    change_kind: str  # "added" | "removed" | "changed"
    edge_fingerprint: str = ""


@dataclass
class Snapshot:
    """The per-commit node/edge delta written under ``snapshots/<after_sha>.json``."""

    commit: str
    step_id: str
    before_sha: Optional[str]
    seq: Optional[int] = None
    nodes_added: list[str] = field(default_factory=list)
    nodes_removed: list[str] = field(default_factory=list)
    nodes_changed: list[str] = field(default_factory=list)
    edges_added: list[str] = field(default_factory=list)
    edges_removed: list[str] = field(default_factory=list)
    edges_changed: list[str] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        """Serialize this snapshot to a JSON-ready dict."""
        return {
            "commit": self.commit,
            "step_id": self.step_id,
            "step_seq": self.seq,
            "before_sha": self.before_sha,
            "nodes": {
                "added": self.nodes_added,
                "removed": self.nodes_removed,
                "changed": self.nodes_changed,
            },
            "edges": {
                "added": self.edges_added,
                "removed": self.edges_removed,
                "changed": self.edges_changed,
            },
        }

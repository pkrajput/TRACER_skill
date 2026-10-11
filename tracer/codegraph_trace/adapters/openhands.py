"""OpenHands adapter.

Reads an OpenHands conversation and maps it into the internal
:class:`~codegraph_trace.models.Step` shape. We pull the **prompt** from user messages and the
**reasoning** from the agent's own written turns - its message text and the ``thought`` it
attaches to tool calls - plus any **exposed** reasoning tokens the provider returned and
OpenHands logged (``reasoning_content``, normalised across providers by LiteLLM). Hidden
"thinking" tokens that never reach the harness log are, by definition, not recorded.

Each fragment is provenance-tagged on ``Step.reasoning_segments`` (narration /
tool_thought / exposed_cot) so downstream consumers can distinguish the agent's stated
story from visible chain-of-thought; ``Step.reasoning_text`` stays the flat blob.
This mapping - harness field to TRACER provenance - is the only place OpenHands
knowledge lives; the taxonomy itself is harness-agnostic.

Two on-disk formats are supported transparently:

- **V1 (current SDK)**: a conversation directory containing ``events/event-00000-<id>.json``
  files (one typed event per file), each loadable as a Pydantic ``Event``. Schema:
  ``MessageEvent`` carries ``llm_message.role`` + ``llm_message.content``; ``ActionEvent``
  carries ``thought`` / ``reasoning_content`` plus the tool call.
- **V0 (legacy)**: a single ``events.jsonl`` with ``source`` / ``action`` / ``args.content``.

The input path may be any of: an ``events.jsonl`` file, a single ``event-*.json`` file's parent
``events/`` directory, or a conversation directory that contains an ``events/`` subdir. A step
boundary is one agent narration turn; the raw events composing a step are preserved verbatim on
``Step.raw_event`` (raw records first, parse later). The same :class:`StepSource` contract also
supports a future live websocket source.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator, Optional

from ..models import EXPOSED_COT, NARRATION, TOOL_THOUGHT, ReasoningSegment, Step

# --- text extraction (handles V0 + V1 content shapes) ------------------


def _extract_text(value: Any) -> str:
    """Pull human-readable text out of the many shapes OpenHands uses.

    Handles plain strings, a list of content parts (``[{"type": "text", "text": ...}]``),
    a single content dict, and lists of strings.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("text", "content", "message"):
            if key in value:
                return _extract_text(value[key])
        return ""
    if isinstance(value, (list, tuple)):
        parts = [_extract_text(v) for v in value]
        return "\n".join(p for p in parts if p)
    return ""


# --- a normalized view of one raw event --------------------------------

# Categories the step grouper cares about.
_USER_MSG = "user_msg"
_AGENT_MSG = "agent_msg"
_AGENT_ACTION = "agent_action"
_OTHER = "other"


def _llm_message(event: dict[str, Any]) -> Optional[dict[str, Any]]:
    for key in ("llm_message", "message"):
        val = event.get(key)
        if isinstance(val, dict):
            return val
    return None


def _segments(*pairs: tuple[str, str]) -> list[ReasoningSegment]:
    """Build provenance-tagged segments from ``(provenance, text)`` pairs, dropping empties."""
    return [
        ReasoningSegment(provenance=prov, text=text.strip())
        for prov, text in pairs
        if text and text.strip()
    ]


def classify_event(event: dict[str, Any]) -> tuple[str, str, list[ReasoningSegment]]:
    """Return ``(category, text, segments)`` for a raw event dict (V0 or V1).

    ``text`` is the flat fragment (prompt for user messages, combined reasoning otherwise);
    ``segments`` is the same reasoning split by TRACER's provenance taxonomy. User messages
    carry no segments - their text becomes the step's prompt, not its reasoning.
    """
    source = event.get("source")
    kind = event.get("kind") or ""
    action = event.get("action")

    # --- V1 typed events (discriminated by `kind`) ---
    if kind:
        if kind == "MessageEvent" or kind.endswith("MessageEvent"):
            msg = _llm_message(event) or {}
            role = msg.get("role") or ("user" if source == "user" else "assistant")
            text = _extract_text(msg.get("content")) or _extract_text(event.get("content"))
            if role == "user":
                return (_USER_MSG, text, [])
            return (_AGENT_MSG, text, _segments((NARRATION, text)))
        if kind == "ActionEvent" or kind.endswith("ActionEvent"):
            thought = _extract_text(event.get("thought"))
            reasoning = _extract_text(event.get("reasoning_content"))
            text = "\n\n".join(t for t in (thought, reasoning) if t)
            return (
                _AGENT_ACTION,
                text,
                _segments((TOOL_THOUGHT, thought), (EXPOSED_COT, reasoning)),
            )
        # SystemPromptEvent, ObservationEvent, condensation, state updates, etc.
        return (_OTHER, "", [])

    # --- V0 legacy events (source + action + args) ---
    args = event.get("args") or {}
    if source == "user" and (action == "message" or args.get("content")):
        return (_USER_MSG, _extract_text(args.get("content")) or _extract_text(event), [])
    if source == "agent" and action == "message":
        text = _extract_text(args.get("content")) or _extract_text(event)
        return (_AGENT_MSG, text, _segments((NARRATION, text)))
    if source == "agent":
        thought = _extract_text(args.get("thought")) or _extract_text(event.get("thought"))
        return (_AGENT_ACTION, thought, _segments((TOOL_THOUGHT, thought)))
    return (_OTHER, "", [])


class OpenHandsAdapter:
    """Maps an OpenHands conversation (V0 or V1) into internal steps."""

    def __init__(self, path: str | Path, conversation_id: Optional[str] = None) -> None:
        self.path = Path(path)
        self.conversation_id = conversation_id or self._derive_conversation_id()

    @classmethod
    def from_conversation_dir(cls, conversation_dir: str | Path) -> "OpenHandsAdapter":
        """Build an adapter from a V1 OpenHands conversation directory."""
        d = Path(conversation_dir)
        return cls(d, conversation_id=d.name)

    def _derive_conversation_id(self) -> str:
        p = self.path
        if p.is_dir():
            return p.name or "conv"
        # events.jsonl -> use parent dir name
        return p.parent.name or "conv"

    # --- locate + read raw events -------------------------------------
    def _event_files(self) -> Optional[list[Path]]:
        """If this is a V1 layout, return the sorted ``event-*.json`` files; else None."""
        p = self.path
        if p.is_dir():
            events_dir = p / "events" if (p / "events").is_dir() else p
            files = sorted(events_dir.glob("event-*.json"))
            return files or None
        return None

    def _read_events(self) -> Iterator[dict[str, Any]]:
        files = self._event_files()
        if files is not None:
            for fp in files:
                try:
                    yield json.loads(fp.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError):
                    continue
            return

        # V0: a single JSONL file (or a directory containing events.jsonl).
        jsonl = self.path
        if jsonl.is_dir():
            jsonl = jsonl / "events.jsonl"
        if not jsonl.is_file():
            return
        with jsonl.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue

    # --- build steps ---------------------------------------------------
    def steps(self) -> Iterator[Step]:
        """Yield one step per agent **action** (tool call / edit).

        Each ``ActionEvent`` becomes its own step - this is the granularity that maps 1:1 to a
        commit in a real session, where a single user task produces many actions but few (often
        one) narration messages. The step's reasoning is the agent's narration since the last
        action plus this action's own thought; its raw trail includes the preceding messages,
        the action, and the trailing observation(s) so commit alignment by event id is robust.
        """
        events = list(self._read_events())
        # (category, text, segments, event)
        classified = [(*classify_event(e), e) for e in events]
        n = len(events)
        counter = 0

        def new_id(event: dict[str, Any]) -> str:
            nonlocal counter
            eid = event.get("id")
            if eid in (None, "?", ""):
                counter += 1
                eid = f"n{counter}"
            return f"oh-{self.conversation_id}-{eid}"

        current_prompt = ""
        narration: list[str] = []          # agent message text since the last action
        narration_segments: list[ReasoningSegment] = []  # same, provenance-tagged
        pre_raw: list[dict[str, Any]] = []  # raw events since the last action (msgs, prompts)

        i = 0
        while i < n:
            category, text, segments, event = classified[i]

            if category == _USER_MSG:
                current_prompt = text
                narration = []
                narration_segments = []
                pre_raw.append(event)
                i += 1
                continue

            if category == _AGENT_MSG:
                if text and text.strip():
                    narration.append(text.strip())
                    narration_segments.extend(segments)
                pre_raw.append(event)
                i += 1
                continue

            if category == _AGENT_ACTION:
                raw = [*pre_raw, event]
                # Fold the trailing observation(s) into this action's step so the commit (which
                # may be tagged at either the action or its observation event) is always covered.
                j = i + 1
                while j < n and classified[j][0] == _OTHER:
                    raw.append(classified[j][3])
                    j += 1
                fragments = [f for f in (*narration, text) if f and f.strip()]
                yield Step(
                    step_id=new_id(event),
                    prompt=current_prompt,
                    reasoning_text="\n\n".join(fragments),
                    timestamp=str(event.get("timestamp", "")),
                    raw_event=raw,
                    reasoning_segments=[*narration_segments, *segments],
                )
                narration = []
                narration_segments = []
                pre_raw = []
                i = j
                continue

            # _OTHER outside an action span (system prompt, leading observations): keep as trail.
            pre_raw.append(event)
            i += 1

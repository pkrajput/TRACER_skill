"""Agent adapters.

Each adapter maps a specific agent's log into the internal :class:`~codegraph_trace.models.Step`
shape, which is the only contract the rest of the recording layer depends on. This is what
makes the recorder a plugin host rather than a one-off integration.
"""

from __future__ import annotations

from .base import StepSource, iter_steps
from .openhands import OpenHandsAdapter

__all__ = ["StepSource", "iter_steps", "OpenHandsAdapter"]

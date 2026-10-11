"""codegraph-trace: an agent-agnostic recording layer.

Captures each agent step's prompt and reasoning, ties it to the code nodes the step
changed, and persists an ordered, per-file story of why the code changed.
"""

from __future__ import annotations

from .models import LinkedNode, NodeRef, Snapshot, Step
from .config import TraceConfig
from .recorder import Recorder
from .query import TraceQuery

__all__ = [
    "Step",
    "NodeRef",
    "LinkedNode",
    "Snapshot",
    "TraceConfig",
    "Recorder",
    "TraceQuery",
]

__version__ = "0.1.0"

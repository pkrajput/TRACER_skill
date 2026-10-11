"""Persistence backends owned by the recording layer.

These stores are kept entirely separate from the read-only code graph:

- :mod:`codegraph_trace.store.trace_db`   - SQLite ``steps`` / ``node_links`` / ``node_signatures``
- :mod:`codegraph_trace.store.chroma_store` - ChromaDB ``reasoning`` embeddings
- :mod:`codegraph_trace.store.snapshots`  - per-commit JSON node/edge deltas
"""

from __future__ import annotations

from .trace_db import TraceDB
from .snapshots import SnapshotWriter

__all__ = ["TraceDB", "SnapshotWriter"]

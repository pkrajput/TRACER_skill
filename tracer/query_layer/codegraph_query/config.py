"""Configuration for the query funnel."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from codegraph_trace.config import (
    GraphDbSetupError,
    TraceConfig,
    discover_graph_db,
    graph_db_match_status,
    graph_db_setup_message,
)


@dataclass
class QueryConfig:
    """Paths and knobs for one query session."""

    repo_root: Path
    graph_db_path: Optional[Path] = None
    trace_dir: Optional[Path] = None
    embedding_model: str = "all-MiniLM-L6-v2"
    neighbour_hops: int = 1
    top_k: int = 5
    llm_model: Optional[str] = None

    def __post_init__(self) -> None:
        self.repo_root = Path(self.repo_root).resolve()
        if self.trace_dir is None:
            self.trace_dir = self.repo_root / ".codegraph-trace"
        else:
            self.trace_dir = Path(self.trace_dir)
        if self.graph_db_path is None:
            self.graph_db_path = discover_graph_db(self.repo_root)
        else:
            explicit = Path(self.graph_db_path).expanduser()
            if explicit.is_file() and graph_db_match_status(explicit, self.repo_root) == "mismatch":
                raise GraphDbSetupError(
                    f"Code-map DB does not belong to this repository.\n"
                    f"  repo: {self.repo_root}\n"
                    f"  db:   {explicit}\n\n"
                    f"{graph_db_setup_message(self.repo_root)}"
                )
            self.graph_db_path = explicit
        if self.llm_model is None:
            self.llm_model = os.getenv("LLM_MODEL", "gemini/gemini-2.5-flash")

    @property
    def trace_db_path(self) -> Path:
        """Path to the recording-layer ``trace.db`` for this query."""
        return self.trace_dir / "trace.db"

    def to_trace_config(self) -> TraceConfig:
        """Build a ``TraceConfig`` pointing at the same repo and graph DB."""
        return TraceConfig(
            repo_root=self.repo_root,
            graph_db_path=self.graph_db_path,
            embedding_model=self.embedding_model,
            trace_dir=self.trace_dir,
        )

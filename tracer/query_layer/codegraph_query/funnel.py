"""The single query funnel: graph seed → neighbourhood → node_links → rank → answer."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from codegraph_trace.codegraph import CodeGraph
from codegraph_trace.store.trace_db import TraceDB

from .answer import synthesize_answer
from .config import QueryConfig
from .graph_nav import GraphNavigator
from .models import FunnelResult
from .ranker import StepRanker
from .trace_reader import TraceReader


class ReasoningFunnel:
    """One path from question to answer — no parallel global search."""

    def __init__(self, config: QueryConfig) -> None:
        self.config = config
        if not config.graph_db_path or not config.graph_db_path.is_file():
            raise FileNotFoundError(f"Code-graph database not found: {config.graph_db_path}")
        if not config.trace_db_path.is_file():
            raise FileNotFoundError(
                f"Trace database not found: {config.trace_db_path}. "
                "Record an agent session first."
            )
        self._graph = CodeGraph(
            config.graph_db_path,
            secondary_db_paths=self._imported_graph_dbs(config.trace_db_path),
        )
        self._nav = GraphNavigator(self._graph)
        self._ranker = StepRanker(config.embedding_model)

    @staticmethod
    def _imported_graph_dbs(trace_db_path) -> list[str]:
        """Code-graph DBs of imported repos, so anchors in another codebase resolve."""
        if not trace_db_path or not Path(trace_db_path).is_file():
            return []
        out: list[str] = []
        db = TraceDB(trace_db_path)
        try:
            for row in db.list_imported_repos():
                gdb = row.get("graph_db_path")
                if gdb and Path(gdb).is_file():
                    out.append(gdb)
        finally:
            db.close()
        return out

    def close(self) -> None:
        """Close graph, trace, and ranker resources."""
        self._graph.close()

    def __enter__(self) -> "ReasoningFunnel":
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def query(
        self,
        question: str,
        *,
        anchor: Optional[str] = None,
        top_k: Optional[int] = None,
        use_llm: bool = True,
    ) -> FunnelResult:
        """Run the full funnel and return ranked reasoning plus an answer."""
        top_k = top_k if top_k is not None else self.config.top_k

        anchors = self._nav.find_anchors(question, explicit=anchor)
        if not anchors:
            return FunnelResult(
                question=question,
                anchors=[],
                neighbourhood=[],
                candidates=[],
                ranked=[],
                answer=(
                    "Could not locate a matching function or file in the code graph. "
                    "Try passing --anchor with a qualified name, short name, or file path."
                ),
                meta={"stage": "anchor_miss"},
            )

        anchor_nodes = [a.node for a in anchors]
        anchor_qnames = {a.node.qualified_name for a in anchors}
        neighbourhood = self._nav.neighbourhood(
            anchor_nodes,
            hops=self.config.neighbour_hops,
        )
        qnames = [n.qualified_name for n in neighbourhood]

        co_changed_qns: list[str] = []
        with TraceReader(
            self.config.trace_db_path, repo_root=self.config.repo_root
        ) as reader:
            # Co-change expansion: pull in symbols historically edited alongside the
            # neighbourhood (most-coupled first) so their reasoning is retrieved too, even when
            # they are not graph neighbours of the anchor.
            existing = set(qnames)
            for qn, _count in reader.co_changed(list(anchor_qnames) + qnames):
                if qn in existing:
                    continue
                node = self._graph.find_node_by_qualified_name(qn)
                if node is not None:
                    neighbourhood.append(node)
                    existing.add(qn)
                    co_changed_qns.append(qn)

            all_qnames = [n.qualified_name for n in neighbourhood]
            all_files = [n.file_path for n in neighbourhood if n.file_path]
            candidates = reader.steps_for_neighbourhood(all_qnames, all_files)

        ranked = self._ranker.rank(question, candidates, top_k=top_k)
        ranked = self._boost_anchor_links(ranked, anchor_qnames)
        ranked = self._boost_co_changed(ranked, set(co_changed_qns))
        answer, answer_meta = synthesize_answer(
            question,
            anchors=anchors,
            neighbourhood=neighbourhood,
            ranked=ranked,
            navigator=self._nav,
            llm_model=self.config.llm_model,
            use_llm=use_llm,
        )

        return FunnelResult(
            question=question,
            anchors=anchors,
            neighbourhood=neighbourhood,
            candidates=candidates,
            ranked=ranked,
            answer=answer,
            meta={
                "neighbourhood_size": len(neighbourhood),
                "candidate_count": len(candidates),
                "top_k": top_k,
                "co_changed": co_changed_qns,
                **answer_meta,
            },
        )

    @staticmethod
    def _boost_anchor_links(ranked: list, anchor_qnames: set[str]) -> list:
        """Prefer steps that node_links tied directly to the anchor symbol."""
        if not anchor_qnames:
            return ranked
        for rs in ranked:
            if anchor_qnames.intersection(rs.candidate.linked_qualified_names):
                rs.score += 0.25
        ranked.sort(key=lambda r: (-r.score, r.candidate.timestamp))
        return ranked

    @staticmethod
    def _boost_co_changed(ranked: list, co_changed_qns: set[str]) -> list:
        """Nudge up steps tied to symbols historically co-edited with the neighbourhood."""
        if not co_changed_qns:
            return ranked
        for rs in ranked:
            if co_changed_qns.intersection(rs.candidate.linked_qualified_names):
                rs.score += 0.1
        ranked.sort(key=lambda r: (-r.score, r.candidate.timestamp))
        return ranked

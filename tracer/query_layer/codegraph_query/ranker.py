"""Rank a small candidate set of reasoning steps against the question."""

from __future__ import annotations

import math
from typing import Callable

from codegraph_trace.store.chroma_store import HashEmbeddingFunction, build_embedding_function

from .models import RankedStep, ReasoningCandidate


def _cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class StepRanker:
    """Embed the question once, score only the funnel's candidate steps."""

    def __init__(self, embedding_model: str = "hash") -> None:
        self.embedding_model = embedding_model
        self._embed_fn = build_embedding_function(embedding_model)
        self._embed_text = self._resolve_embedder()

    def rank(
        self,
        question: str,
        candidates: list[ReasoningCandidate],
        *,
        top_k: int = 5,
    ) -> list[RankedStep]:
        """Score candidates against ``query`` and return the top ``k``."""
        if not candidates:
            return []

        q_vec = self._embed_text(question)
        scored: list[RankedStep] = []
        for cand in candidates:
            doc = cand.document
            if not doc.strip():
                continue
            score = _cosine(q_vec, self._embed_text(doc))
            scored.append(RankedStep(candidate=cand, score=score))

        scored.sort(key=lambda r: (-r.score, r.candidate.timestamp))
        return scored[:top_k]

    def _resolve_embedder(self) -> Callable[[str], list[float]]:
        if isinstance(self._embed_fn, HashEmbeddingFunction):
            return self._embed_fn._embed  # noqa: SLF001 - test/offline path

        def _st_embed(text: str) -> list[float]:
            # Chroma embedding functions follow the EmbeddingFunction protocol: call with a
            # LIST of documents and get back one vector per document. Passing a bare string
            # makes it iterate the string per-character (and SentenceTransformer returns numpy
            # arrays), so always wrap in a list, take the single vector, and coerce to a plain
            # list[float] for the pure-Python cosine below.
            vecs = self._embed_fn([text])
            if vecs is None or len(vecs) == 0:
                return []
            return [float(x) for x in vecs[0]]

        return _st_embed
